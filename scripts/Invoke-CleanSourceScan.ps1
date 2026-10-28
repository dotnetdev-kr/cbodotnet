#requires -Version 7.3

<#
.SYNOPSIS
Runs the upstream binary scanner against a pristine, separate VMR checkout.
.DESCRIPTION
Locally clones the pinned tag using shared Git objects, or verifies an existing
pristine checkout. It mounts both checkouts read-only and runs the built
BinaryToolTask in Validate mode. Reports are written to a new report directory;
no source, allowlist, warm build cache or existing report is removed or replaced.
The returned object's ContainerReportFile can be passed as BinariesReportFile
to the upstream common tests.
.PARAMETER BuildImageId
Immutable native ARM64 image ID containing the build tools.
.PARAMETER ReportName
New report subdirectory name. Defaults to a unique UTC timestamp suffix.
.EXAMPLE
$scan = ./scripts/Invoke-CleanSourceScan.ps1 -BuildImageId <immutable-image-id>
$scan.ContainerReportFile
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^(sha256:)?[a-f0-9]{64}$')]
    [string] $BuildImageId,

    [string] $Distribution = 'Ubuntu-22.04',
    [string] $LinuxWorkspaceRoot,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string] $ReportName = ('clean-source-binary-scan-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$expectedCommit = '5a2162bea6845eabc1fc721624a43568c65db3b1'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$wslExecutable = (Get-Command wsl.exe -CommandType Application | Select-Object -First 1).Source

function Invoke-ScanWsl {
    param([string[]] $Arguments, [switch] $AsRoot, [switch] $Capture, [int[]] $AllowedExitCodes = @(0))
    $nativeArguments = @('--distribution', $Distribution)
    if ($AsRoot) { $nativeArguments += @('--user', 'root') }
    $nativeArguments += @('--exec') + $Arguments
    $nativeOutput = @(& $wslExecutable @nativeArguments)
    $nativeExitCode = $LASTEXITCODE
    if ($nativeExitCode -notin $AllowedExitCodes) {
        if ($nativeOutput.Count) { $nativeOutput | ForEach-Object { Write-Host $_ } }
        throw "Source scan command '$($Arguments[0])' failed with exit code $nativeExitCode."
    }
    if ($Capture) { return [pscustomobject]@{ ExitCode = $nativeExitCode; Text = ($nativeOutput -join "`n") } }
    $nativeOutput | ForEach-Object { Write-Host $_ }
}

function Assert-PristineScanSource {
    $revision = (Invoke-ScanWsl -Arguments @('git', '-C', $cleanSource, 'rev-parse', 'HEAD') -Capture).Text.Trim()
    if ($revision -cne $expectedCommit) { throw 'The separate scan checkout has a different commit.' }
    $status = (Invoke-ScanWsl -Arguments @('git', '-C', $cleanSource, 'status', '--porcelain', '--untracked-files=all') -Capture).Text
    if ($status.Length) { throw 'The separate scan checkout is not pristine; preserving it without changes.' }
}

$linuxHome = (Invoke-ScanWsl -Arguments @('printenv', 'HOME') -Capture).Text.Trim()
if ([string]::IsNullOrWhiteSpace($LinuxWorkspaceRoot)) { $LinuxWorkspaceRoot = "$linuxHome/cbodotnet" }
$LinuxWorkspaceRoot = $LinuxWorkspaceRoot.TrimEnd('/')
if (-not $LinuxWorkspaceRoot.StartsWith('/') -or $LinuxWorkspaceRoot -eq '/' -or $LinuxWorkspaceRoot -match '[:\r\n]') {
    throw 'LinuxWorkspaceRoot must be a non-root absolute Linux path without volume delimiters.'
}
$linuxUid = (Invoke-ScanWsl -Arguments @('id', '-u') -Capture).Text.Trim()
$linuxGid = (Invoke-ScanWsl -Arguments @('id', '-g') -Capture).Text.Trim()
if ($linuxUid -notmatch '^\d+$' -or $linuxGid -notmatch '^\d+$') { throw 'Cannot determine the Linux UID:GID.' }
$architecture = (Invoke-ScanWsl -Arguments @('uname', '-m') -Capture).Text.Trim()
if ($architecture -ne 'aarch64') { throw 'Native ARM64 Linux is required.' }
$linuxProject = (Invoke-ScanWsl -Arguments @('wslpath', '-a', '-u', $projectRoot) -Capture).Text.Trim()
if ($linuxProject -match '[:\r\n]') { throw 'The project path cannot contain volume delimiters.' }
$warmSource = "$LinuxWorkspaceRoot/work/dotnet-v10.0.403"
$cleanSource = "$LinuxWorkspaceRoot/work/source-scan-v10.0.403"
$warmRevision = (Invoke-ScanWsl -Arguments @('git', '-C', $warmSource, 'rev-parse', 'HEAD') -Capture).Text.Trim()
if ($warmRevision -cne $expectedCommit) { throw 'The warm VMR is not the pinned source revision.' }
$cleanExists = Invoke-ScanWsl -Arguments @('test', '-e', $cleanSource) -Capture -AllowedExitCodes @(0, 1)
$cleanLink = Invoke-ScanWsl -Arguments @('test', '-L', $cleanSource) -Capture -AllowedExitCodes @(0, 1)
if ($cleanLink.ExitCode -eq 0) { throw 'Refusing a symlink as the clean source checkout.' }
if ($cleanExists.ExitCode -ne 0) {
    Invoke-ScanWsl -Arguments @('git', 'clone', '--shared', '--branch', 'v10.0.403', '--', $warmSource, $cleanSource)
}
Assert-PristineScanSource

$podman = @('podman', '--cgroup-manager=cgroupfs', '--events-backend=file')
$imageText = (Invoke-ScanWsl -Arguments ($podman + @('image', 'inspect', $BuildImageId)) -AsRoot -Capture).Text
$images = @($imageText | ConvertFrom-Json)
if ($images.Count -ne 1 -or $images[0].Architecture -ne 'arm64' -or $images[0].Os -ne 'linux') {
    throw 'The scan image must be native linux/arm64.'
}
$containerReports = "/project/artifacts/10.0.403-linux-arm64/reports/$ReportName"
$windowsReports = Join-Path $projectRoot "artifacts/10.0.403-linux-arm64/reports/$ReportName"
if (Test-Path -LiteralPath $windowsReports) { throw "Refusing an existing report directory: $windowsReports" }
New-Item -ItemType Directory -Path $windowsReports | Out-Null

$scanCommand = @(
    'run', '--rm', '--cgroups=disabled', '--network=host', '--user', "${linuxUid}:${linuxGid}",
    '--env', 'HOME=/tmp', '--env', 'DOTNET_CLI_HOME=/tmp/clean-source-scan-cli',
    '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1', '--env', 'DOTNET_PROCESSOR_COUNT=2',
    '--volume', "${warmSource}:/vmr:ro", '--volume', "${cleanSource}:/clean:ro",
    '--volume', "${linuxProject}:/project", '--workdir', '/tmp', $BuildImageId,
    '/vmr/.dotnet/dotnet', 'msbuild', '/project/scripts/scan-clean-source.proj',
    "/p:ScanReportDirectory=$containerReports", '/verbosity:minimal', '/nologo',
    "/bl:$containerReports/scan.binlog", "/flp:logfile=$containerReports/scan.log;verbosity=normal"
)
$scanRecord = [ordered]@{
    sourceCommit = $expectedCommit
    cleanSourceCheckout = $cleanSource
    imageId = $BuildImageId
    scanMode = 'Validate'
    sourceMountedReadOnly = $true
    originalAllowlistUsed = $true
    startedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    command = $podman + $scanCommand
}
$exitCode = 0
try {
    Invoke-ScanWsl -Arguments ($podman + $scanCommand) -AsRoot
    Assert-PristineScanSource
    $newBinaries = Get-Item -LiteralPath (Join-Path $windowsReports 'NewBinaries.txt')
    if ($newBinaries.Length -ne 0) { throw 'The generated NewBinaries report is not truly empty.' }
    $inputHashes = (Invoke-ScanWsl -Arguments @('sha256sum',
        "$warmSource/artifacts/bin/BinaryToolKit/Release/BinaryToolKit.dll",
        "$cleanSource/eng/allowed-vmr-binaries.txt") -Capture).Text
    $scanRecord.worktreeCleanAfterScan = $true
    $scanRecord.newBinariesBytes = $newBinaries.Length
    $scanRecord.newBinariesSha256 = (Get-FileHash -LiteralPath $newBinaries.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $scanRecord.standaloneProjectSha256 = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'scan-clean-source.proj') -Algorithm SHA256).Hash.ToLowerInvariant()
    $scanRecord.inputHashes = $inputHashes -split "`n"
}
catch {
    $exitCode = 1
    $scanRecord.error = $_.Exception.Message
    throw
}
finally {
    $scanRecord.exitCode = $exitCode
    $scanRecord.finishedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    $scanRecord | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $windowsReports 'scan-execution.json') -Encoding utf8NoBOM
}

[pscustomobject]@{
    SourceCommit = $expectedCommit
    ContainerReportFile = "$containerReports/NewBinaries.txt"
    WindowsReportFile = Join-Path $windowsReports 'NewBinaries.txt'
    WindowsReportDirectory = $windowsReports
    NewBinariesBytes = 0
}
