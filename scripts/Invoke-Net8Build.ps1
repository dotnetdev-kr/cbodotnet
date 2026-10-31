#requires -Version 7.3

<#
.SYNOPSIS
Prepares or runs the pinned .NET SDK build on native ARM64 WSL.
.DESCRIPTION
Uses the default user of Ubuntu-22.04 for source files and a rootful Podman
engine for containers. Container processes run with that user's Linux UID:GID.
Prepare installs host prerequisites, clones the pinned source if absent,
builds the derived ARM64 image, prepares or validates the signed Xenial sysroot,
and runs the original prep.sh in a separately recorded attempt. Build and Test
require those prepared inputs. The wrapper does not remove workspaces, sysroots
or container storage. The upstream prep script replaces its downloaded PSB
archive with a bootstrapped archive; the Bash helper preserves the original.
The fixed profile builds .NET 8.0.133 with legacy VMR source-build orchestration.
It has no modern regular-build mode. Prepare uses a separate root container with
--privileged solely for signed Xenial sysroot creation. Upstream preparation,
Build and Test run without --privileged as the default Linux user.
.PARAMETER Mode
Prepare, Build, or Test. Prepare installs prerequisites and acquires bootstrap
inputs; Build/Test never install host tools or implicitly run preparation.
.PARAMETER Distribution
Existing WSL distribution. Defaults to Ubuntu-22.04.
.PARAMETER ProfilePath
Path to the checked-in, fixed ARM64 build profile.
.PARAMETER LinuxWorkspaceRoot
Linux filesystem parent for work, inputs and container-home. Defaults to the
default WSL user's HOME followed by /cbodotnet/net8; no username is assumed.
.PARAMETER ImageName
Local derived image tag. Build/Test inspect it and refuse a foreign architecture.
.PARAMETER OfficialSdkArchivePath
In Test mode, an absolute container path to a verified official SDK archive
used only as the upstream smoke-test comparison baseline. Defaults to the
matching archive under /inputs/official-sdk. Pass an empty string to let the
upstream tests skip the optional Microsoft SDK content comparisons instead.
.EXAMPLE
Get-Help ./scripts/Invoke-Net8Build.ps1 -Full
.EXAMPLE
./scripts/Invoke-Net8Build.ps1 -Mode Prepare
.EXAMPLE
./scripts/Invoke-Net8Build.ps1 -Mode Build
.EXAMPLE
./scripts/Invoke-Net8Build.ps1 -Mode Test -Distribution Ubuntu-22.04
.NOTES
Requires PowerShell 7.3+ and an existing native ARM64 Linux WSL distribution.
Rootful Podman uses --cgroup-manager=cgroupfs --events-backend=file. Container
cgroups are disabled for compatibility with this WSL environment; the existing
build-vmr8.sh controls build parallelism. The native ARM64 build containers use
a copy of the host seccomp policy with only fchmodat2 additionally allowed, for
new libc/tar compatibility on the older Podman host. The host policy is unchanged.
No WSL restart, VHD move or deletion
is performed. Use a separate execution context for concurrent builds.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Prepare', 'Build', 'Test')]
    [string] $Mode,

    [ValidateNotNullOrEmpty()]
    [string] $Distribution = 'Ubuntu-22.04',

    [ValidateNotNullOrEmpty()]
    [string] $ProfilePath = (Join-Path $PSScriptRoot '../profiles/dotnet-8.0.133-linux-arm64.json'),

    [string] $LinuxWorkspaceRoot,

    [ValidateNotNullOrEmpty()]
    [string] $ImageName = 'localhost/cbodotnet-arm64:8.0.133',

    [string] $OfficialSdkArchivePath = '/inputs/official-sdk/dotnet-sdk-8.0.133-linux-arm64.tar.gz'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Handle native exit codes explicitly, including expected test(1) results.
$PSNativeCommandUseErrorActionPreference = $false
if ($Mode -eq 'Test' -and $OfficialSdkArchivePath -and
    -not $OfficialSdkArchivePath.StartsWith('/')) {
    throw 'A supplied OfficialSdkArchivePath must be an absolute container path.'
}

$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$buildProfileFile = (Resolve-Path -LiteralPath $ProfilePath).Path
$buildProfile = Get-Content -Raw -LiteralPath $buildProfileFile | ConvertFrom-Json
$wslExecutable = (Get-Command wsl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source

function Invoke-WslChecked {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $Arguments,
        [switch] $AsRoot,
        [switch] $Capture,
        [int[]] $AllowedExitCodes = @(0)
    )
    $wslArguments = @('--distribution', $Distribution)
    if ($AsRoot) { $wslArguments += @('--user', 'root') }
    $wslArguments += @('--exec') + $Arguments
    Write-Verbose ('wsl.exe argument array: ' + ($wslArguments | ConvertTo-Json -Compress))
    if ($Capture) {
        $capturedLines = @(& $wslExecutable @wslArguments)
        $commandExitCode = $LASTEXITCODE
        if ($commandExitCode -notin $AllowedExitCodes) {
            throw "WSL command '$($Arguments[0])' failed with exit code $commandExitCode."
        }
        return [pscustomobject]@{
            ExitCode = $commandExitCode
            Output = ($capturedLines -join "`n")
        }
    }
    & $wslExecutable @wslArguments
    $commandExitCode = $LASTEXITCODE
    if ($commandExitCode -notin $AllowedExitCodes) {
        throw "WSL command '$($Arguments[0])' failed with exit code $commandExitCode."
    }
}

function Invoke-PodmanChecked {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $Arguments,
        [switch] $Capture,
        [int[]] $AllowedExitCodes = @(0)
    )
    $podmanArguments = @('podman', '--cgroup-manager=cgroupfs', '--events-backend=file') + $Arguments
    Invoke-WslChecked -Arguments $podmanArguments -AsRoot -Capture:$Capture -AllowedExitCodes $AllowedExitCodes
}

function Test-LinuxEntry {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    $entry = Invoke-WslChecked -Arguments @('test', '-e', $LiteralPath) -Capture -AllowedExitCodes @(0, 1)
    if ($entry.ExitCode -eq 0) { return $true }
    $link = Invoke-WslChecked -Arguments @('test', '-L', $LiteralPath) -Capture -AllowedExitCodes @(0, 1)
    return $link.ExitCode -eq 0
}

function Assert-LinuxDirectory {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    Invoke-WslChecked -Arguments @('test', '-d', $LiteralPath)
}

function Assert-LinuxAbsolutePath {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    if (-not $LiteralPath.StartsWith('/') -or $LiteralPath -eq '/' -or $LiteralPath -match '[:\r\n]') {
        throw "A non-root absolute Linux path without volume delimiters is required: $LiteralPath"
    }
}

function Get-Arm64Image {
    param([Parameter(Mandatory)] [string] $Reference)
    $inspection = Invoke-PodmanChecked -Arguments @('image', 'inspect', $Reference) -Capture
    $images = @($inspection.Output | ConvertFrom-Json)
    if ($images.Count -ne 1) { throw "Expected one local image for $Reference." }
    $image = $images[0]
    if ($image.Architecture -ne 'arm64' -or $image.Os -ne 'linux') {
        throw "Image $Reference is $($image.Os)/$($image.Architecture); native linux/arm64 is required."
    }
    if ($image.Id -notmatch '^(sha256:)?[a-f0-9]{64}$') {
        throw "Image $Reference has an unexpected immutable image ID."
    }
    return $image
}

function Invoke-BuildContainer {
    param([Parameter(Mandatory)] [string[]] $Command)
    # Arguments are passed directly to Podman/WSL; no sh -c or command strings.
    $runArguments = @(
        'run', '--rm', '--cgroups=disabled', '--network=host',
        '--user', "${linuxUid}:${linuxGid}",
        '--security-opt', "seccomp=$linuxSeccompPolicy",
        '--env', 'HOME=/home/build',
        '--volume', "${linuxSource}:/vmr",
        '--volume', "${linuxInputs}:/inputs",
        '--volume', "${linuxProject}:/project",
        '--volume', "${linuxSysrootReports}:/reports:ro",
        '--volume', "${linuxContainerHome}:/home/build",
        '--workdir', '/vmr', $derivedImage.Id
    ) + $Command
    Invoke-PodmanChecked -Arguments $runArguments
}

function Assert-SourceRevision {
    Assert-LinuxDirectory -LiteralPath "$linuxSource/.git"
    $revision = (Invoke-WslChecked -Arguments @('git', '-C', $linuxSource, 'rev-parse', 'HEAD') -Capture).Output.Trim()
    if ($revision -cne $buildProfile.source.commit) {
        throw "Refusing source revision $revision; the profile pins $($buildProfile.source.commit)."
    }
}

function Assert-SysrootReports {
    foreach ($name in @('sysroot-files.sha256', 'sysroot-file-list.sha256', 'sysroot-symlinks.tsv', 'sysroot-packages.tsv', 'sysroot-provenance.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $windowsSysrootReports $name) -PathType Leaf)) {
            throw "Existing sysroot lacks its verification report: $name. Preserve it and prepare inputs in a new workspace."
        }
    }
    # Stored paths are container paths. Reuse exactly the same /reports and
    # /inputs mounts when verifying the checksum list and each sysroot file.
    Invoke-BuildContainer -Command @('sha256sum', '--check', '--strict', "$containerSysrootReports/sysroot-file-list.sha256")
    Invoke-BuildContainer -Command @('sha256sum', '--check', '--strict', '--status', "$containerSysrootReports/sysroot-files.sha256")
    $checkInventory = @'
import os
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
reports = pathlib.Path(sys.argv[2])
expected_files = set()
for line in (reports / 'sysroot-files.sha256').read_text().splitlines():
    match = re.fullmatch(r'[a-f0-9]{64}  (.+)', line)
    if not match:
        raise SystemExit('Unsupported checksum entry in sysroot inventory')
    path = pathlib.Path(match.group(1))
    if not path.is_relative_to(root):
        raise SystemExit('Checksum entry is outside the selected sysroot')
    expected_files.add(str(path))
actual_files = set()
actual_links = set()
for directory, directories, files in os.walk(root, followlinks=False):
    for name in directories + files:
        path = pathlib.Path(directory) / name
        if path.is_symlink():
            actual_links.add(str(path) + '\t' + os.readlink(path))
        elif path.is_file():
            actual_files.add(str(path))
expected_links = set((reports / 'sysroot-symlinks.tsv').read_text().splitlines())
if not expected_files or actual_files != expected_files:
    raise SystemExit('Sysroot file inventory differs from its recorded manifest')
if actual_links != expected_links:
    raise SystemExit('Sysroot symlink inventory differs from its recorded manifest')
print('Sysroot file checksums and complete file/symlink inventory verified.')
'@
    Invoke-BuildContainer -Command @('python3', '-c', $checkInventory, '/inputs/arm64-xenial', $containerSysrootReports)
}

# The Bash wrappers deliberately pin this single, selected profile.
if ($buildProfile.schemaVersion -ne 1 -or $buildProfile.sdkVersion -ne '8.0.133' -or
    $buildProfile.source.tag -ne 'v8.0.133' -or
    $buildProfile.source.commit -cne '7d1bf90885cff22e7da72b27e9848e42fd3cb1ae' -or
    $buildProfile.host.os -ne 'linux' -or $buildProfile.host.architecture -ne 'arm64' -or
    $buildProfile.target.rid -ne 'linux-arm64' -or $buildProfile.sysroot.suite -ne 'xenial' -or
    $buildProfile.sysroot.packageSignatureVerification -ne $true -or
    $buildProfile.build.configuration -ne 'Release' -or
    $buildProfile.build.system -ne 'legacy-vmr-source-build' -or
    $buildProfile.build.sourceOnly -ne $true -or
    $buildProfile.build.crossBuild -ne $true -or $buildProfile.build.portableBuild -ne $true -or
    $buildProfile.build.maxCpuCount -lt 1 -or $buildProfile.build.maxCpuCount -gt 999 -or
    $buildProfile.container.digest -notmatch '^sha256:[a-f0-9]{64}$') {
    throw 'This wrapper requires the checked-in .NET 8.0.133 Linux ARM64 profile; update the independent .NET 8 wrappers together for a new profile.'
}
$containerFile = Join-Path $projectRoot 'containers/arm64-net8.Containerfile'
$baseReference = "$($buildProfile.container.repository)@$($buildProfile.container.digest)"
$fromLine = (Get-Content -LiteralPath $containerFile | Where-Object { $_ -match '^FROM\s+' } | Select-Object -First 1).Trim()
if ($fromLine -cne "FROM $baseReference") {
    throw 'Containerfile base reference does not match the pinned profile digest.'
}
if ($ImageName.StartsWith('-') -or $ImageName -match '[\s\r\n]') {
    throw 'ImageName must be a local image reference without whitespace or leading options.'
}

$linuxArchitecture = (Invoke-WslChecked -Arguments @('uname', '-m') -Capture).Output.Trim()
$linuxSystem = (Invoke-WslChecked -Arguments @('uname', '-s') -Capture).Output.Trim()
if ($linuxSystem -ne 'Linux' -or $linuxArchitecture -ne 'aarch64') {
    throw "Native ARM64 Linux is required; WSL reports $linuxSystem/$linuxArchitecture."
}
$linuxHome = (Invoke-WslChecked -Arguments @('printenv', 'HOME') -Capture).Output.Trim()
Assert-LinuxAbsolutePath -LiteralPath $linuxHome
$linuxUid = (Invoke-WslChecked -Arguments @('id', '-u') -Capture).Output.Trim()
$linuxGid = (Invoke-WslChecked -Arguments @('id', '-g') -Capture).Output.Trim()
if ($linuxUid -notmatch '^\d+$' -or $linuxGid -notmatch '^\d+$') { throw 'Unable to determine the default Linux UID:GID.' }
if ([string]::IsNullOrWhiteSpace($LinuxWorkspaceRoot)) { $LinuxWorkspaceRoot = "$linuxHome/cbodotnet/net8" }
$LinuxWorkspaceRoot = $LinuxWorkspaceRoot.TrimEnd('/')
Assert-LinuxAbsolutePath -LiteralPath $LinuxWorkspaceRoot
$linuxProject = (Invoke-WslChecked -Arguments @('wslpath', '-a', '-u', $projectRoot) -Capture).Output.Trim()
Assert-LinuxAbsolutePath -LiteralPath $linuxProject
$linuxProfileFile = (Invoke-WslChecked -Arguments @('wslpath', '-a', '-u', $buildProfileFile) -Capture).Output.Trim()
$linuxSource = "$LinuxWorkspaceRoot/work/dotnet-$($buildProfile.source.tag)"
$linuxInputs = "$LinuxWorkspaceRoot/inputs"
$linuxContainerHome = "$LinuxWorkspaceRoot/container-home"
$linuxSysroot = "$linuxInputs/arm64-xenial"
$releaseDirectory = "$($buildProfile.sdkVersion)-$($buildProfile.target.rid)"
$windowsReports = Join-Path $projectRoot "artifacts/$releaseDirectory/reports"
$linuxReports = "$linuxProject/artifacts/$releaseDirectory/reports"
$containerReports = "/project/artifacts/$releaseDirectory/reports"
$windowsSysrootReports = Join-Path $windowsReports 'sysroot'
$linuxSysrootReports = "$linuxReports/sysroot"
$containerSysrootReports = '/reports'
$linuxSeccompPolicy = "$linuxInputs/seccomp-net8-fchmodat2.json"
$linuxSeccompReport = "$linuxReports/seccomp-net8.json"
$windowsSeccompReport = Join-Path $windowsReports 'seccomp-net8.json'

Write-Host "Mode: $Mode; WSL: $Distribution; default Linux UID:GID: ${linuxUid}:${linuxGid}"
Write-Host "Source: $linuxSource"
Write-Host "Reports: $windowsReports"

if ($Mode -eq 'Prepare') {
    Invoke-WslChecked -Arguments @('apt-get', 'update') -AsRoot
    Invoke-WslChecked -Arguments @(
        'env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'install', '-y', '--no-install-recommends',
        'podman', 'git', 'python3', 'curl', 'ca-certificates', 'xz-utils', 'zstd', 'binutils', 'file'
    ) -AsRoot
    Invoke-WslChecked -Arguments @('mkdir', '-p', '--', "$LinuxWorkspaceRoot/work", $linuxInputs, $linuxContainerHome, $linuxReports, $linuxSysrootReports)
    if (-not (Test-LinuxEntry -LiteralPath $linuxSource)) {
        Invoke-WslChecked -Arguments @('git', 'clone', '--depth', '1', '--branch', $buildProfile.source.tag, '--', $buildProfile.source.repository, $linuxSource)
    }
    Assert-SourceRevision
    Invoke-PodmanChecked -Arguments @('pull', $baseReference)
    $null = Get-Arm64Image -Reference $baseReference
    Invoke-PodmanChecked -Arguments @(
        'build', '--network=host', '--file', "$linuxProject/containers/arm64-net8.Containerfile",
        '--tag', $ImageName, "$linuxProject/containers"
    )
}
else {
    Assert-SourceRevision
    Assert-LinuxDirectory -LiteralPath $linuxInputs
    Assert-LinuxDirectory -LiteralPath $linuxContainerHome
    Assert-LinuxDirectory -LiteralPath $linuxSysroot
    Assert-LinuxDirectory -LiteralPath $linuxSysrootReports
    Invoke-WslChecked -Arguments @('mkdir', '-p', '--', $linuxReports)
}

$derivedImage = Get-Arm64Image -Reference $ImageName
Invoke-WslChecked -Arguments @(
    'python3', "$linuxProject/scripts/prepare-net8-seccomp.py",
    '--source-policy', '/usr/share/containers/seccomp.json',
    '--output-policy', $linuxSeccompPolicy, '--report', $linuxSeccompReport
)
$seccompRecord = Get-Content -Raw -LiteralPath $windowsSeccompReport | ConvertFrom-Json
if ($seccompRecord.outputPolicy.path -cne $linuxSeccompPolicy -or
    $seccompRecord.outputPolicy.sha256 -notmatch '^[a-f0-9]{64}$' -or
    $seccompRecord.allOtherRulesUnchanged -ne $true -or $seccompRecord.seccompUnconfined -ne $false) {
    throw 'The derived .NET 8 seccomp policy record failed validation.'
}
$imageRecord = [ordered]@{
    schemaVersion = 1
    inspectedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    distribution = $Distribution
    engine = 'rootful-podman'
    imageReference = $ImageName
    imageId = $derivedImage.Id
    imageArchitecture = $derivedImage.Architecture
    imageOs = $derivedImage.Os
    repositoryDigests = @($derivedImage.RepoDigests)
    baseReference = $baseReference
    containerfileSha256 = (Get-FileHash -LiteralPath $containerFile -Algorithm SHA256).Hash.ToLowerInvariant()
    profileSha256 = (Get-FileHash -LiteralPath $buildProfileFile -Algorithm SHA256).Hash.ToLowerInvariant()
    defaultLinuxUid = [int]$linuxUid
    defaultLinuxGid = [int]$linuxGid
    containerHome = $linuxContainerHome
    sourceCommit = $buildProfile.source.commit
    seccompPolicyPath = $linuxSeccompPolicy
    seccompPolicySha256 = $seccompRecord.outputPolicy.sha256
    seccompBasePolicySha256 = $seccompRecord.basePolicy.sha256
    seccompAddedRuleCount = $seccompRecord.addedRuleCount
}
$imageRecord | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $windowsReports 'derived-image.json') -Encoding utf8NoBOM

if ($Mode -eq 'Prepare' -and -not (Test-LinuxEntry -LiteralPath $linuxSysroot)) {
    $prepareArguments = @(
        'run', '--rm', '--privileged', '--cgroups=disabled', '--network=host',
        '--user', '0:0', '--env', 'HOME=/root',
        '--volume', "${linuxSource}:/vmr:ro",
        '--volume', "${linuxInputs}:/inputs",
        '--volume', "${linuxProject}:/project:ro",
        '--volume', "${linuxSysrootReports}:/reports",
        '--workdir', '/vmr', $derivedImage.Id,
        'bash', '/project/scripts/prepare-sysroot8.sh', '/vmr', '/inputs',
        $containerSysrootReports, $linuxUid, $linuxGid
    )
    Invoke-PodmanChecked -Arguments $prepareArguments
}
Assert-LinuxDirectory -LiteralPath $linuxSysroot
$sysrootLink = Invoke-WslChecked -Arguments @('test', '-L', $linuxSysroot) -Capture -AllowedExitCodes @(0, 1)
if ($sysrootLink.ExitCode -eq 0) { throw 'Refusing a symlink as the sysroot root directory.' }
Assert-SysrootReports

if ($Mode -eq 'Prepare') {
    Invoke-WslChecked -Arguments @('bash', "$linuxProject/scripts/inventory-environment.sh", '--workspace', $linuxSource, '--output', "$linuxReports/wsl-environment.json")
    Invoke-BuildContainer -Command @('bash', '/project/scripts/inventory-environment.sh', '--workspace', '/vmr', '--output', "$containerReports/build-environment.json")
}

# Each action retains the image and profile selected before invoking upstream.
$attemptName = $Mode.ToLowerInvariant() + '-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
$attemptReports = "$containerReports/runs/$attemptName"
$windowsAttemptReports = Join-Path $windowsReports "runs/$attemptName"
$null = New-Item -ItemType Directory -Path $windowsAttemptReports
$imageRecord | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $windowsAttemptReports 'derived-image.json') -Encoding utf8NoBOM
Copy-Item -LiteralPath $buildProfileFile -Destination (Join-Path $windowsAttemptReports 'profile.json')
Copy-Item -LiteralPath $windowsSeccompReport -Destination (Join-Path $windowsAttemptReports 'seccomp-provenance.json')
Invoke-WslChecked -Arguments @('cp', '--', $linuxSeccompPolicy, "$linuxReports/runs/$attemptName/seccomp-policy.json")
Invoke-WslChecked -Arguments @('cp', '--', '/usr/share/containers/seccomp.json', "$linuxReports/runs/$attemptName/seccomp-base-policy.json")
$buildCommand = @(
    'bash', '/project/scripts/build-vmr8.sh', '--source-dir', '/vmr', '--sysroot', '/inputs/arm64-xenial',
    '--reports-dir', $attemptReports, '--action', $Mode.ToLowerInvariant(),
    '--max-cpu-count', [string]$buildProfile.build.maxCpuCount
)
if ($Mode -eq 'Test' -and $OfficialSdkArchivePath) {
    Assert-LinuxAbsolutePath -LiteralPath $OfficialSdkArchivePath
    Invoke-BuildContainer -Command @('test', '-f', $OfficialSdkArchivePath)
    $buildCommand += @('--official-sdk-archive', $OfficialSdkArchivePath)
}
Write-Host "Attempt reports: $attemptReports"
Invoke-BuildContainer -Command $buildCommand
if ($Mode -eq 'Prepare') {
    Write-Host 'Preparation complete. Run -Mode Build explicitly to start the SDK build.'
}

