#requires -Version 7.3

<#
.SYNOPSIS
Creates or reopens a native wslc container for testing a built Linux SDK archive.
.DESCRIPTION
The architecture-specific CMD entry points invoke this shared helper. Requires
wslc 3.0.3+ and a Windows OS matching the target architecture. The container has
Ubuntu 24.04 runtime dependencies, but no preinstalled .NET runtime or SDK.
Only the selected archive and setup script are copied into the container.
The named container, extracted SDK and /work persist after leaving Bash.
.PARAMETER ArchivePath
Built tar.gz to test. Defaults to this project's 10.0.403 build.1 for the target.
.PARAMETER Name
Persistent container name. Choose a new name to test a different archive.
.PARAMETER Port
Windows loopback port forwarded to container TCP port 5000.
.PARAMETER NoAttach
Prepare and print connection details without opening interactive Bash.
.EXAMPLE
./start-wslc-aarch64.cmd
.EXAMPLE
./start-wslc-x64.cmd "D:\Releases\sdk-linux-x64.tar.gz" -Name sdk-x64-test -Port 5001
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('aarch64', 'arm64', 'x64')]
    [string] $Architecture,

    [Parameter(Position = 0)]
    [string] $ArchivePath,

    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,62}$')]
    [string] $Name,

    [ValidateRange(1, 65535)]
    [int] $Port = 5000,

    [switch] $NoAttach
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Invoke-Wslc {
    param([string[]] $Arguments, [switch] $Capture)
    if ($Capture) {
        $result = & $script:WslcPath @Arguments
    } else {
        & $script:WslcPath @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "wslc $($Arguments[0]) failed (exit $LASTEXITCODE). The named container, if created, has been retained."
    }
    if ($Capture) { return $result }
}

try {
    # Windows and upstream container images retain their official Arm64 names.
    $productArchitecture = if ($Architecture -in @('aarch64', 'arm64')) { 'arm64' } else { 'x64' }
    $Architecture = if ($productArchitecture -eq 'arm64') { 'aarch64' } else { 'x64' }
    $hostArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    if (-not $IsWindows -or $hostArchitecture -ne $productArchitecture) {
        throw "linux-$Architecture requires native Windows $Architecture with wslc. This OS is $hostArchitecture. wslc 3.0.3 has no --platform option; use the matching host."
    }
    if (-not $ArchivePath) {
        $ArchivePath = Join-Path $PSScriptRoot "../artifacts/10.0.403-linux-$Architecture/cbodotnet-sdk-10.0.403-linux-$Architecture-build.1.tar.gz"
    }
    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
        throw "SDK archive not found: $ArchivePath. Pass a downloaded linux-$Architecture SDK tar.gz as the first argument."
    }
    $ArchivePath = (Resolve-Path -LiteralPath $ArchivePath).ProviderPath
    if (-not $ArchivePath.EndsWith('.tar.gz', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'ArchivePath must identify an SDK .tar.gz file.'
    }
    if (-not $Name) { $Name = "cbodotnet-sdk-test-$Architecture" }
    $wslcCommand = Get-Command wslc.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $script:WslcPath = if ($wslcCommand) { $wslcCommand.Source } else { Join-Path $env:ProgramFiles 'WSL/wslc.exe' }
    if (-not (Test-Path -LiteralPath $script:WslcPath -PathType Leaf)) {
        throw 'wslc.exe was not found. Install WSL with wslc 3.0.3 or later before running this script.'
    }

    $sha256 = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $imageSuffix = if ($productArchitecture -eq 'arm64') { 'arm64v8' } else { 'amd64' }
    $image = "mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-$imageSuffix"
    Write-Host "Archive: $ArchivePath"
    Write-Host "SHA256:  $sha256"

    # A successful list distinguishes a missing container from an unavailable engine.
    $null = Invoke-Wslc -Arguments @('container', 'list', '--all', '--quiet') -Capture
    $inspectOutput = & $script:WslcPath container inspect --format json $Name 2>$null
    $exists = $LASTEXITCODE -eq 0
    if ($exists) {
        $container = @((($inspectOutput -join "`n") | ConvertFrom-Json -AsHashtable))[0]
        $labels = $container.Config.Labels
        if ($labels -isnot [System.Collections.IDictionary] -or
            $labels['org.cbodotnet.session'] -ne 'sdk-test-v1' -or
            $labels['org.cbodotnet.architecture'] -ne $Architecture -or
            $labels['org.cbodotnet.archive-sha256'] -ne $sha256 -or
            $labels['org.cbodotnet.host-port'] -ne "$Port") {
            throw "Container '$Name' has different settings or is not managed by this script. Use -Name with a different name."
        }
        if ($container.State.Status -ne 'running') {
            Invoke-Wslc -Arguments @('start', $Name)
        }
        Write-Host "Reusing container: $Name"
    } else {
        Invoke-Wslc -Arguments @(
            'run', '--detach', '--name', $Name, '--pull', 'missing',
            '--label', 'org.cbodotnet.session=sdk-test-v1',
            '--label', "org.cbodotnet.architecture=$Architecture",
            '--label', "org.cbodotnet.archive-sha256=$sha256",
            '--label', "org.cbodotnet.host-port=$Port",
            '--publish', "127.0.0.1:${Port}:5000",
            '--env', 'DOTNET_ROOT=/opt/cbodotnet/sdk',
            '--env', 'PATH=/opt/cbodotnet/sdk:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1',
            '--env', 'DOTNET_NOLOGO=1',
            '--env', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
            '--env', 'ASPNETCORE_URLS=http://0.0.0.0:5000',
            $image, '/bin/sleep', 'infinity'
        )
    }

    # exec's argument vector avoids shell interpolation of Windows paths and names.
    $setupScript = Join-Path $PSScriptRoot 'wslc-sdk-session-setup.sh'
    # wslc 3.0.3 requires an existing destination directory and keeps the basename.
    Invoke-Wslc -Arguments @('container', 'cp', '--quiet', $setupScript, "${Name}:/tmp/")
    $containerArchive = '/tmp/cbodotnet-input/' + (Split-Path -Leaf $ArchivePath)
    $null = & $script:WslcPath exec $Name /usr/bin/test -f /opt/cbodotnet/sdk/.cbodotnet-archive-sha256
    if ($LASTEXITCODE -ne 0) {
        Invoke-Wslc -Arguments @('exec', $Name, '/bin/mkdir', '-p', '/tmp/cbodotnet-input')
        Invoke-Wslc -Arguments @('container', 'cp', '--quiet', $ArchivePath, "${Name}:/tmp/cbodotnet-input/")
    }
    Invoke-Wslc -Arguments @('exec', $Name, '/bin/bash', '/tmp/wslc-sdk-session-setup.sh', $Architecture, $sha256, $containerArchive)

    Write-Host "`nContainer: $Name  |  workspace: /work  |  HTTP: http://localhost:$Port"
    Write-Host "Reconnect: run the same CMD again, or:"
    Write-Host "  `"$script:WslcPath`" exec -i -t -w /work $Name /bin/bash --noprofile --rcfile /opt/cbodotnet/session.bashrc -i"
    Write-Host "Stop when finished: wslc stop $Name"
    if (-not $NoAttach) {
        Invoke-Wslc -Arguments @('exec', '-i', '-t', '-w', '/work', $Name, '/bin/bash', '--noprofile', '--rcfile', '/opt/cbodotnet/session.bashrc', '-i')
    }
} catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
}
