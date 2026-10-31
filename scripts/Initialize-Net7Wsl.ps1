#requires -Version 7.3

<#
.SYNOPSIS
Creates a fresh, dedicated, disk-backed ARM64 WSL 2 environment for .NET 7.
.DESCRIPTION
Downloads the fixed Ubuntu 22.04 ARM64 WSL root filesystem into ignored local
storage, verifies its exact size and SHA-256, imports a new WSL 2 distribution,
and initializes the build account and host packages. Existing distribution
names and installation paths are refused. No distribution is stopped, moved,
unregistered, or overwritten. Installation records are written under artifacts.
The selected current-image URL may change upstream; a different image is
refused rather than accepted under the recorded hash.
.PARAMETER Distribution
Fresh distribution name. Defaults to cbodotnet-net7-arm64.
.PARAMETER InstallPath
Fresh installation directory within this project's .build/wsl/net7 directory.
The default keeps the Linux virtual disk on the same drive as this project.
.EXAMPLE
./scripts/Initialize-Net7Wsl.ps1
.NOTES
Requires Windows ARM64, PowerShell 7.3+, and an installed WSL 2 runtime.
The build account is configured in /etc/wsl.conf without restarting WSL.
Use --user build explicitly until WSL reloads that configuration naturally.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string] $Distribution = 'cbodotnet-net7-arm64',
    [string] $InstallPath = (Join-Path $PSScriptRoot '../.build/wsl/net7/distro')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $IsWindows -or [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'Arm64') {
    throw 'A Windows ARM64 host is required.'
}
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$storageRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot '.build/wsl/net7'))
$InstallPath = [System.IO.Path]::GetFullPath($InstallPath)
if (-not $InstallPath.StartsWith($storageRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "InstallPath must be a new child directory of this project's .build/wsl/net7 directory."
}
$rootfsUrl = 'https://cloud-images.ubuntu.com/wsl/jammy/current/ubuntu-jammy-wsl-arm64-ubuntu22.04lts.rootfs.tar.gz'
$expectedHash = '7d7cd98abef266eb4a0f999feb6951997b564241939ad3adb29b1159224d8a08'
$expectedBytes = [long]324314721
$rootfsArchive = Join-Path $storageRoot 'ubuntu-jammy-wsl-arm64-ubuntu22.04lts.rootfs.tar.gz'
$hostInitializer = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'initialize-net7-host.sh')).Path
$wslExecutable = (Get-Command wsl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source

function Assert-OrdinaryAncestors {
    param([Parameter(Mandatory)] [string] $LiteralPath)
    $candidate = [System.IO.Path]::GetFullPath($LiteralPath)
    while ($candidate) {
        $entry = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        if ($entry -and ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing a symbolic link or junction in the installation paths: $candidate"
        }
        $parent = [System.IO.Path]::GetDirectoryName($candidate)
        if ($parent -eq $candidate) { break }
        $candidate = $parent
    }
}

function Assert-FreshInstallation {
    $registered = @(& $wslExecutable --list --quiet)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to list registered WSL distributions.' }
    $registered = @($registered | ForEach-Object { ($_ -replace "`0", '').Trim() } | Where-Object { $_ })
    if ($registered -contains $Distribution) { throw "The WSL distribution already exists: $Distribution" }
    if (Get-Item -LiteralPath $InstallPath -Force -ErrorAction SilentlyContinue) {
        throw "The WSL installation path already exists: $InstallPath"
    }
    Assert-OrdinaryAncestors -LiteralPath $InstallPath
    Assert-OrdinaryAncestors -LiteralPath $rootfsArchive
}

Assert-FreshInstallation
$reportsRoot = Join-Path $projectRoot 'artifacts/reports/wsl-installation'
Assert-OrdinaryAncestors -LiteralPath $reportsRoot
$attemptId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$attemptDirectory = Join-Path $reportsRoot $attemptId
$null = New-Item -ItemType Directory -Path $attemptDirectory
$recordPath = Join-Path $attemptDirectory 'wsl-installation.json'
$record = [ordered]@{
    schemaVersion = 1
    startedAtUtc = [DateTime]::UtcNow.ToString('o')
    status = 'started'
    distribution = $Distribution
    installPath = $InstallPath
    requestedWslVersion = 2
    rootfs = [ordered]@{ url = $rootfsUrl; path = $rootfsArchive; expectedBytes = $expectedBytes; expectedSha256 = $expectedHash }
    initializer = [ordered]@{ path = $hostInitializer; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $hostInitializer).Hash.ToLowerInvariant() }
    existingDistributionsModified = $false
    distributionRestarted = $false
}
function Write-InstallationRecord {
    [System.IO.File]::WriteAllText($recordPath, (($record | ConvertTo-Json -Depth 12) + "`n"), [System.Text.UTF8Encoding]::new($false))
}
Write-InstallationRecord
try {
    $null = New-Item -ItemType Directory -Path $storageRoot -Force
    if (-not (Test-Path -LiteralPath $rootfsArchive)) {
        $partialArchive = Join-Path $storageRoot ('rootfs-' + $attemptId + '.partial')
        $record['downloadPath'] = $partialArchive
        $record['status'] = 'downloading-rootfs'
        Write-InstallationRecord
        Invoke-WebRequest -Uri $rootfsUrl -OutFile $partialArchive
        $download = Get-Item -LiteralPath $partialArchive
        $downloadHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $partialArchive).Hash.ToLowerInvariant()
        if ($download.Length -ne $expectedBytes -or $downloadHash -cne $expectedHash) {
            throw "The downloaded root filesystem differs from the fixed input. The download is preserved at $partialArchive."
        }
        # The two-argument Move refuses an existing destination and preserves it.
        [System.IO.File]::Move($partialArchive, $rootfsArchive)
    }
    $archive = Get-Item -LiteralPath $rootfsArchive
    if ($archive.PSIsContainer -or ($archive.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'The cached root filesystem must be an ordinary file.'
    }
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $rootfsArchive).Hash.ToLowerInvariant()
    if ($archive.Length -ne $expectedBytes -or $actualHash -cne $expectedHash) {
        throw 'The cached root filesystem does not match the fixed size and SHA-256. Preserve it and supply the recorded input.'
    }
    $record.rootfs['bytes'] = $archive.Length
    $record.rootfs['sha256'] = $actualHash
    $record['status'] = 'rootfs-verified'
    Write-InstallationRecord
    Assert-FreshInstallation
    $null = New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($InstallPath)) -Force
    & $wslExecutable --import $Distribution $InstallPath $rootfsArchive --version 2
    if ($LASTEXITCODE -ne 0) { throw "WSL import failed with exit code $LASTEXITCODE. Any partial installation is preserved." }
    $record['status'] = 'imported'
    Write-InstallationRecord
    $linuxInitializerLines = @(& $wslExecutable --distribution $Distribution --user root --exec wslpath -a -u $hostInitializer)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to translate the checked-in host initializer path.' }
    $linuxInitializer = ($linuxInitializerLines -join "`n").Trim()
    if (-not $linuxInitializer.StartsWith('/') -or $linuxInitializer.Contains("`n")) {
        throw 'WSL returned an invalid initializer path.'
    }
    $initializationLog = Join-Path $attemptDirectory 'host-initialization.log'
    $record['initializationLog'] = $initializationLog
    $record['status'] = 'initializing-host'
    Write-InstallationRecord
    $initializationOutput = @(& $wslExecutable --distribution $Distribution --user root --exec bash $linuxInitializer 2>&1 | Tee-Object -FilePath $initializationLog)
    if ($LASTEXITCODE -ne 0) { throw "Host initialization failed with exit code $LASTEXITCODE. The dedicated distribution and its log are preserved." }
    $hostState = @($initializationOutput | ForEach-Object { [string]$_ } | Where-Object { $_.StartsWith('CBODOTNET_HOST_STATE=') })
    if ($hostState.Count -ne 1) { throw 'The host initializer did not produce one provenance record.' }
    $record['hostState'] = $hostState[0].Substring('CBODOTNET_HOST_STATE='.Length) | ConvertFrom-Json
    $record['initializationLog'] = $initializationLog
    $record['status'] = 'complete'
    $record['completedAtUtc'] = [DateTime]::UtcNow.ToString('o')
    Write-InstallationRecord
    Write-Output "Initialized $Distribution at $InstallPath. Use --user build explicitly until WSL reloads /etc/wsl.conf."
    Write-Output "Installation provenance: $recordPath"
}
catch {
    $record['status'] = 'failed'
    $record['failedAtUtc'] = [DateTime]::UtcNow.ToString('o')
    $record['error'] = $_.Exception.Message
    Write-InstallationRecord
    throw
}
