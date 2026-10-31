#requires -Version 7.3
<#
.SYNOPSIS
Prepares, builds or tests the pinned portable native Linux ARM64 .NET 5 SDK.
.DESCRIPTION
Uses the legacy source-build repository directly. Each attempt freezes scripts,
patches, profile and image identity. All Linux bind mounts retain their actual
absolute paths, preserving source-export and private bootstrap receipts.
Prepare acquires exact sources and prepares a new signed Xenial target sysroot.
Build keeps the normal upstream graph, FetchSources and report targets active.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Prepare','Build','Test')] [string]$Mode,
    [string]$Distribution = 'cbodotnet-net7-arm64',
    [ValidatePattern('^[a-z_][a-z0-9_-]*$')] [string]$LinuxUser = 'build',
    [string]$LinuxWorkspaceRoot,
    [string]$ImageName = 'localhost/cbodotnet-arm64:5.0.214',
    [switch]$EnableRootPipelineLogger
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$project = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$profilePath = Join-Path $project 'profiles/dotnet-5.0.214-linux-arm64.json'
$profileBytes = [IO.File]::ReadAllBytes($profilePath)
$profile = [Text.Encoding]::UTF8.GetString($profileBytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
$profileHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($profileBytes)).ToLowerInvariant()
if ($profile.sdkVersion -ne '5.0.214' -or $profile.source.commit -cne 'd414ecb2d997a9b3f38aaaeddace30ca097e546d' -or
    $profile.source.repository -ne 'https://github.com/dotnet/source-build' -or
    $profile.build.system -ne 'legacy-source-build-direct' -or $profile.build.sourceOnly -ne $true -or
    $profile.build.maxCpuCount -ne 2 -or $profile.target.rid -ne 'linux-arm64') { throw 'The fixed .NET 5 profile does not match this harness.' }
if ($ImageName.StartsWith('-') -or $ImageName -match '\s') { throw 'An ordinary container image reference is required.' }
function Invoke-Linux {
    param([string[]]$Arguments,[switch]$Root,[switch]$Capture)
    $selected = if ($Root) { 'root' } else { $LinuxUser }
    $wslArguments = @('-d',$Distribution,'-u',$selected,'--exec') + $Arguments
    if ($Capture) { $result = @(& wsl.exe @wslArguments); $code = $LASTEXITCODE }
    else { & wsl.exe @wslArguments; $code = $LASTEXITCODE }
    if ($code) { throw "WSL command '$($Arguments[0])' failed with exit code $code." }
    if ($Capture) { return $result -join "`n" }
}
function Invoke-Podman {
    param([string[]]$Arguments,[switch]$Capture)
    Invoke-Linux -Root -Capture:$Capture -Arguments (@('podman','--cgroup-manager=cgroupfs','--events-backend=file') + $Arguments)
}
function Assert-LinuxPath {
    param([string]$Path)
    if (-not $Path.StartsWith('/') -or $Path -eq '/' -or $Path -match '[:\r\n\s]') { throw "The legacy build requires an absolute Linux path without whitespace: $Path" }
}
if ((Invoke-Linux -Capture -Arguments @('uname','-m')).Trim() -ne 'aarch64') { throw 'Native ARM64 WSL is required.' }
$linuxHome = (Invoke-Linux -Capture -Arguments @('printenv','HOME')).Trim()
if (-not $LinuxWorkspaceRoot) { $LinuxWorkspaceRoot = "$linuxHome/cbodotnet/net5" }
$LinuxWorkspaceRoot = $LinuxWorkspaceRoot.TrimEnd('/')
Assert-LinuxPath $LinuxWorkspaceRoot
$linuxProject = (Invoke-Linux -Capture -Arguments @('wslpath','-a','-u',$project)).Trim()
Assert-LinuxPath $linuxProject
$uid = (Invoke-Linux -Capture -Arguments @('id','-u')).Trim()
$gid = (Invoke-Linux -Capture -Arguments @('id','-g')).Trim()
if ($uid -notmatch '^\d+$' -or $gid -notmatch '^\d+$' -or $uid -eq '0') { throw 'An unprivileged Linux UID:GID is required.' }
$work = "$LinuxWorkspaceRoot/work"
$source = "$work/source-build-5.0.214"
$inputs = "$LinuxWorkspaceRoot/inputs"
$containerHome = "$LinuxWorkspaceRoot/container-home"
$relativeRelease = 'artifacts/5.0.214-linux-arm64'
$windowsReports = Join-Path $project "$relativeRelease/reports"
$linuxReports = "$linuxProject/$relativeRelease/reports"
$sysrootReports = "$linuxReports/sysroot"
Invoke-Linux -Arguments @('mkdir','-p','--',$work,$inputs,$containerHome,$linuxReports)
if ($Mode -eq 'Prepare') {
    $cloneCode = @'
import pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1])
if not root.exists():
    subprocess.run(['git','clone','--no-checkout','https://github.com/dotnet/source-build.git',str(root)],check=True)
    subprocess.run(['git','-C',str(root),'checkout','--detach','d414ecb2d997a9b3f38aaaeddace30ca097e546d'],check=True)
'@
    Invoke-Linux -Arguments @('python3','-c',$cloneCode,$source)
}
if ((Invoke-Linux -Capture -Arguments @('git','-C',$source,'rev-parse','HEAD')).Trim() -cne $profile.source.commit) { throw 'Source-build commit mismatch.' }
$containerfile = Join-Path $project 'containers/arm64-net5.Containerfile'
$from = (Get-Content -LiteralPath $containerfile | Where-Object { $_ -match '^FROM\s+' } | Select-Object -First 1).Trim()
if ($from -cne "FROM $($profile.container.repository)@$($profile.container.digest)") { throw 'Containerfile base differs from the profile.' }
$exists = Invoke-Podman -Capture -Arguments @('image','list','--format','{{.Repository}}:{{.Tag}}')
if ($Mode -eq 'Prepare' -and $exists -notmatch [regex]::Escape($ImageName)) {
    Invoke-Podman -Arguments @('build','--network=host','--file',"$linuxProject/containers/arm64-net5.Containerfile",'--tag',$ImageName,"$linuxProject/containers")
}
$images = @((Invoke-Podman -Capture -Arguments @('image','inspect',$ImageName)) | ConvertFrom-Json)
if ($images.Count -ne 1 -or $images[0].Architecture -ne 'arm64' -or $images[0].Os -ne 'linux') { throw 'A single native Linux ARM64 image is required.' }
$image = $images[0]
if ($image.Id -notmatch '^(sha256:)?[a-f0-9]{64}$') { throw 'Unexpected image identity.' }
$action = $Mode.ToLowerInvariant()
$attempt = "$action-$([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))"
$windowsAttempt = Join-Path $windowsReports "runs/$attempt"
$null = New-Item -ItemType Directory -Path $windowsAttempt
$linuxAttempt = "$linuxReports/runs/$attempt"
$snapshot = Join-Path $windowsAttempt 'rebuild-inputs'
foreach ($directory in @('scripts','patches/net5','patches/net5-tests','profiles','containers')) { $null = New-Item -ItemType Directory -Path (Join-Path $snapshot $directory) -Force }
foreach ($name in @('build-source5.sh','apply-net5-patches.py','prepare-net5-bootstrap.py','prepare-net5-tests.py','prepare-legacy-xmldoc-recovery.py','prepare-sysroot5.sh','verify-sysroot5.py','clone-legacy-sources.py','Invoke-Net5Build.ps1')) {
    Copy-Item -LiteralPath (Join-Path $project "scripts/$name") -Destination (Join-Path $snapshot 'scripts')
}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $project 'patches/net5') -File) { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $snapshot 'patches/net5') }
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $project 'patches/net5-tests') -File) { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $snapshot 'patches/net5-tests') }
[IO.File]::WriteAllBytes((Join-Path $snapshot 'profiles/dotnet-5.0.214-linux-arm64.json'),$profileBytes)
Copy-Item -LiteralPath $containerfile -Destination (Join-Path $snapshot 'containers/arm64-net5.Containerfile')
$record = [ordered]@{schemaVersion=1;recordedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');mode=$Mode;
    imageId=$image.Id;imageReference=$ImageName;distribution=$Distribution;linuxUser=$LinuxUser;uid=[int]$uid;gid=[int]$gid;
    sourceRoot=$source;sourceCommit=$profile.source.commit;profileSha256=$profileHash;cpuAffinity='4,5';
    baseReference="$($profile.container.repository)@$($profile.container.digest)";
    containerfileSha256=(Get-FileHash -LiteralPath $containerfile -Algorithm SHA256).Hash.ToLowerInvariant()}
$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $windowsAttempt 'execution-environment.json') -Encoding utf8NoBOM
function Invoke-Container {
    param([string[]]$Command,[switch]$Privileged)
    $options = @('run','--rm','--cgroups=disabled','--network=host')
    if ($Privileged) {
        $options += @('--privileged','--user','0:0','--volume',"${source}:${source}:ro",'--volume',"${inputs}:${inputs}",
            '--volume',"${linuxProject}:${linuxProject}:ro",'--volume',"${sysrootReports}:${sysrootReports}")
    } else {
        $options += @('--user',"${uid}:${gid}",'--volume',"${LinuxWorkspaceRoot}:${LinuxWorkspaceRoot}",
            '--volume',"${linuxProject}:${linuxProject}")
    }
    $options += @('--env',"HOME=$containerHome",'--workdir',$source,$image.Id)
    Invoke-Podman -Arguments ($options + $Command)
}
$logger = if ($EnableRootPipelineLogger) { 'true' } else { 'false' }
$command = @('bash',"$linuxAttempt/rebuild-inputs/scripts/build-source5.sh",'--source-dir',$source,'--inputs-dir',$inputs,
    '--reports-dir',$linuxAttempt,'--profile',"$linuxAttempt/rebuild-inputs/profiles/dotnet-5.0.214-linux-arm64.json",
    '--sysroot-reports-dir',$sysrootReports,'--action',$action,'--cpu-affinity','4,5','--max-cpu-count','2',
    '--root-pipeline-logger',$logger)
Write-Host "Mode: $Mode; WSL: $Distribution; image: $($image.Id); reports: $windowsAttempt"
Invoke-Container -Command $command
if ($Mode -eq 'Prepare') {
    $hasSysroot = (Invoke-Linux -Capture -Arguments @('python3','-c','import os,sys; print("yes" if os.path.lexists(sys.argv[1]) else "no")',"$inputs/arm64-xenial")).Trim()
    if ($hasSysroot -eq 'no') {
        Invoke-Linux -Arguments @('mkdir','-p','--',$sysrootReports)
        Invoke-Container -Privileged -Command @('taskset','--cpu-list','4,5','bash',"$linuxAttempt/rebuild-inputs/scripts/prepare-sysroot5.sh",$source,$inputs,$sysrootReports,$uid,$gid)
    }
    Invoke-Container -Command @('python3',"$linuxAttempt/rebuild-inputs/scripts/verify-sysroot5.py",'--sysroot',"$inputs/arm64-xenial",'--reports-dir',$sysrootReports)
}
