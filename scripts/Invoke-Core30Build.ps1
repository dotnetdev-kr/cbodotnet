#requires -Version 7.3
<#
.SYNOPSIS
Acquires, prepares, builds or tests the pinned native ARM64 .NET Core 3.0 SDK.
.DESCRIPTION
Uses the existing D-backed ARM64 WSL instance and a separate Core 3.0 workspace.
Every source/input/project bind mount retains its absolute host path because
initial source-export receipts and inventories contain those exact paths.
Normal upstream metadata, patching, component builds and reports remain enabled.
Recorded compatibility changes select the Git acquisition adapter, retained
bootstrap tools, target sysroot, native ARM64 crossgen and official package-feed
indexes. Only fresh signed sysroot preparation is privileged.
.PARAMETER CpuAffinity
Two eligible CPU numbers for the recorded native build process affinity.
.EXAMPLE
./scripts/Invoke-Core30Build.ps1 -Mode Acquire
.EXAMPLE
./scripts/Invoke-Core30Build.ps1 -Mode Prepare
.EXAMPLE
./scripts/Invoke-Core30Build.ps1 -Mode Build
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Acquire','Prepare','Build','Test')] [string]$Mode,
    [string]$Distribution = 'cbodotnet-net7-arm64',
    [ValidatePattern('^[a-z_][a-z0-9_-]*$')] [string]$LinuxUser = 'build',
    [string]$LinuxWorkspaceRoot,
    [string]$ImageName = 'localhost/cbodotnet-arm64:3.0.103',
    [ValidatePattern('^\d+,\d+$')] [string]$CpuAffinity = '4,5',
    [string]$LinuxSdkArchive
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$project = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$profilePath = Join-Path $project 'profiles/dotnet-3.0.103-linux-arm64.json'
$profileBytes = [System.IO.File]::ReadAllBytes($profilePath)
$profile = [System.Text.Encoding]::UTF8.GetString($profileBytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
$profileSha256 = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($profileBytes)).ToLowerInvariant()
if ($profile.sdkVersion -ne '3.0.103' -or $profile.source.commit -cne '40de72d1087a1d05dfd39c87f888a0611ec6c60f' -or
    $profile.build.system -ne 'legacy-source-build-direct' -or $profile.build.sourceOnly -ne $true -or
    $profile.target.rid -ne 'linux-arm64' -or $profile.build.maxCpuCount -ne 2) { throw 'The fixed Core 3.0 profile does not match this harness.' }
$containerfile = Join-Path $project 'containers/arm64-core30.Containerfile'
$fromLine = (Get-Content -LiteralPath $containerfile | Where-Object { $_ -match '^FROM\s+' } | Select-Object -First 1).Trim()
if ($fromLine -cne "FROM $($profile.container.repository)@$($profile.container.digest)") { throw 'Container base differs from the pinned profile.' }
if ($ImageName.StartsWith('-') -or $ImageName -match '\s') { throw 'An ordinary image reference is required.' }
function Invoke-Linux {
    param([string[]]$Arguments,[switch]$Root,[switch]$Capture)
    $selectedUser = if ($Root) { 'root' } else { $LinuxUser }
    $wslArguments = @('-d',$Distribution,'-u',$selectedUser,'--exec') + $Arguments
    if ($Capture) { $result = @(& wsl.exe @wslArguments); $code = $LASTEXITCODE }
    else { & wsl.exe @wslArguments; $code = $LASTEXITCODE }
    if ($code) { throw "WSL command '$($Arguments[0])' failed with exit code $code." }
    if ($Capture) { return $result -join "`n" }
}
function Invoke-Podman {
    param([string[]]$Arguments,[switch]$Capture)
    Invoke-Linux -Root -Capture:$Capture -Arguments (@('podman','--cgroup-manager=cgroupfs','--events-backend=file') + $Arguments)
}
function Assert-AbsolutePath {
    param([string]$Path)
    if ($Path -notmatch '^/[A-Za-z0-9_./-]+$' -or $Path -eq '/' -or $Path -match '(^|/)\.\.(/|$)') {
        throw "An absolute Linux control path without shell metacharacters is required: $Path"
    }
}
if ((Invoke-Linux -Capture -Arguments @('uname','-m')).Trim() -ne 'aarch64') { throw 'Native ARM64 WSL is required.' }
$linuxHome = (Invoke-Linux -Capture -Arguments @('printenv','HOME')).Trim()
if (-not $LinuxWorkspaceRoot) { $LinuxWorkspaceRoot = "$linuxHome/cbodotnet/core30" }
$LinuxWorkspaceRoot = $LinuxWorkspaceRoot.TrimEnd('/')
Assert-AbsolutePath $LinuxWorkspaceRoot
$linuxProject = (Invoke-Linux -Capture -Arguments @('wslpath','-a','-u',$project)).Trim()
Assert-AbsolutePath $linuxProject
$uid = (Invoke-Linux -Capture -Arguments @('id','-u')).Trim()
$gid = (Invoke-Linux -Capture -Arguments @('id','-g')).Trim()
if ($uid -notmatch '^\d+$' -or $gid -notmatch '^\d+$' -or $uid -eq '0') { throw 'An unprivileged Linux UID:GID is required.' }
$work = "$LinuxWorkspaceRoot/work"
$source = "$work/source-build-3.0.103"
$inputs = "$LinuxWorkspaceRoot/inputs"
$containerHome = "$LinuxWorkspaceRoot/container-home"
$release = 'artifacts/3.0.103-linux-arm64'
$windowsReports = Join-Path $project "$release/reports"
$reports = "$linuxProject/$release/reports"
$sysrootReports = "$reports/sysroot"
$seccomp = "$inputs/seccomp-core30-fchmodat2.json"
Invoke-Linux -Arguments @('mkdir','-p','--',$work,$inputs,$containerHome,$reports,$sysrootReports)
if ($Mode -eq 'Acquire') {
    # A normal full-history checkout retains the commit counts used by upstream.
    Invoke-Linux -Arguments @('python3','-c','import pathlib,subprocess,sys; p=pathlib.Path(sys.argv[1]); subprocess.run(["git","clone","--no-checkout","https://github.com/dotnet/source-build.git",str(p)],check=True) if not p.exists() else None; subprocess.run(["git","-C",str(p),"checkout","--detach",sys.argv[2]],check=True) if not (p/"eng/Version.Details.xml").exists() else None',$source,$profile.source.commit)
}
Invoke-Linux -Arguments @('test','-d',"$source/.git")
if ((Invoke-Linux -Capture -Arguments @('git','-C',$source,'rev-parse','HEAD')).Trim() -cne $profile.source.commit) { throw 'Pinned source-build HEAD mismatch.' }
if ($Mode -in @('Acquire','Prepare')) {
    Invoke-Podman -Arguments @('build','--network=host','--file',"$linuxProject/containers/arm64-core30.Containerfile",'--tag',$ImageName,"$linuxProject/containers")
}
$images = @((Invoke-Podman -Capture -Arguments @('image','inspect',$ImageName)) | ConvertFrom-Json)
if ($images.Count -ne 1 -or $images[0].Architecture -ne 'arm64' -or $images[0].Os -ne 'linux') { throw 'A single native Linux ARM64 image is required.' }
$image = $images[0]
if ($image.Id -notmatch '^(sha256:)?[a-f0-9]{64}$') { throw 'Unexpected image identity.' }
Invoke-Linux -Arguments @('python3',"$linuxProject/scripts/prepare-core30-seccomp.py",'--output-policy',$seccomp,'--report',"$reports/seccomp-core30.json")
$seccompRecord = Get-Content -Raw -LiteralPath (Join-Path $windowsReports 'seccomp-core30.json') | ConvertFrom-Json
$imageRecord = [ordered]@{schemaVersion=1; inspectedAtUtc=[DateTimeOffset]::UtcNow.ToString('o'); distribution=$Distribution;
    linuxUser=$LinuxUser; uid=[int]$uid; gid=[int]$gid; imageId=$image.Id; imageReference=$ImageName;
    baseReference="$($profile.container.repository)@$($profile.container.digest)"; sourceCommit=$profile.source.commit;
    profileSha256=$profileSha256; cpuAffinity=$CpuAffinity; sameAbsoluteMountPaths=$true;
    unprivilegedWorkspaceMount=$LinuxWorkspaceRoot; unprivilegedWorkspaceMountMode='single-read-write-bind';
    containerfileSha256=(Get-FileHash -LiteralPath $containerfile -Algorithm SHA256).Hash.ToLowerInvariant(); seccomp=$seccompRecord}
$imageRecord | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $windowsReports 'derived-image.json') -Encoding utf8NoBOM
function Invoke-BuildContainer {
    param([string[]]$Command,[switch]$Privileged)
    $options = @('run','--rm','--cgroups=disabled','--network=host')
    if ($Privileged) {
        $options += @('--privileged','--user','0:0','--env',"SUDO_UID=$uid",'--volume',"${source}:${source}:ro",'--volume',"${inputs}:${inputs}",'--volume',"${linuxProject}:${linuxProject}:ro")
    } else {
        # A single workspace bind preserves atomic retry quarantine moves.
        $options += @('--security-opt',"seccomp=$seccomp",'--user',"${uid}:${gid}",'--volume',"${LinuxWorkspaceRoot}:${LinuxWorkspaceRoot}",'--volume',"${linuxProject}:${linuxProject}")
    }
    $options += @('--env','HOME=/home/build','--env','LANG=C.UTF-8','--env','LC_ALL=C.UTF-8','--volume',"${containerHome}:/home/build",
        '--volume',"${sysrootReports}:${sysrootReports}",'--workdir',$source,$image.Id)
    Invoke-Podman -Arguments ($options + $Command)
}
$action = $Mode.ToLowerInvariant()
$attempt = "$action-$([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))"
$windowsAttempt = Join-Path $windowsReports "runs/$attempt"
$null = New-Item -ItemType Directory -Path $windowsAttempt
$imageRecord | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $windowsAttempt 'derived-image.json') -Encoding utf8NoBOM
[System.IO.File]::WriteAllBytes((Join-Path $windowsAttempt 'profile.json'),$profileBytes)
Copy-Item -LiteralPath (Join-Path $windowsReports 'seccomp-core30.json') -Destination (Join-Path $windowsAttempt 'seccomp-provenance.json')
Invoke-Linux -Arguments @('cp','--',$seccomp,"$reports/runs/$attempt/seccomp-policy.json")
Invoke-Linux -Arguments @('cp','--',$seccompRecord.basePolicy.path,"$reports/runs/$attempt/seccomp-base-policy.json")
$snapshot = Join-Path $windowsAttempt 'rebuild-inputs'
foreach ($directory in @('scripts','patches/core30','patches/core30-tests','profiles','containers')) {
    $null = New-Item -ItemType Directory -Path (Join-Path $snapshot $directory) -Force
}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $project 'scripts') -File) {
    if ($file.Extension -in @('.sh','.py','.ps1','.cmd','.bat')) { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $snapshot 'scripts') }
}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $project 'patches/core30') -File) {
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $snapshot 'patches/core30')
}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $project 'patches/core30-tests') -File) {
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $snapshot 'patches/core30-tests')
}
[System.IO.File]::WriteAllBytes((Join-Path $snapshot 'profiles/dotnet-3.0.103-linux-arm64.json'),$profileBytes)
Copy-Item -LiteralPath $containerfile -Destination (Join-Path $snapshot 'containers/arm64-core30.Containerfile')
$frozen = "$reports/runs/$attempt/rebuild-inputs"
if ($Mode -eq 'Prepare') {
    $exists = Invoke-Linux -Capture -Arguments @('python3','-c','import os,sys; print("yes" if os.path.lexists(sys.argv[1]) else "no")',"$inputs/arm64-xenial")
    if ($exists.Trim() -eq 'no') {
        Invoke-BuildContainer -Privileged -Command @('bash',"$frozen/scripts/prepare-sysroot-core30.sh",$source,$inputs,$sysrootReports,$uid,$gid)
    }
}
if ($Mode -in @('Prepare','Build','Test')) {
    Invoke-BuildContainer -Command @('python3',"$frozen/scripts/verify-sysroot-core30.py",'--sysroot',"$inputs/arm64-xenial",'--reports-dir',$sysrootReports)
}
$command = @('bash',"$frozen/scripts/build-core30.sh",'--source-dir',$source,'--inputs-dir',$inputs,
    '--reports-dir',"$reports/runs/$attempt",'--sysroot-reports',$sysrootReports,
    '--profile',"$frozen/profiles/dotnet-3.0.103-linux-arm64.json",'--action',$action,'--cpu-affinity',$CpuAffinity,'--max-cpu-count','2')
if ($Mode -eq 'Test') {
    if (-not $LinuxSdkArchive) { $LinuxSdkArchive = "$source/bin/arm64/Release/dotnet-sdk-3.0.103-linux-arm64.tar.gz" }
    Assert-AbsolutePath $LinuxSdkArchive
    $command += @('--sdk-archive',$LinuxSdkArchive)
}
Write-Host "Mode: $Mode; WSL: $Distribution; image: $($image.Id); reports: $windowsAttempt"
Invoke-BuildContainer -Command $command
