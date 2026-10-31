#requires -Version 7.3
<#
.SYNOPSIS
Generates, prepares, builds, tests or collects the pinned native ARM64 .NET 6 SDK.
.DESCRIPTION
Uses a dedicated WSL instance and rootful Podman. Build processes run as the
selected unprivileged Linux user. Only signed sysroot preparation is privileged.
The default existing WSL instance is cbodotnet-net7-arm64; .NET 6 work, inputs,
container home and artifact reports use separate version-specific directories.
Generate clones the pinned installer if absent, builds the container and creates
the external source tree. The generator mounts the source tree's parent because
upstream recreates its output directory. Prepare preserves original downloads
before the explicit ARM64 bootstrap transformation. Existing inputs and reports
are retained. Use separate workspaces for concurrent builds.
.PARAMETER Distribution
Native ARM64 WSL instance. The recorded run uses a dedicated D-backed instance.
.PARAMETER LinuxUser
Existing unprivileged Linux account used for source ownership and build processes.
.PARAMETER OfficialSdkArchivePath
Exact-version official test baseline, mounted below /inputs. An empty value skips
the optional SDK layout comparison. It never substitutes for the community SDK.
.EXAMPLE
./scripts/Invoke-Net6Build.ps1 -Mode Generate
.EXAMPLE
./scripts/Invoke-Net6Build.ps1 -Mode Prepare
.EXAMPLE
./scripts/Invoke-Net6Build.ps1 -Mode Build
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Generate','Prepare','Build','Test','Collect')] [string]$Mode,
    [string]$Distribution = 'cbodotnet-net7-arm64',
    [ValidatePattern('^[a-z_][a-z0-9_-]*$')] [string]$LinuxUser = 'build',
    [string]$LinuxWorkspaceRoot,
    [string]$ImageName = 'localhost/cbodotnet-arm64:6.0.136',
    [string]$OfficialSdkArchivePath = '/inputs/official-sdk/dotnet-sdk-6.0.136-linux-arm64.tar.gz'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$project = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$profilePath = Join-Path $project 'profiles/dotnet-6.0.136-linux-arm64.json'
$profileBytes = [System.IO.File]::ReadAllBytes($profilePath)
$profile = [System.Text.Encoding]::UTF8.GetString($profileBytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
$profileSha256 = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($profileBytes)).ToLowerInvariant()
if ($profile.sdkVersion -ne '6.0.136' -or $profile.source.commit -cne 'd638663530d923adbe0442604b7a6562127321e9' -or
    $profile.build.system -ne 'legacy-installer-source-build' -or $profile.build.sourceOnly -ne $true -or
    $profile.target.rid -ne 'linux-arm64' -or $profile.build.maxCpuCount -ne 2) { throw 'The fixed .NET 6 profile does not match this harness.' }
$containerfile = Join-Path $project 'containers/arm64-net6.Containerfile'
$fromLine = (Get-Content -LiteralPath $containerfile | Where-Object { $_ -match '^FROM\s+' } | Select-Object -First 1).Trim()
if ($fromLine -cne "FROM $($profile.container.repository)@$($profile.container.digest)") { throw 'Containerfile base differs from the pinned profile.' }
if ($ImageName.StartsWith('-') -or $ImageName -match '\s') { throw 'An ordinary container image reference is required.' }
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
    if (-not $Path.StartsWith('/') -or $Path -eq '/' -or $Path -match '[:\r\n]') { throw "Unsafe Linux path: $Path" }
}
if ((Invoke-Linux -Capture -Arguments @('uname','-m')).Trim() -ne 'aarch64') { throw 'Native ARM64 WSL is required.' }
$linuxHome = (Invoke-Linux -Capture -Arguments @('printenv','HOME')).Trim()
if (-not $LinuxWorkspaceRoot) { $LinuxWorkspaceRoot = "$linuxHome/cbodotnet/net6" }
$LinuxWorkspaceRoot = $LinuxWorkspaceRoot.TrimEnd('/')
Assert-AbsolutePath $LinuxWorkspaceRoot
$linuxProject = (Invoke-Linux -Capture -Arguments @('wslpath','-a','-u',$project)).Trim()
$uid = (Invoke-Linux -Capture -Arguments @('id','-u')).Trim()
$gid = (Invoke-Linux -Capture -Arguments @('id','-g')).Trim()
if ($uid -notmatch '^\d+$' -or $gid -notmatch '^\d+$' -or $uid -eq '0') { throw 'An unprivileged Linux UID:GID is required.' }
$work = "$LinuxWorkspaceRoot/work"
$installer = "$work/installer-v6.0.136"
$source = "$work/source-v6.0.136"
$inputs = "$LinuxWorkspaceRoot/inputs"
$containerHome = "$LinuxWorkspaceRoot/container-home"
$release = 'artifacts/6.0.136-linux-arm64'
$windowsReports = Join-Path $project "$release/reports"
$linuxReports = "$linuxProject/$release/reports"
$reports = "/project/$release/reports"
$seccomp = "$inputs/seccomp-net6-fchmodat2.json"
Invoke-Linux -Arguments @('mkdir','-p','--',$work,$inputs,$containerHome,$linuxReports,"$linuxReports/sysroot")
if ($Mode -eq 'Generate') {
    $null = Invoke-Linux -Arguments @('python3','-c','import pathlib,subprocess,sys; p=pathlib.Path(sys.argv[1]); subprocess.run(["git","clone","--depth","1","--branch","v6.0.136","https://github.com/dotnet/installer.git",str(p)],check=True) if not p.exists() else None',$installer)
}
if ($Mode -in @('Generate','Prepare')) {
    Invoke-Podman -Arguments @('build','--network=host','--file',"$linuxProject/containers/arm64-net6.Containerfile",'--tag',$ImageName,"$linuxProject/containers")
}
Invoke-Linux -Arguments @('test','-d',"$installer/.git")
if ((Invoke-Linux -Capture -Arguments @('git','-C',$installer,'rev-parse','HEAD')).Trim() -cne $profile.source.commit) { throw 'Installer source commit mismatch.' }
$images = @((Invoke-Podman -Capture -Arguments @('image','inspect',$ImageName)) | ConvertFrom-Json)
if ($images.Count -ne 1 -or $images[0].Architecture -ne 'arm64' -or $images[0].Os -ne 'linux') { throw 'A single native Linux ARM64 image is required.' }
$image = $images[0]
if ($image.Id -notmatch '^(sha256:)?[a-f0-9]{64}$') { throw 'Unexpected image identity.' }
Invoke-Linux -Arguments @('python3',"$linuxProject/scripts/prepare-net6-seccomp.py",'--output-policy',$seccomp,'--report',"$linuxReports/seccomp-net6.json")
$imageRecord = [ordered]@{schemaVersion=1; inspectedAtUtc=[DateTimeOffset]::UtcNow.ToString('o'); distribution=$Distribution;
    linuxUser=$LinuxUser; uid=[int]$uid; gid=[int]$gid; imageId=$image.Id; imageReference=$ImageName;
    baseReference="$($profile.container.repository)@$($profile.container.digest)"; installerCommit=$profile.source.commit;
    containerfileSha256=(Get-FileHash -LiteralPath (Join-Path $project 'containers/arm64-net6.Containerfile') -Algorithm SHA256).Hash.ToLowerInvariant();
    profileSha256=$profileSha256;
    seccomp=(Get-Content -Raw -LiteralPath (Join-Path $windowsReports 'seccomp-net6.json') | ConvertFrom-Json)}
$imageRecord | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $windowsReports 'derived-image.json') -Encoding utf8NoBOM
function Invoke-BuildContainer {
    param([string[]]$Command,[switch]$Privileged)
    $options = @('run','--rm','--cgroups=disabled','--network=host')
    if ($Privileged) {
        $options += @('--privileged','--user','0:0','--volume',"${work}:/work:ro",'--volume',"${installer}:/installer:ro",'--volume',"${linuxProject}:/project:ro")
    } else {
        $options += @('--security-opt',"seccomp=$seccomp",'--user',"${uid}:${gid}",'--volume',"${work}:/work",'--volume',"${installer}:/installer",'--volume',"${linuxProject}:/project")
    }
    $options += @('--env','HOME=/home/build','--volume',"${inputs}:/inputs",'--volume',"${containerHome}:/home/build",'--volume',"${linuxReports}/sysroot:/reports",'--workdir','/installer',$image.Id)
    Invoke-Podman -Arguments ($options + $Command)
}
$containerSource = '/work/source-v6.0.136'
$provenance = @('python3','/project/scripts/source6-provenance.py','verify','--installer-dir','/installer','--source-dir',$containerSource,'--reports-dir',"$reports/generation")
if ($Mode -eq 'Generate' -and (Test-Path -LiteralPath (Join-Path $windowsReports 'generation/generation.json'))) {
    Invoke-BuildContainer -Command $provenance
    Write-Host 'Existing generated source inputs verified.'
    exit 0
}
if ($Mode -ne 'Generate') { Invoke-BuildContainer -Command $provenance }
if ($Mode -eq 'Prepare') {
    $exists = Invoke-Linux -Capture -Arguments @('python3','-c','import os,sys; print("yes" if os.path.lexists(sys.argv[1]) else "no")',"$inputs/arm64-xenial")
    if ($exists.Trim() -eq 'no') {
        Invoke-BuildContainer -Privileged -Command @('bash','/project/scripts/prepare-sysroot6.sh',$containerSource,'/inputs','/reports',$uid,$gid)
    }
}
if ($Mode -in @('Prepare','Build','Test')) {
    Invoke-BuildContainer -Command @('python3','/project/scripts/verify-sysroot6.py','--sysroot','/inputs/arm64-xenial','--reports-dir','/reports')
}
if ($Mode -eq 'Collect') {
    Invoke-BuildContainer -Command @('python3','/project/scripts/collect-artifacts.py','--source-dir','/installer','--generated-source-dir',$containerSource,
        '--generation-report',"$reports/generation/generation.json",'--profile','/project/profiles/dotnet-6.0.136-linux-arm64.json',
        '--output-dir',"/project/$release",'--reports-dir',$reports,'--build-image-id',$image.Id)
    exit 0
}
$action = $Mode.ToLowerInvariant()
$attempt = "$action-$([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ'))"
$windowsAttempt = Join-Path $windowsReports "runs/$attempt"
$null = New-Item -ItemType Directory -Path $windowsAttempt
$imageRecord | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $windowsAttempt 'derived-image.json') -Encoding utf8NoBOM
[System.IO.File]::WriteAllBytes((Join-Path $windowsAttempt 'profile.json'),$profileBytes)
Copy-Item -LiteralPath (Join-Path $windowsReports 'seccomp-net6.json') -Destination (Join-Path $windowsAttempt 'seccomp-provenance.json')
Invoke-Linux -Arguments @('cp','--',$seccomp,"$linuxReports/runs/$attempt/seccomp-policy.json")
Invoke-Linux -Arguments @('cp','--',$imageRecord.seccomp.basePolicy.path,"$linuxReports/runs/$attempt/seccomp-base-policy.json")
# Run an immutable per-attempt script/patch snapshot so later harness edits
# cannot change a shell's input while an upstream process is still running.
$snapshot = Join-Path $windowsAttempt 'rebuild-inputs'
foreach ($directory in @('scripts','patches/net6','profiles','containers')) {
    $null = New-Item -ItemType Directory -Path (Join-Path $snapshot $directory) -Force
}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $project 'scripts') -File) {
    if ($file.Extension -in @('.sh','.py','.ps1','.cmd','.bat')) {
        Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $snapshot 'scripts')
    }
}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $project 'patches/net6') -File) {
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $snapshot 'patches/net6')
}
[System.IO.File]::WriteAllBytes((Join-Path $snapshot 'profiles/dotnet-6.0.136-linux-arm64.json'),$profileBytes)
Copy-Item -LiteralPath $containerfile -Destination (Join-Path $snapshot 'containers/arm64-net6.Containerfile')
$command = @('bash',"$reports/runs/$attempt/rebuild-inputs/scripts/build-source6.sh",'--installer-dir','/installer','--source-dir',$containerSource,'--reports-dir',"$reports/runs/$attempt",'--action',$action,'--max-cpu-count','2')
if ($Mode -eq 'Test' -and $OfficialSdkArchivePath) {
    Assert-AbsolutePath $OfficialSdkArchivePath
    $command += @('--official-sdk-archive',$OfficialSdkArchivePath)
}
Write-Host "Mode: $Mode; WSL: $Distribution; image: $($image.Id); reports: $windowsAttempt"
Invoke-BuildContainer -Command $command
