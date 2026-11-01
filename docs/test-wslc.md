# Using a built SDK with wslc

Run the architecture-specific CMD launcher on Windows to enter Bash in a Linux container with the built SDK archive installed. The SDK path and environment variables are configured so that `dotnet` is ready to use. Leaving Bash retains the SDK and the files in `/work` in the same named container.

The launchers default to **.NET SDK 10.0.403 Linux ARM64 build.1**, whose ARM64 wslc session has been validated on this Windows ARM64 PC. Other locally built ARM64 archives are listed in [version coverage](dotnet-version-coverage.md). Selecting another archive does not install its system dependencies: follow its build report, including the controlled OpenSSL/ICU inputs for older SDKs. Those other archives' native validation does not establish a wslc session result. Qualified Linux x64 archives and native user-space results are recorded in the [x64 CI results](ci-x64-results.md); the Windows x64 wslc launcher remains separately unvalidated.

## Prerequisites

- Windows with the same architecture as the target: Windows ARM64 for the ARM64 SDK or Windows x64 for the x64 SDK.
- WSL **3.0.3 or later**, including wslc. The tested version is `wslc 3.0.3.0`.
- **PowerShell 7.3 or later**, with `pwsh.exe` available on PATH.
- The SDK `.tar.gz` for the selected architecture. The first run also needs network access to download the base image.

The launcher exits if the Windows OS architecture does not match the target. Running the x64 CMD on this ARM64 PC does not switch it to an x64 Linux environment. wslc 3.0.3 has no equivalent to Docker's `--platform` option, so these launchers use native execution on matching architectures. [wslc source in WSL 3.0.3](https://github.com/microsoft/WSL/tree/3.0.3/src/windows/wslc).

Check versions and CLI access in PowerShell:

```powershell
$PSVersionTable.PSVersion
wsl.exe --version
& "$env:ProgramFiles\WSL\wslc.exe" version
```

The helper invoked by the CMD looks for `%ProgramFiles%\WSL\wslc.exe` even when `wslc.exe` is not on PATH. When calling the CLI directly, use its full path as shown below. Adjust the path if WSL is installed elsewhere.

## Starting a session

Run the ARM64 CMD from the project root:

```powershell
cd D:\Projects\cbodotnet
.\scripts\start-wslc-arm64.cmd
```

The default archives and container names are:

| Target | CMD | Default archive | Default container |
| --- | --- | --- | --- |
| ARM64 | `scripts/start-wslc-arm64.cmd` | `artifacts/10.0.403-linux-arm64/cbodotnet-sdk-10.0.403-linux-arm64-build.1.tar.gz` | `cbodotnet-sdk-test-arm64` |
| x64 | `scripts/start-wslc-x64.cmd` | `artifacts/10.0.403-linux-x64/cbodotnet-sdk-10.0.403-linux-x64-build.1.tar.gz` | `cbodotnet-sdk-test-x64` |

The `build.1` paths are configured defaults. CI archives use their actual run ID and must be selected explicitly. On native Windows x64, download and extract the qualified CI delivery, then select its SDK archive, for example:

```powershell
.\scripts\start-wslc-x64.cmd -ArchivePath "D:\Releases\cbodotnet-sdk-10.0.403-linux-x64-build.41301145771.tar.gz"
```

If the archive is stored elsewhere, pass its path as the first argument or with `-ArchivePath`. Quote paths that contain spaces.

```powershell
.\scripts\start-wslc-arm64.cmd "D:\Releases\sdk-linux-arm64.tar.gz"
.\scripts\start-wslc-arm64.cmd -ArchivePath "D:\Releases\sdk-linux-arm64.tar.gz" -Name sdk-arm64-other -Port 5001
```

| Option | Behavior |
| --- | --- |
| First argument or `-ArchivePath PATH` | Selects the SDK `.tar.gz` to install |
| `-Name NAME` | Names a new test container. Use 2–63 letters, digits, `_`, `.`, or `-`, starting with a letter or digit |
| `-Port NUMBER` | Selects the Windows loopback port. The default is `5000`; the container port is always `5000` |
| `-NoAttach` | Prepares the environment, prints connection instructions, and exits without opening interactive Bash |

```powershell
.\scripts\start-wslc-arm64.cmd -NoAttach
```

Reusing an existing container requires a matching architecture, selected archive SHA-256, and Windows port. To test a different archive or port, choose a new `-Name`. Use a different Windows port as well if the existing container will run at the same time.

## Container contents

The ARM64 base is `mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-arm64v8`; the x64 base is `mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-amd64`. These Ubuntu 24.04 images provide system dependencies without a preinstalled .NET runtime or SDK. The `dotnet` used in Bash therefore comes from the selected locally built archive. [Official image manifest](https://github.com/dotnet/dotnet-docker/blob/main/manifest.json), [ARM64 runtime-deps Dockerfile](https://github.com/dotnet/dotnet-docker/blob/main/src/runtime-deps/10.0/noble/arm64v8/Dockerfile).

During initial setup, only the archive and setup script are copied into the container. Setup then:

1. Verifies that the copied archive matches the SHA-256 calculated on Windows.
2. Checks that the container CPU and the ELF architecture of the `dotnet` executable match the target.
3. Installs the SDK at `/opt/cbodotnet/sdk` and prints `dotnet --info`.

On reconnection, the launcher checks the container's configuration labels and the SDK's archive hash marker, then reuses the installed SDK. It does not rehash every SDK file or extract the archive again on each connection.

| Location or setting | Purpose |
| --- | --- |
| `/opt/cbodotnet/sdk` | SDK extracted from the selected archive, configured through `DOTNET_ROOT` and PATH |
| `/work` | Bash starting directory and project workspace |
| `ASPNETCORE_URLS=http://0.0.0.0:5000` | Default listening address for access from outside the container |
| Windows `127.0.0.1:<Port>` → container `5000` | Connection path for Windows browsers and HTTP clients |

This environment **does not mount a volume or a Windows workspace**. The SDK and `/work` are stored in the container's writable layer. They survive leaving Bash and stopping the container, but are removed when the container is deleted. Changes in `/work` are not automatically copied to the Windows project directory.

## Running a console app and native apphost

Run these commands in the Linux Bash session. If a project with the same name already exists, run that project instead of creating it again, or choose a new name.

```bash
cd /work
dotnet --info
dotnet new console -o ConsoleDemo --framework net10.0
dotnet run --project ConsoleDemo

dotnet publish ConsoleDemo/ConsoleDemo.csproj \
  --configuration Release --self-contained false \
  --output /work/console-publish
/work/console-publish/ConsoleDemo
```

The default console example prints `Hello, World!` through both execution paths. The final command runs the native Linux apphost using the installed runtime. External NuGet packages and workloads require separate downloads and compatibility checks.

## Running a web app and accessing it from Windows

Start a web app in Linux Bash:

```bash
cd /work
dotnet new web -o WebDemo --framework net10.0
dotnet run --project WebDemo --no-launch-profile \
  --urls http://0.0.0.0:5000
```

Using `--no-launch-profile` and an explicit listening address selects the published container port `5000` instead of the template's development port. Open `http://localhost:5000/` in a Windows browser or check it from a separate Windows PowerShell window:

```powershell
(Invoke-WebRequest "http://127.0.0.1:5000/").Content
```

The default web example returns `Hello World!`. If the session was created with `-Port 5001`, change only the Windows URL to `http://localhost:5001/`. The app inside the container still listens on `0.0.0.0:5000`. Press `Ctrl+C` in Linux Bash to stop the web app.

## Reconnecting and stopping

After leaving Bash with `exit`, run the same CMD to return to the same container and `/work`. If the container is stopped, the CMD starts it before connecting. If the initial command specified `-ArchivePath`, `-Name`, or `-Port`, pass the same values when reconnecting.

```powershell
.\scripts\start-wslc-arm64.cmd
```

To connect directly from PowerShell:

```powershell
& "$env:ProgramFiles\WSL\wslc.exe" exec -i -t -w /work cbodotnet-sdk-test-arm64 /bin/bash --noprofile --rcfile /opt/cbodotnet/session.bashrc -i
```

To stop the container when finished, run the following on Windows. The SDK and `/work` are retained, and running app processes are terminated. After restarting through the CMD, start any apps you need again.

```powershell
& "$env:ProgramFiles\WSL\wslc.exe" stop cbodotnet-sdk-test-arm64
```

When invoking the CLI directly from CMD, use this path syntax:

```bat
"%ProgramFiles%\WSL\wslc.exe" container list --all
```

The launcher does not automatically delete containers. After saving any work you need, run the following on a stopped container **only if you explicitly choose to delete the container, its SDK, and `/work`**. Substitute the container name if you used `-Name`.

```powershell
& "$env:ProgramFiles\WSL\wslc.exe" container rm cbodotnet-sdk-test-arm64
```

## Results on this PC

The following checks were completed on Windows ARM64 with `wslc 3.0.3.0`, using the ARM64 archive `10.0.403 build.1`.

| Check | Result |
| --- | --- |
| ARM64 CMD with default options | Interactive Bash input and `exit` worked |
| `-NoAttach` | Installed the SDK, printed its information, and exited without attaching |
| SDK identity | Version `10.0.403`, RID `linux-arm64` |
| Console | Correct output from `dotnet run` and the built native apphost |
| ASP.NET Core | Built the web app and received HTTP 200 with `Hello World!` from Windows at `127.0.0.1:5000` |
| Stop and rerun the same CMD | Retained the same container ID, `/work/session-proof.txt`, and apphost |
| Custom archive path | Created a new container using directory and file names containing spaces |
| Existing session with different settings | Rejected reuse of the same name with a different `-Port` |
| x64 CMD host check on ARM64 | Rejected execution with exit code `1`; this does not validate native x64 execution |

The runtime-deps base image digest used for validation was `sha256:1b1cd2aa285ed1175fe4027ba1f26c88bb17beeaeccc43ded69083383c52dd95`. The launcher uses an image tag and `--pull missing`, so a new environment is not guaranteed to select this digest.

After validation, the default `cbodotnet-sdk-test-arm64` container was restarted and left running. It contains the `/work/Hello` and `/work/Web` examples. The web process used during validation was terminated when the container was stopped; start the app in Bash to access it again. Later Linux x64 archives are qualified separately in the [native x64 CI results](ci-x64-results.md). Launcher execution on native Windows x64 remains separately unvalidated.
