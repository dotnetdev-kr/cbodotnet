FROM mcr.microsoft.com/dotnet-buildtools/prereqs@sha256:3c6f20064af0ba7844c51b17f6fe06fd499fb27af0aba281254bd573af830d73

# Native runtime prerequisites follow the pinned VMR's Linux requirements.
# Target headers/libraries come from the separately prepared Xenial sysroot.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang-18 llvm-18 lld-18 lldb-18 liblldb-18-dev \
      cmake ninja-build python-is-python3 python3 python3-aiohttp python3-zstandard \
      curl git cpio file binutils gpgv ubuntu-keyring time elfutils jq \
      libicu-dev liblttng-ust-dev libssl-dev libkrb5-dev zlib1g-dev \
      libunwind-dev libnuma-dev debootstrap && apt-get clean

# Xenial metadata is signed by historical Ubuntu archive keys. Keep signature
# verification enabled and retain both original inputs alongside the union.
RUN cp /usr/share/keyrings/ubuntu-archive-keyring.gpg /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
    && cat /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
           /usr/share/keyrings/ubuntu-archive-removed-keys.gpg \
         > /usr/share/keyrings/ubuntu-archive-keyring.gpg

# The pinned base supplies Node 20 and npm. Refuse an inadequate inherited tool.
RUN node --version && npm --version \
    && node -e 'if (Number(process.versions.node.split(".")[0]) < 20) process.exit(1)'

# The tagged NativeAOT SDK invokes gcc -fuse-ld=lld, which needs ld.lld on PATH.
RUN apt-get update && apt-get install -y --no-install-recommends lld \
    && apt-get clean && gcc -fuse-ld=lld -Wl,--version

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1
WORKDIR /vmr
