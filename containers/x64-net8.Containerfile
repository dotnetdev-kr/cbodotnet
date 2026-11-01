FROM mcr.microsoft.com/dotnet-buildtools/prereqs@sha256:3c6f20064af0ba7844c51b17f6fe06fd499fb27af0aba281254bd573af830d73

# Native x64 build tools for the pinned .NET 8 source-build orchestration.
# Target headers and libraries come from the separately prepared Xenial sysroot.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang-18 llvm-18 lld-18 lld lldb-18 liblldb-18-dev \
      cmake ninja-build autoconf automake gettext libtool pkg-config \
      python-is-python3 python3 python3-aiohttp python3-zstandard \
      curl wget git cpio file binutils gpgv ubuntu-keyring time elfutils jq \
      tar gzip xz-utils zstd zip unzip patch \
      libbrotli-dev libicu-dev liblttng-ust-dev libssl-dev libkrb5-dev \
      zlib1g-dev libunwind-dev libnuma-dev uuid-dev debootstrap \
    && apt-get clean

# Xenial uses historical Ubuntu archive keys. Retain both inputs and keep
# signature verification enabled when preparing the independent target sysroot.
RUN cp /usr/share/keyrings/ubuntu-archive-keyring.gpg /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
    && cat /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
           /usr/share/keyrings/ubuntu-archive-removed-keys.gpg \
         > /usr/share/keyrings/ubuntu-archive-keyring.gpg

# NativeAOT linker probes require the unversioned ld.lld executable on PATH.
RUN clang-18 --version && cmake --version \
    && clang-18 -fuse-ld=lld -Wl,--version \
    && gcc -fuse-ld=lld -Wl,--version

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1
WORKDIR /vmr
