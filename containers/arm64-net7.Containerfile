FROM mcr.microsoft.com/dotnet-buildtools/prereqs@sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4

# Native ARM64 tools for the generated .NET 7 installer source-build tree.
# Target headers and libraries come from a separately prepared Xenial sysroot.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang-16 llvm-16 lld-16 lldb-16 liblldb-16-dev \
      cmake ninja-build autoconf automake gettext libtool pkg-config \
      python-is-python3 python3 python3-aiohttp python3-zstandard \
      curl wget git cpio file binutils gpgv ubuntu-keyring time elfutils jq \
      tar gzip xz-utils zstd zip unzip patch \
      libbrotli-dev libicu-dev liblttng-ust-dev libssl-dev libkrb5-dev \
      zlib1g-dev libunwind-dev libnuma-dev uuid-dev debootstrap qemu-user-static \
    && apt-get clean

# The base includes LLVM 18. Select LLVM 16 explicitly, including unversioned
# linker and LLVM utilities used by the older runtime and NativeAOT projects.
RUN mkdir -p /opt/cbodotnet/llvm16/bin \
    && for tool in clang clang++ ld.lld llvm-ar llvm-nm llvm-objcopy llvm-ranlib llvm-strip; do \
         ln -s "/usr/bin/${tool}-16" "/opt/cbodotnet/llvm16/bin/${tool}"; \
       done
ENV PATH="/opt/cbodotnet/llvm16/bin:${PATH}"
ENV CC=clang-16 CXX=clang++-16 CLR_CC=clang-16 CLR_CXX=clang++-16 CppCompilerAndLinker=clang16

# Retain current and historical Ubuntu archive keys while keeping signature
# verification enabled for the independent target sysroot.
RUN cp /usr/share/keyrings/ubuntu-archive-keyring.gpg /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
    && cat /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
           /usr/share/keyrings/ubuntu-archive-removed-keys.gpg \
         > /usr/share/keyrings/ubuntu-archive-keyring.gpg

RUN clang-16 --version && cmake --version && ld.lld --version \
    && clang-16 -fuse-ld=lld -Wl,--version \
    && gcc -fuse-ld=lld -Wl,--version

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1
WORKDIR /source
