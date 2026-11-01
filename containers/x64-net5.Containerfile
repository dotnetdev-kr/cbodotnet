FROM mcr.microsoft.com/dotnet/sdk@sha256:1e34d3881f9e1da0b2e81de59656abc29be6993eef2362d9134d66530db8b6ba

# The retained Focal x64 SDK image supplies OpenSSL 1.1 and ICU 66 for
# historical build tools. The .NET 5 bootstrap SDK is installed separately.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang-9 llvm-9 lld-9 lldb liblldb-dev \
      cmake ninja-build autoconf automake gettext libtool pkg-config \
      python-is-python3 python3 python3-aiohttp \
      curl wget git cpio file binutils gpgv ubuntu-keyring time elfutils jq \
      tar gzip xz-utils zip unzip patch rename \
      libbrotli-dev libicu-dev liblttng-ust-dev libssl-dev libkrb5-dev \
      zlib1g-dev libunwind-dev libnuma-dev uuid-dev debootstrap \
    && apt-get clean

# The pinned runtime recommends LLVM 9. Keep its unversioned utility lookups
# consistent with the compiler while retaining the host GNU toolchain.
RUN mkdir -p /opt/cbodotnet/llvm9/bin \
    && for tool in clang clang++ ld.lld llvm-ar llvm-nm llvm-objcopy llvm-ranlib llvm-strip; do \
         ln -s "/usr/bin/${tool}-9" "/opt/cbodotnet/llvm9/bin/${tool}"; \
       done
ENV PATH="/opt/cbodotnet/llvm9/bin:${PATH}"
ENV CC=/usr/bin/clang-9 CXX=/usr/bin/clang++-9 CLR_CC=/usr/bin/clang-9 CLR_CXX=/usr/bin/clang++-9

# Retain historical Ubuntu signing keys for the independently prepared
# Xenial target sysroot without disabling package signature verification.
RUN cp /usr/share/keyrings/ubuntu-archive-keyring.gpg /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
    && cat /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
           /usr/share/keyrings/ubuntu-archive-removed-keys.gpg \
         > /usr/share/keyrings/ubuntu-archive-keyring.gpg

RUN test "$(uname -m)" = x86_64 \
    && clang-9 --version && cmake --version && ld.lld --version

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1 DOTNET_MULTILEVEL_LOOKUP=0
WORKDIR /source
