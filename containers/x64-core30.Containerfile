FROM mcr.microsoft.com/dotnet/core/sdk@sha256:b3906812d41e505b7b81e4ee54a948d2acb8a2d5af1638b39a4f3d1654105833

# The retained native x64 Bionic image supplies OpenSSL 1.1 and ICU 60 for
# the separately installed .NET Core 3.0.100 bootstrap SDK.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang-6.0 llvm-6.0 lldb-6.0 liblldb-6.0-dev \
      cmake ninja-build autoconf automake gettext libtool pkg-config \
      python python2.7 python3 python3-distutils \
      curl wget git cpio file binutils \
      gpgv ubuntu-keyring time elfutils jq tar gzip xz-utils zip unzip patch rename \
      libbrotli-dev libicu-dev liblttng-ust-dev libssl-dev libkrb5-dev \
      zlib1g-dev libunwind8-dev libnuma-dev uuid-dev \
      debootstrap symlinks \
    && apt-get clean

# CoreCLR accepts clang6.0. Core-Setup's older cross compiler selector needs
# a recorded compatibility fix before this compiler can build that component.
# Clang uses the GNU linker supplied by binutils; this host does not need LLD.
RUN mkdir -p /opt/cbodotnet/llvm6/bin \
    && for tool in clang clang++ llvm-ar llvm-link llvm-nm llvm-objcopy llvm-objdump llvm-ranlib llvm-strip; do \
         ln -s "/usr/bin/${tool}-6.0" "/opt/cbodotnet/llvm6/bin/${tool}"; \
       done
ENV PATH="/opt/cbodotnet/llvm6/bin:${PATH}"
ENV CC=/usr/bin/clang-6.0 CXX=/usr/bin/clang++-6.0 CLR_CC=/usr/bin/clang-6.0 CLR_CXX=/usr/bin/clang++-6.0

# Preserve signed Ubuntu archive trust for an independently prepared target
# sysroot. The container's host libraries are not the target ABI policy.
RUN cp /usr/share/keyrings/ubuntu-archive-keyring.gpg /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
    && cat /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
           /usr/share/keyrings/ubuntu-archive-removed-keys.gpg \
         > /usr/share/keyrings/ubuntu-archive-keyring.gpg

# Bionic's Python 3 is sufficient for upstream scripts. Current project helpers
# requiring Python 3.9+ run on the CI host or in a separately pinned analysis
# container; this recipe does not supply that interpreter.
RUN test "$(uname -m)" = x86_64 \
    && test -f /usr/lib/x86_64-linux-gnu/libssl.so.1.1 \
    && clang-6.0 --version && cmake --version && python2.7 --version && python3 --version \
    && /usr/bin/ld --version \
    && python3 -c "import re,subprocess; version=tuple(map(int,re.search(r'cmake version ([0-9]+)\.([0-9]+)',subprocess.check_output(['cmake','--version']).decode()).groups())); assert version >= (3,8)" \
    && pkg-config --modversion icu-uc

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1 DOTNET_MULTILEVEL_LOOKUP=0 NUGET_XMLDOC_MODE=none
WORKDIR /source
