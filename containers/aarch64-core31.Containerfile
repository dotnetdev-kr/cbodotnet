FROM mcr.microsoft.com/dotnet/sdk@sha256:a4028735b2ed1209c9116cebc74ae1c2fb27ea7d24b1be3f495fee0bac27dd52

# The official native AArch64 SDK image uses Ubuntu 20.04 with the OpenSSL 1.1
# and ICU libraries required to execute the historical .NET Core toolchain.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang-9 llvm-9 lld-9 lldb-9 liblldb-9-dev \
      cmake ninja-build autoconf automake gettext libtool pkg-config \
      python2 python3 locales \
      curl wget git cpio file binutils gpgv ubuntu-keyring time elfutils jq \
      tar gzip bzip2 xz-utils zip unzip patch \
      libicu-dev liblttng-ust-dev libssl-dev libcurl4-openssl-dev \
      libkrb5-dev zlib1g-dev libunwind-dev libnuma-dev uuid-dev \
      debootstrap qemu-user-static \
    && apt-get clean \
    && locale-gen en_US.UTF-8

# Several older native scripts fall back to unversioned compiler/LLVM names.
# Keep that selection explicit without modifying the distribution executables.
RUN mkdir -p /opt/cbodotnet/llvm9/bin \
    && for tool in clang clang++ ld.lld llvm-ar llvm-link llvm-nm llvm-objcopy llvm-objdump llvm-ranlib llvm-strip; do \
         ln -s "/usr/bin/${tool}-9" "/opt/cbodotnet/llvm9/bin/${tool}"; \
       done \
    && ln -s /usr/bin/python2 /opt/cbodotnet/llvm9/bin/python
ENV PATH="/opt/cbodotnet/llvm9/bin:${PATH}"
ENV CC=/usr/bin/clang-9 CXX=/usr/bin/clang++-9

# Retain the verification keys needed by a future independent legacy sysroot.
# This image alone does not establish that every native producer uses a sysroot.
RUN cp /usr/share/keyrings/ubuntu-archive-keyring.gpg /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
    && cat /usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg \
           /usr/share/keyrings/ubuntu-archive-removed-keys.gpg \
         > /usr/share/keyrings/ubuntu-archive-keyring.gpg

RUN test "$(uname -m)" = aarch64 \
    && clang --version && clang++ --version && ld.lld --version && llvm-objdump --version \
    && cmake --version && python --version && python3 --version \
    && dotnet --list-sdks && dotnet --list-runtimes

ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1
WORKDIR /source-build
