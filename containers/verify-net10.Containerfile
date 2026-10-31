ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG ICU_PACKAGE
ARG SSL_PACKAGE
ENV DEBIAN_FRONTEND=noninteractive
RUN . /etc/os-release \
    && case "$ID:$VERSION_ID:$ICU_PACKAGE:$SSL_PACKAGE" in \
        ubuntu:22.04:libicu70:libssl3|ubuntu:24.04:libicu74:libssl3t64|debian:13:libicu76:libssl3t64) ;; \
        *) echo 'The verification OS and dependency tuple is not supported.' >&2; exit 1 ;; \
       esac \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 binutils curl ca-certificates util-linux \
        "$ICU_PACKAGE" "$SSL_PACKAGE" libgssapi-krb5-2 \
        libstdc++6 zlib1g libgcc-s1 \
    && apt-get clean

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_NOLOGO=1
WORKDIR /tmp
