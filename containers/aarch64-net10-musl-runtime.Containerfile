FROM docker.io/library/alpine@sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29

COPY apk-snapshots/ /cbodotnet-pinned-indexes/
COPY seed-apk-cache.sh /cbodotnet-seed-apk-cache.sh

# Native Alpine transaction. Keep authenticated original indexes and package bytes.
RUN printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' > /etc/apk/repositories \
    && mkdir /cbodotnet-apks \
    && apk --cache-dir /cbodotnet-apks update \
    && sh /cbodotnet-seed-apk-cache.sh /cbodotnet-apks /cbodotnet-pinned-indexes 9a6918bdad9239435f2acb887b465c2c41ce121c5a745580cde569766f913540 ad8f92f7111c96240bc7ec595d78201a74e4fc1ef2d50658f3136a446e0c7f08 \
    && sha256sum /cbodotnet-apks/APKINDEX* > /cbodotnet-apks/index-sha256.txt \
    && grep -q '9a6918bdad9239435f2acb887b465c2c41ce121c5a745580cde569766f913540' /cbodotnet-apks/index-sha256.txt \
    && grep -q 'ad8f92f7111c96240bc7ec595d78201a74e4fc1ef2d50658f3136a446e0c7f08' /cbodotnet-apks/index-sha256.txt \
    && apk --cache-dir /cbodotnet-apks fetch --recursive --output /cbodotnet-apks \
        bash=5.3.9-r1 \
        python3=3.14.10-r1 \
        curl=8.23.0-r0 \
        tar=1.35-r5 \
        binutils=2.45.1-r1 \
        ca-certificates=20261020-r0 \
        libgcc=15.2.0-r5 \
        libstdc++=15.2.0-r5 \
        libssl3=3.5.9-r0 \
        icu-libs=78.1-r0 \
        icu-data-full=78.1-r0 \
        tzdata=2026f-r0 \
        krb5-libs=1.22.2-r1 \
        brotli-libs=1.2.1-r0 \
        lttng-ust=2.14.2-r0 \
        coreutils=9.11-r0 \
        findutils=4.10.0-r1 \
        grep=3.12-r0 \
        sed=4.9-r2 \
        gawk=5.3.2-r2 \
        file=5.47-r2 \
    && apk --cache-dir /cbodotnet-apks add --no-network /cbodotnet-apks/*.apk \
        bash=5.3.9-r1 \
        python3=3.14.10-r1 \
        curl=8.23.0-r0 \
        tar=1.35-r5 \
        binutils=2.45.1-r1 \
        ca-certificates=20261020-r0 \
        libgcc=15.2.0-r5 \
        libstdc++=15.2.0-r5 \
        libssl3=3.5.9-r0 \
        icu-libs=78.1-r0 \
        icu-data-full=78.1-r0 \
        tzdata=2026f-r0 \
        krb5-libs=1.22.2-r1 \
        brotli-libs=1.2.1-r0 \
        lttng-ust=2.14.2-r0 \
        coreutils=9.11-r0 \
        findutils=4.10.0-r1 \
        grep=3.12-r0 \
        sed=4.9-r2 \
        gawk=5.3.2-r2 \
        file=5.47-r2 \
    && apk info -vv > /cbodotnet-apks/installed-packages.txt \
    && test "$(cat /etc/alpine-release)" = 3.24.4 \
    && ! apk info -e gcompat \
    && ! apk info -e libc6-compat

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_NOLOGO=1
WORKDIR /tmp
