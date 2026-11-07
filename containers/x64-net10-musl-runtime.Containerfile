FROM docker.io/library/alpine@sha256:0f49f331d9212aff11b932863be4eb01cdf962969aa86dab7d1ee21ac6f5f52b

COPY apk-snapshots/ /cbodotnet-pinned-indexes/
COPY seed-apk-cache.sh /cbodotnet-seed-apk-cache.sh

# Native Alpine transaction. Keep authenticated original indexes and package bytes.
RUN printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' > /etc/apk/repositories \
    && mkdir /cbodotnet-apks \
    && apk --cache-dir /cbodotnet-apks update \
    && sh /cbodotnet-seed-apk-cache.sh /cbodotnet-apks /cbodotnet-pinned-indexes f976c7888999de04ae70250f872ad85bdc52309d2a5e06597a77f634f912d895 072b5bd71bf3b1a21da3cc3232f6370a3936945c0644d973420e62c58a7453f8 \
    && sha256sum /cbodotnet-apks/APKINDEX* > /cbodotnet-apks/index-sha256.txt \
    && grep -q 'f976c7888999de04ae70250f872ad85bdc52309d2a5e06597a77f634f912d895' /cbodotnet-apks/index-sha256.txt \
    && grep -q '072b5bd71bf3b1a21da3cc3232f6370a3936945c0644d973420e62c58a7453f8' /cbodotnet-apks/index-sha256.txt \
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
