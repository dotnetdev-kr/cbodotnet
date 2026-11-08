ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG MAIN_INDEX_SHA256
ARG COMMUNITY_INDEX_SHA256
COPY apk-snapshots/ /cbodotnet-pinned-indexes/
COPY seed-apk-cache.sh /cbodotnet-seed-apk-cache.sh
# Explicit Core3 runtime roots plus Python/readelf diagnostics. No SDK,
# compiler, development headers, curl CLI, or gawk supplies hidden providers.
RUN test "$(cat /etc/alpine-release)" = 3.24.4 \
    && printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' > /etc/apk/repositories \
    && mkdir /cbodotnet-apks \
    && apk --cache-dir /cbodotnet-apks update \
    && sh /cbodotnet-seed-apk-cache.sh /cbodotnet-apks /cbodotnet-pinned-indexes "$MAIN_INDEX_SHA256" "$COMMUNITY_INDEX_SHA256" \
    && apk --cache-dir /cbodotnet-apks fetch --recursive --output /cbodotnet-apks \
        python3=3.14.10-r1 binutils=2.45.1-r1 \
        musl=1.2.6-r3 ca-certificates=20261020-r0 libgcc=15.2.0-r5 libstdc++=15.2.0-r5 \
        libssl3=3.5.9-r0 libcrypto3=3.5.9-r0 icu-libs=78.1-r0 icu-data-full=78.1-r0 \
        tzdata=2026f-r0 krb5-libs=1.22.2-r1 zlib=1.4-r0 brotli-libs=1.2.1-r0 lttng-ust=2.14.2-r0 \
        libcurl=8.23.0-r0 libintl=1.0-r0 \
    && rm -f /cbodotnet-apks/icu-data-en-*.apk \
    && apk --cache-dir /cbodotnet-apks add --no-network /cbodotnet-apks/*.apk \
    && apk info -vv > /cbodotnet-apks/installed-packages.txt \
    && ! command -v dotnet && ! command -v clang && ! command -v gcc \
    && ! command -v curl && ! command -v gawk \
    && ! apk info -e gcompat && ! apk info -e libc6-compat \
    && addgroup -g 10001 core3-probe && adduser -D -u 10001 -G core3-probe core3-probe
ENV PYTHONDONTWRITEBYTECODE=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
WORKDIR /tmp
