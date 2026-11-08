ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG MAIN_INDEX_SHA256
ARG COMMUNITY_INDEX_SHA256
COPY apk-snapshots/ /cbodotnet-pinned-indexes/
COPY seed-apk-cache.sh /cbodotnet-seed-apk-cache.sh
# Investigation worker only. The caller supplies the matching pinned Alpine
# base and authenticated index snapshots already used by the musl profiles.
RUN test "$(cat /etc/alpine-release)" = 3.24.4 \
    && test -n "$MAIN_INDEX_SHA256" && test -n "$COMMUNITY_INDEX_SHA256" \
    && printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' > /etc/apk/repositories \
    && mkdir /cbodotnet-apks \
    && apk --cache-dir /cbodotnet-apks update \
    && sh /cbodotnet-seed-apk-cache.sh /cbodotnet-apks /cbodotnet-pinned-indexes "$MAIN_INDEX_SHA256" "$COMMUNITY_INDEX_SHA256" \
    && apk --cache-dir /cbodotnet-apks fetch --recursive --output /cbodotnet-apks \
        bash=5.3.9-r1 build-base=0.5-r4 clang20=20.1.8-r3 lld20=20.1.8-r1 \
        cmake=4.2.3-r0 python3=3.14.10-r1 git=2.54.0-r0 patch=2.8.1-r0 \
        icu-dev=78.1-r0 icu-data-full=78.1-r0 openssl-dev=3.5.9-r0 \
        libunwind-dev=1.8.3-r0 gettext-dev=1.0-r0 curl-dev=8.23.0-r0 \
        linux-headers=7.0.0-r1 lttng-ust-dev=2.14.2-r0 ca-certificates=20261020-r0 \
        krb5-libs=1.22.2-r1 tzdata=2026f-r0 \
    && rm -f /cbodotnet-apks/icu-data-en-*.apk \
    && apk --cache-dir /cbodotnet-apks add --no-network /cbodotnet-apks/*.apk \
    && apk info -vv > /cbodotnet-apks/installed-packages.txt \
    && ! apk info -e gcompat && ! apk info -e libc6-compat && ! command -v dotnet \
    && addgroup -g 10001 core3-probe \
    && adduser -D -u 10001 -G core3-probe core3-probe
ENV PATH=/usr/lib/llvm20/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
WORKDIR /tmp
