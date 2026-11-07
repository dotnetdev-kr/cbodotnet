ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG MAIN_INDEX_SHA256
ARG COMMUNITY_INDEX_SHA256
ARG APK_PACKAGES
COPY apk-snapshots/ /cbodotnet-pinned-indexes/
COPY seed-apk-cache.sh /cbodotnet-seed-apk-cache.sh
RUN test "$(cat /etc/alpine-release)" = 3.24.4 \
    && test -n "$APK_PACKAGES" \
    && printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' > /etc/apk/repositories \
    && mkdir /cbodotnet-apks \
    && apk --cache-dir /cbodotnet-apks update \
    && sh /cbodotnet-seed-apk-cache.sh /cbodotnet-apks /cbodotnet-pinned-indexes "$MAIN_INDEX_SHA256" "$COMMUNITY_INDEX_SHA256" \
    && apk --cache-dir /cbodotnet-apks fetch --recursive --output /cbodotnet-apks $APK_PACKAGES \
    && apk --cache-dir /cbodotnet-apks add --no-network /cbodotnet-apks/*.apk $APK_PACKAGES \
    && apk info -vv > /cbodotnet-apks/installed-packages.txt \
    && ! apk info -e gcompat \
    && ! apk info -e libc6-compat \
    && ! command -v dotnet \
    && addgroup -g 10001 cbot-musl \
    && adduser -D -u 10001 -G cbot-musl cbot-musl
ENV PATH=/usr/lib/llvm20/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_NOLOGO=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /tmp
