ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG SDK_SERIES=10.0
ARG APK_DEPENDENCIES
RUN test "$(cat /etc/alpine-release)" = 3.24.4 \
    && test -n "$APK_DEPENDENCIES" \
    && apk add --no-cache $APK_DEPENDENCIES \
    && ! apk info -e gcompat \
    && ! apk info -e libc6-compat \
    && addgroup -g 1654 app \
    && adduser -D -u 1654 -G app app \
    && install -d -m 0777 /work
COPY rootfs/ /
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    DOTNET_ROOT=/opt/cbodotnet/${SDK_SERIES} \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
WORKDIR /work
USER app
CMD ["cbodotnet", "--info"]
