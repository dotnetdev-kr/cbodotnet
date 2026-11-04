ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG SDK_SERIES=10.0
ENV DEBIAN_FRONTEND=noninteractive
RUN . /etc/os-release \
    && test "$ID:$VERSION_ID" = debian:13 \
    && case "$SDK_SERIES" in 3.0|3.1) http_dependencies=libcurl4t64 ;; *) http_dependencies= ;; esac \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates libc6 libgcc-s1 libstdc++6 zlib1g libgssapi-krb5-2 libicu76 libssl3t64 $http_dependencies \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1654 app \
    && useradd --uid 1654 --gid 1654 --create-home app \
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
