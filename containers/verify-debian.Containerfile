FROM docker.io/library/debian@sha256:89c1ea91e897f0fe0a3731595330bc45b8bdef4047464a07116f891a94054b31

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 binutils curl ca-certificates libicu76 libssl3t64 \
        libgssapi-krb5-2 libstdc++6 zlib1g libgcc-s1 \
    && apt-get clean

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_NOLOGO=1
