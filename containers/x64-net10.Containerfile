FROM mcr.microsoft.com/dotnet-buildtools/prereqs@sha256:3c6f20064af0ba7844c51b17f6fe06fd499fb27af0aba281254bd573af830d73

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        lld-18 python3-aiohttp python3-zstandard binutils gpgv \
        ubuntu-keyring time elfutils jq \
    && apt-get clean

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_NOLOGO=1
WORKDIR /vmr
