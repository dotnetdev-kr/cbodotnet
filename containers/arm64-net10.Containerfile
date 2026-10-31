FROM mcr.microsoft.com/dotnet-buildtools/prereqs@sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4

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
