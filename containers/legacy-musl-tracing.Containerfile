ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE}

# Separate test-only tools. The canonical SDK-free minimal runtime image is
# still used independently for all offline/ICU/crypto/TLS consumer checks.
RUN mkdir /cbodotnet-trace-test-apks \
    && apk --cache-dir /cbodotnet-apks fetch --recursive --output /cbodotnet-trace-test-apks \
        lttng-tools=2.14.0-r1 babeltrace=2.0.6-r1 \
    && apk --no-network add /cbodotnet-trace-test-apks/*.apk \
    && apk info -vv > /cbodotnet-trace-test-apks/installed-packages.txt \
    && ! command -v dotnet \
    && ! command -v cc \
    && ! command -v clang
