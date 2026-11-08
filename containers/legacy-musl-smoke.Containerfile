ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE}

# Original source-build's layout-comparison assertion invokes git diff. Retain
# its separate authenticated test-only APK transaction; this image does not
# change the frozen canonical minimal runtime used by native consumer probes.
RUN mkdir /cbodotnet-original-test-apks \
    && apk --cache-dir /cbodotnet-apks fetch --recursive --output /cbodotnet-original-test-apks git=2.54.0-r0 \
    && apk --no-network add /cbodotnet-original-test-apks/*.apk \
    && ! command -v dotnet \
    && ! command -v cc \
    && ! command -v clang
