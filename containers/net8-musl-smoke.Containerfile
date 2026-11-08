ARG BUILDER_IMAGE
FROM ${BUILDER_IMAGE}

# The original NET8 debug-symbol test uses eu-readelf, not GNU readelf.
# Reuse the builder's authenticated frozen APK indexes. These additional tools
# are test-only and do not enter the canonical minimal consumer image or SDK.
RUN mkdir /cbodotnet-net8-test-apks \
    && apk --cache-dir /cbodotnet-apks fetch --recursive --output /cbodotnet-net8-test-apks elfutils=0.195-r0 \
    && apk --no-network add /cbodotnet-net8-test-apks/*.apk \
    && apk info -v > /cbodotnet-net8-test-apks/installed-packages.txt \
    && eu-readelf --version > /cbodotnet-net8-test-apks/eu-readelf-version.txt
