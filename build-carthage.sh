#!/usr/bin/env bash

set -eu

CONFIGURATION="Release"
FRAMEWORK_NAME="MozillaAppServices.framework.zip"
ARCHIVE=true

while [[ "$#" -gt 0 ]]; do case $1 in
  --configuration) CONFIGURATION="$2"; shift;shift;;
  --out) FRAMEWORK_NAME="$2"; shift;shift;;
  --no-archive) ARCHIVE=false; shift;;
  *) echo "Unknown parameter: $1"; exit 1;
esac; done

set -vx

# Xcode 12 -- Carthage workaround
# See https://github.com/Carthage/Carthage/issues/3019
if xcodebuild -version | grep -q "Xcode 12.0"; then
  xcconfig="${PWD}/tmp.xcconfig"
  true > "$xcconfig"
  echo 'EXCLUDED_ARCHS__EFFECTIVE_PLATFORM_SUFFIX_simulator__NATIVE_ARCH_64_BIT_x86_64=arm64 arm64e armv7 armv7s armv6 armv8' >> "$xcconfig"
  echo 'EXCLUDED_ARCHS=$(inherited) $(EXCLUDED_ARCHS__EFFECTIVE_PLATFORM_SUFFIX_$(EFFECTIVE_PLATFORM_SUFFIX)__NATIVE_ARCH_64_BIT_$(NATIVE_ARCH_64_BIT))' >> "$xcconfig"
  export XCODE_XCCONFIG_FILE="${xcconfig}"
fi

carthage bootstrap --platform iOS --cache-builds

set -o pipefail && \
carthage build --no-skip-current --platform iOS --verbose --configuration "${CONFIGURATION}" --cache-builds | \
tee raw_xcodebuild.log | \
xcpretty

if [ "$ARCHIVE" = true ]; then
    ## When https://github.com/Carthage/Carthage/issues/2623 is fixed,
    ## carthage build --archive should work to produce a zip

    # Exclude SwiftProtobuf.
    zip -r "${FRAMEWORK_NAME}" Carthage/Build/iOS megazords/ios/DEPENDENCIES.md -x '*SwiftProtobuf.framework*/*'
fi
