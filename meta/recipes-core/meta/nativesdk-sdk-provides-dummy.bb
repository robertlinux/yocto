DUMMYARCH = "sdk-provides-dummy-${SDKPKGSUFFIX}"

DUMMYPROVIDES_PACKAGES = "\
    pkgconfig \
"

DUMMYPROVIDES = "\
    /bin/sh \
    /bin/bash \
    /usr/bin/env \
    /usr/bin/pkg-config \
    libGL.so()(64bit) \
    libGL.so \
"

require dummy-sdk-package.inc

inherit nativesdk
