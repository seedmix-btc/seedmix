#!/usr/bin/env bash
# -- Build script for Linux prototype ---------------------------------------
# Usage:
#   ./scripts/build.sh           Debug build (mouse/touch input)
#   ./scripts/build.sh release   Release build
#   ./scripts/build.sh asan      Debug build with AddressSanitizer
#   ./scripts/build.sh buttons   Debug build with button input emulation
#   ./scripts/build.sh clean     Clean build directory
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build_linux"

# -- Check for dependencies ---------------------------------------------
check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "❌ Missing: $1 - install it and try again." >&2
        exit 1
    fi
}

check_dep cmake
check_dep pkg-config
check_dep autoconf
check_dep automake
check_dep libtool

if ! pkg-config --exists sdl2; then
    echo "❌ SDL2 not found. Install:  sudo apt install libsdl2-dev" >&2
    exit 1
fi

# -- Clone submodules if missing ---------------------------------------
source "${PROJECT_ROOT}/scripts/ensure_deps.sh"

# -- Clean -------------------------------------------------------------
if [ "${1:-}" = "clean" ]; then
    echo "Cleaning build directory…"
    rm -rf "$BUILD_DIR"
    echo "✅ Clean."
    exit 0
fi

# -- Configure & Build ------------------------------------------------
BUILD_TYPE="${1:-Debug}"
ASAN_FLAG=""
BUTTONS_FLAG="-DENABLE_BUTTONS=OFF"

if [ "$BUILD_TYPE" = "asan" ]; then
    BUILD_TYPE="Debug"
    ASAN_FLAG="-DENABLE_ASAN=ON"
    echo "AddressSanitizer enabled"
elif [ "$BUILD_TYPE" = "buttons" ]; then
    BUILD_TYPE="Debug"
    BUTTONS_FLAG="-DENABLE_BUTTONS=ON"
    echo "Button input emulation enabled"
fi
BUILD_TYPE="${BUILD_TYPE^}"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "Configuring (${BUILD_TYPE})…"
cmake "$PROJECT_ROOT" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DLVGL_DIR="${PROJECT_ROOT}/external/lvgl" \
    $ASAN_FLAG \
    $BUTTONS_FLAG

echo "Building…"
cmake --build . -- -j"$(nproc)"

echo ""
echo "✅ Build complete: ${BUILD_DIR}/seedmix"
echo "   Run it:  ${BUILD_DIR}/seedmix"
