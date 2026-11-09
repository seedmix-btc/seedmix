#!/usr/bin/env bash
# -- Web (Emscripten) build script ------------------------------------------
# Usage:
#   ./scripts/build_web.sh          Configure + build (Release) into build_web/
#   ./scripts/build_web.sh serve    Build, then serve http://localhost:8000
#                                   (PORT=8080 to pick another port)
#   ./scripts/build_web.sh clean    Remove build_web/
#
# Builds are incremental, so `serve` always builds first: an up-to-date tree
# costs about a second.
#
# The Emscripten SDK is auto-installed into external/emsdk on first run (see
# ensure_deps.sh).  Set EMSDK=/path/to/emsdk to use an existing SDK instead.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build_web"
PAGE="${BUILD_DIR}/seedmix.html"
PORT="${PORT:-8000}"

MODE="${1:-build}"
case "$MODE" in
    build | serve | clean) ;;
    *)
        echo "❌ Unknown option: $MODE" >&2
        echo "   Usage: $0 [serve|clean]" >&2
        exit 1
        ;;
esac

serve_page() {
    echo "Serving on http://localhost:${PORT}/ (Ctrl-C to stop)…"
    exec "${PROJECT_ROOT}/scripts/serve_web.py" "$PORT" "$BUILD_DIR"
}

# Cleaning needs no toolchain, so handle it before touching the SDK.
if [ "$MODE" = "clean" ]; then
    echo "Cleaning build directory…"
    rm -rf "$BUILD_DIR"
    echo "✅ Clean."
    exit 0
fi

check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "❌ Missing: $1 - $2" >&2
        exit 1
    fi
}

# -- Clone pinned deps + install the Emscripten SDK ------------------------
# shellcheck disable=SC1091
source "${PROJECT_ROOT}/scripts/ensure_deps.sh"

if [ -n "${EMSDK:-}" ] && [ -f "${EMSDK}/emsdk_env.sh" ]; then
    EMSDK_DIR="$EMSDK"   # use a pre-existing SDK if one is provided
else
    ensure_emsdk
    EMSDK_DIR="${PROJECT_ROOT}/external/emsdk"
fi

# shellcheck disable=SC1091
source "${EMSDK_DIR}/emsdk_env.sh"

check_dep emcc "could not activate the Emscripten SDK"
check_dep emcmake "could not activate the Emscripten SDK"
check_dep emconfigure "could not activate the Emscripten SDK"
check_dep emmake "could not activate the Emscripten SDK"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure once. Re-running it on every build regenerates the build files,
# which invalidates ExternalProject steps; make re-runs CMake itself when a
# CMakeLists changes, so there is nothing to gain from doing it here.
if [ ! -f CMakeCache.txt ]; then
    echo "Configuring (Emscripten, Release)…"
    emcmake cmake "$PROJECT_ROOT" \
        -DCMAKE_BUILD_TYPE=Release
fi

echo "Building…"
cmake --build . -- -j"$(nproc)"

echo ""
echo "✅ Build complete: ${PAGE}"
echo "   Serve it:  ./scripts/build_web.sh serve"
echo "              (the page needs cross-origin isolation for its threads; a"
echo "               plain 'python3 -m http.server' leaves them unavailable)"
echo "   Then open: http://localhost:${PORT}/seedmix.html"
echo "   (Camera access needs a secure context: http://localhost or https)"

if [ "$MODE" = "serve" ]; then
    echo ""
    serve_page
fi
