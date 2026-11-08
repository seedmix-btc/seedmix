#!/usr/bin/env bash
# -- Configure libwally-core for the ExternalProject build -------------------
#
# Usage: configure_libwally.sh <src-dir> <build-dir> <prefix> <native|emscripten>
#                              [stamp-file]
#
# The configure step of an ExternalProject re-runs whenever CMake regenerates
# its build files, which happens on every reconfigure.  Doing the destructive
# part every time (wipe the tree, re-extract with `git archive`, re-run autogen
# and configure) threw away every object file, so the whole of libwally and
# secp256k1 was rebuilt from scratch for each build.  This script does that work
# only when it is actually stale: when the revision being built, or the prefix
# it installs into, differs from the last run.
set -euo pipefail

SRC="${1:?usage: configure_libwally.sh <src> <build> <prefix> <native|emscripten> [stamp]}"
BUILD="${2:?}"
PREFIX="${3:?}"
MODE="${4:?}"

# The stamp lives outside the tree being configured, so wiping it (and the
# submodule checkout, for the native build) cannot hide a stale configuration.
STAMP="${5:-${BUILD}/.seedmix-libwally-stamp}"

want() {
    printf '%s %s %s %s\n' \
        "$(git -C "$SRC" rev-parse HEAD)" \
        "$(git -C "$SRC/src/secp256k1" rev-parse HEAD)" \
        "$MODE" "$PREFIX"
}

WANT="$(want)"
if [ -f "$STAMP" ] && [ -f "$BUILD/config.status" ] && [ "$(cat "$STAMP")" = "$WANT" ]; then
    echo "libwally: already configured for $(git -C "$SRC" rev-parse --short HEAD), reusing ${BUILD}"
    exit 0
fi

# Stale: rebuild the tree (Emscripten, where the build dir is a copy) and
# regenerate configure.  Only a revision change gets this far, so the cost is
# paid once per change rather than once per build.
if [ "$BUILD" != "$SRC" ]; then
    echo "libwally: preparing a pristine tree in ${BUILD}"
    find "$BUILD" -mindepth 1 -delete
    git -C "$SRC" archive HEAD | tar -x -C "$BUILD"
    mkdir -p "$BUILD/src/secp256k1"
    git -C "$SRC/src/secp256k1" archive HEAD | tar -x -C "$BUILD/src/secp256k1"
fi

cd "$BUILD"
echo "libwally: running autogen.sh"
./tools/autogen.sh

echo "libwally: configuring for ${PREFIX}"
case "$MODE" in
    emscripten)
        emconfigure ./configure --prefix="$PREFIX" --enable-static --disable-shared \
            --disable-elements --enable-standard-secp
        ;;
    native)
        ./configure --prefix="$PREFIX" --enable-static --disable-shared \
            --disable-elements --enable-standard-secp
        ;;
    *)
        echo "unknown mode: $MODE" >&2
        exit 1
        ;;
esac

printf '%s\n' "$WANT" >"$STAMP"
