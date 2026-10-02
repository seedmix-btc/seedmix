#!/usr/bin/env bash
# -- Build & run libFuzzer targets (Linux only) ----------------------------
# Usage:
#   FUZZ_TIME=30 ./scripts/fuzz.sh     Run each fuzzer for 30s (default)
# Requires clang and a prior libwally build (./scripts/build.sh).
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build_linux"
LIBWALLY_INC="${BUILD_DIR}/libwally-install/include"
LIBWALLY_LIBS=(
    "${BUILD_DIR}/libwally-install/lib/libwallycore.a"
    "${BUILD_DIR}/libwally-install/lib/libsecp256k1.a"
)

check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "Missing: $1" >&2
        exit 1
    fi
}

check_dep clang

# Clone dependencies if missing
source "${PROJECT_ROOT}/scripts/ensure_deps.sh"

if [ ! -f "${LIBWALLY_LIBS[0]}" ]; then
    echo "libwally not built - run ./scripts/build.sh first." >&2
    exit 1
fi

FUZZ_TIME="${FUZZ_TIME:-30}"

FLAGS=(
    -g -O1
    -fsanitize=fuzzer,address,undefined
    -I"${PROJECT_ROOT}/main"
    -I"${PROJECT_ROOT}/main/crypto"
    -I"${PROJECT_ROOT}/main/util"
    -I"${PROJECT_ROOT}/platform/linux"
    -I"${LIBWALLY_INC}"
)

# Libraries the current target needs on top of libwally (set per target below).
EXTRA_LIBS=()

# Fuzzer-found units land in the target's own corpus directory; the seed inputs
# are copied in from the test vectors so the fuzzers do not have to guess a
# valid file header first.
seed_corpus() {
    local dir="$1"
    shift
    mkdir -p "${dir}"
    for src in "$@"; do
        local dst="${dir}/$(basename "${src}")"
        [ -e "${src}" ] || continue
        [ -e "${dst}" ] || cp "${src}" "${dst}"
    done
}

run_fuzzer() {
    local name="$1"
    shift
    local corpus="${BUILD_DIR}/fuzz_corpus_${name#fuzz_}"
    echo "Building fuzzer: ${name}"
    clang "${FLAGS[@]}" "$@" "${LIBWALLY_LIBS[@]}" "${EXTRA_LIBS[@]}" -lm -lpthread -o "${BUILD_DIR}/${name}"

    echo "Running ${name} for ${FUZZ_TIME}s…"
    local args=(-max_total_time="${FUZZ_TIME}" -detect_leaks=0 -print_final_stats=1)
    if [ -d "${corpus}" ]; then
        args=("${corpus}" "${args[@]}")
    fi
    "${BUILD_DIR}/${name}" "${args[@]}"
}

MNEMONIC_DEPS=(
    "${PROJECT_ROOT}/main/crypto/mnemonic.c"
    "${PROJECT_ROOT}/main/crypto/bip39_wordlist.c"
    "${PROJECT_ROOT}/main/crypto/secure_stack.c"
    "${PROJECT_ROOT}/main/util/utils.c"
    "${PROJECT_ROOT}/fuzz/stubs.c"
)

run_fuzzer fuzz_mnemonic "${MNEMONIC_DEPS[@]}" "${PROJECT_ROOT}/fuzz/fuzz_mnemonic.c"
run_fuzzer fuzz_mnemonic_roundtrip "${MNEMONIC_DEPS[@]}" "${PROJECT_ROOT}/fuzz/fuzz_mnemonic_roundtrip.c"
run_fuzzer fuzz_mnemonic_combine "${MNEMONIC_DEPS[@]}" "${PROJECT_ROOT}/fuzz/fuzz_mnemonic_combine.c"

run_fuzzer fuzz_wordlist \
    "${PROJECT_ROOT}/main/crypto/bip39_wordlist.c" \
    "${PROJECT_ROOT}/fuzz/stubs.c" \
    "${PROJECT_ROOT}/fuzz/fuzz_wordlist.c"

SEEDQR_DEPS=(
    "${PROJECT_ROOT}/main/crypto/seedqr.c"
    "${PROJECT_ROOT}/main/crypto/bip39_wordlist.c"
    "${PROJECT_ROOT}/main/crypto/mnemonic.c"
    "${PROJECT_ROOT}/main/crypto/secure_stack.c"
    "${PROJECT_ROOT}/main/util/utils.c"
    "${PROJECT_ROOT}/fuzz/stubs.c"
)

run_fuzzer fuzz_seedqr_decode "${SEEDQR_DEPS[@]}" "${PROJECT_ROOT}/fuzz/fuzz_seedqr_decode.c"

run_fuzzer fuzz_txinspect \
    "${PROJECT_ROOT}/main/crypto/txinspect.c" \
    "${PROJECT_ROOT}/main/crypto/ur_psbt.c" \
    "${PROJECT_ROOT}/main/crypto/ur.c" \
    "${PROJECT_ROOT}/main/crypto/fountain.c" \
    "${PROJECT_ROOT}/main/util/utils.c" \
    "${PROJECT_ROOT}/fuzz/stubs.c" \
    "${PROJECT_ROOT}/fuzz/fuzz_txinspect.c"

run_fuzzer fuzz_ur \
    "${PROJECT_ROOT}/main/crypto/ur_psbt.c" \
    "${PROJECT_ROOT}/main/crypto/ur.c" \
    "${PROJECT_ROOT}/main/crypto/fountain.c" \
    "${PROJECT_ROOT}/fuzz/fuzz_ur.c"

run_fuzzer fuzz_ur_descriptor \
    "${PROJECT_ROOT}/main/crypto/ur_descriptor.c" \
    "${PROJECT_ROOT}/main/crypto/ur.c" \
    "${PROJECT_ROOT}/main/crypto/fountain.c" \
    "${PROJECT_ROOT}/main/crypto/descriptor.c" \
    "${PROJECT_ROOT}/main/util/utils.c" \
    "${PROJECT_ROOT}/fuzz/stubs.c" \
    "${PROJECT_ROOT}/fuzz/fuzz_ur_descriptor.c"

# Image decoders for the files a user picks on the scan screen.  Seeded from the
# test-vector images (and the format fixtures), because a random byte stream
# almost never looks like a GIF or a PNG header.
seed_corpus "${BUILD_DIR}/fuzz_corpus_gif" "${PROJECT_ROOT}"/tests/vectors/gif/*.gif
seed_corpus "${BUILD_DIR}/fuzz_corpus_png" "${PROJECT_ROOT}"/tests/vectors/seedqr/qr-png/*.png \
    "${PROJECT_ROOT}"/tests/vectors/png/*.png

run_fuzzer fuzz_gif \
    "${PROJECT_ROOT}/platform/linux/gif_gray.c" \
    "${PROJECT_ROOT}/platform/linux/image_file.c" \
    "${PROJECT_ROOT}/fuzz/fuzz_gif.c"

EXTRA_LIBS=(-lz)
run_fuzzer fuzz_png \
    "${PROJECT_ROOT}/platform/linux/png_gray.c" \
    "${PROJECT_ROOT}/platform/linux/image_file.c" \
    "${PROJECT_ROOT}/fuzz/fuzz_png.c"
EXTRA_LIBS=()
