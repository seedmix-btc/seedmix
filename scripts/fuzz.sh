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
    -I"${LIBWALLY_INC}"
)

run_fuzzer() {
    local name="$1"
    shift
    echo "Building fuzzer: ${name}"
    clang "${FLAGS[@]}" "$@" "${LIBWALLY_LIBS[@]}" -lm -lpthread -o "${BUILD_DIR}/${name}"

    echo "Running ${name} for ${FUZZ_TIME}s…"
    "${BUILD_DIR}/${name}" -max_total_time="${FUZZ_TIME}" -detect_leaks=0 -print_final_stats=1
}

MNEMONIC_DEPS=(
    "${PROJECT_ROOT}/main/crypto/mnemonic.c"
    "${PROJECT_ROOT}/main/crypto/bip39_wordlist.c"
    "${PROJECT_ROOT}/main/crypto/secure_stack.c"
    "${PROJECT_ROOT}/main/util/utils.c"
    "${PROJECT_ROOT}/main/util/log.c"
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
    "${PROJECT_ROOT}/main/util/log.c"
    "${PROJECT_ROOT}/fuzz/stubs.c"
)

run_fuzzer fuzz_seedqr_decode "${SEEDQR_DEPS[@]}" "${PROJECT_ROOT}/fuzz/fuzz_seedqr_decode.c"
