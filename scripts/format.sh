#!/usr/bin/env bash
# -- Format C sources with clang-format -------------------------------------
# Usage:
#   ./scripts/format.sh            Format all project sources in-place
#   ./scripts/format.sh check      Check formatting without changing files
#   ./scripts/format.sh <file...>  Format specific files
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# -- clang-format ----------------------------------------------
# Override with: CLANG_FORMAT=/path/to/clang-format ./scripts/format.sh
CLANG_FORMAT="${CLANG_FORMAT:-clang-format-11}"
CLANG_FORMAT_MAJOR="11"

if ! command -v "$CLANG_FORMAT" &>/dev/null; then
    echo "Missing: $CLANG_FORMAT - install it (e.g. sudo apt install $CLANG_FORMAT)." >&2
    exit 1
fi

# Warn if the resolved binary does not match the pinned major version.
if ! "$CLANG_FORMAT" --version | grep -q "version ${CLANG_FORMAT_MAJOR}\."; then
    echo "Warning: expected clang-format ${CLANG_FORMAT_MAJOR}.x but got: $("$CLANG_FORMAT" --version)" >&2
fi

MODE="${1:-format}"

case "$MODE" in
    check)
        FLAGS=(--dry-run --Werror)
        [ "$#" -gt 0 ] && shift
        ;;
    format)
        FLAGS=(-i)
        [ "$#" -gt 0 ] && shift
        ;;
    *)
        # Any other first argument is treated as a file path.
        FLAGS=(-i)
        ;;
esac

# -- Collect files --------------------------------------------------------
if [ "$#" -gt 0 ]; then
    mapfile -t FILES < <(printf '%s\n' "$@")
else
    mapfile -t FILES < <(
        find "$PROJECT_ROOT" \
            \( -path "$PROJECT_ROOT/build*" -o \
               -path "$PROJECT_ROOT/external" -o \
               -path "$PROJECT_ROOT/lvgl" -o \
               -path "*managed_components*" \) -prune -o \
            \( -name '*.c' -o -name '*.h' \) -print
    )
fi

# -- Apply exclusions -----------------------------------------------------
EXCLUDE_FILES=(
    "$PROJECT_ROOT/main/lv_conf.h"
    "$PROJECT_ROOT/main/assets/splash_480x320_img.c"
    "$PROJECT_ROOT/main/assets/splash_480x320_img.h"
    "$PROJECT_ROOT/main/assets/splash_240x135_img.c"
    "$PROJECT_ROOT/main/assets/splash_240x135_img.h"
    "$PROJECT_ROOT/main/assets/logo_img.c"
    "$PROJECT_ROOT/main/assets/logo_img.h"
)
if [ "${#EXCLUDE_FILES[@]}" -gt 0 ]; then
    filtered=()
    for f in "${FILES[@]}"; do
        skip=0
        for x in "${EXCLUDE_FILES[@]}"; do
            if [ "$f" = "$x" ]; then skip=1; break; fi
        done
        [ "$skip" -eq 0 ] && filtered+=("$f")
    done
    FILES=("${filtered[@]}")
fi

if [ "${#FILES[@]}" -eq 0 ]; then
    echo "No files to format."
    exit 0
fi

# -- Run clang-format -----------------------------------------------------
"$CLANG_FORMAT" "${FLAGS[@]}" --style=file "${FILES[@]}"
