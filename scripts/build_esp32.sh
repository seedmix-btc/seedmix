#!/usr/bin/env bash
# -- Build / flash / monitor the ESP32 firmware -----------------------------
# Usage:
#   ./scripts/build_esp32.sh              Build
#   ./scripts/build_esp32.sh flash        Build + flash via idf.py
#   ./scripts/build_esp32.sh monitor      Open the serial monitor
#   ./scripts/build_esp32.sh menuconfig   Edit the Kconfig (seedmix Hardware)
#   ./scripts/build_esp32.sh clean        Remove the build dir
#   ./scripts/build_esp32.sh fullclean    Also delete the generated sdkconfig
#
# Boards (BOARD=...):
#   waveshare_3_5   Waveshare ESP32-S3-Touch-LCD-3.5 / -3.5-C (ESP32-S3, default)
#   ttgo_tdisplay   classic ESP32 TTGO T-Display
#
# Configuring is a two-file job: the shared base `sdkconfig.defaults` plus the
# board's overlay `sdkconfig.defaults.<board>`, applied in that order so the
# overlay wins.
#
# Environment overrides:
#   BOARD               Board preset (see above)
#   ESP_TARGET          IDF target; defaults to the board's own target
#   BUILD_DIR           Build directory (default: <root>/build_<board>)
#   SDKCONFIG_DEFAULTS  Full defaults list, semicolon-separated, paths relative
#                       to platform/esp32
#                       (default: sdkconfig.defaults;<board overlay>)
#   IDF_ACTIVATE        Path to the ESP-IDF activate script
#                       (default: ~/.espressif/tools/activate_idf_v5.5.5.sh)
#   ESP_PORT            Serial port for flash/monitor (default: /dev/ttyACM0)
#
# Each board keeps its own build directory.  The generated `sdkconfig` itself
# has to live in the project directory (that is the path ESP-IDF expects), so a
# stamp file records which board produced it and the script regenerates it when
# you switch boards.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ESP32_DIR="${PROJECT_ROOT}/platform/esp32"
IDF_ACTIVATE="${IDF_ACTIVATE:-$HOME/.espressif/tools/activate_idf_v5.5.5.sh}"
ESP_PORT="${ESP_PORT:-/dev/ttyACM0}"
BOARD="${BOARD:-waveshare_3_5}"

# A board is a target plus an overlay applied on top of the shared defaults.
BASE_DEFAULTS="sdkconfig.defaults"
case "$BOARD" in
    ttgo_tdisplay)
        BOARD_TARGET="esp32"
        BOARD_OVERLAY="sdkconfig.defaults.ttgo_tdisplay"
        ;;
    waveshare_3_5)
        BOARD_TARGET="esp32s3"
        BOARD_OVERLAY="sdkconfig.defaults.waveshare_3_5"
        ;;
    *)
        echo "Unknown BOARD '$BOARD' (known boards: ttgo_tdisplay, waveshare_3_5)" >&2
        exit 1
        ;;
esac

ESP_TARGET="${ESP_TARGET:-$BOARD_TARGET}"
BUILD_DIR="${BUILD_DIR:-${PROJECT_ROOT}/build_${BOARD}}"
ACTION="${1:-build}"

# Shared base first, board overlay second: a key set in the overlay wins.
# Callers may override the whole list with their own semicolon-separated value.
DEFAULTS_REL="${SDKCONFIG_DEFAULTS:-${BASE_DEFAULTS};${BOARD_OVERLAY}}"
STAMP_VALUE="${BOARD}:${DEFAULTS_REL}"

# ESP-IDF resolves relative SDKCONFIG_DEFAULTS entries against the process CWD
# (not necessarily the project directory), so pass absolute paths.
DEFAULTS_ABS=""
for defaults_file in $(printf '%s' "$DEFAULTS_REL" | tr ';' ' '); do
    case "$defaults_file" in
        /*) abs="$defaults_file" ;;
        *) abs="${ESP32_DIR}/${defaults_file}" ;;
    esac
    if [ ! -f "$abs" ]; then
        echo "Kconfig defaults file not found: $abs" >&2
        exit 1
    fi
    DEFAULTS_ABS="${DEFAULTS_ABS:+$DEFAULTS_ABS;}$abs"
done

if [ ! -f "$IDF_ACTIVATE" ]; then
    echo "ESP-IDF activate script not found: $IDF_ACTIVATE" >&2
    echo "Set IDF_ACTIVATE=/path/to/activate_idf_vX.Y.Z.sh" >&2
    exit 1
fi

# idf.py needs the ESP-IDF environment (toolchain, Python venv, IDF_PATH).
# The activate script only works when it detects it's being sourced by a
# shell, so delegate to `bash -c` (where $0 is "bash") and pass state through
# the environment.  Inside we call idf.py by path because the activate script
# exposes it as a shell alias, which is not expanded in non-interactive shells.
IDF_ACTIVATE="$IDF_ACTIVATE" BUILD_DIR="$BUILD_DIR" ESP_PORT="$ESP_PORT" \
    ESP32_DIR="$ESP32_DIR" ACTION="$ACTION" ESP_TARGET="$ESP_TARGET" \
    SDKCONFIG_DEFAULTS_ABS="$DEFAULTS_ABS" STAMP_VALUE="$STAMP_VALUE" \
    BOARD="$BOARD" DEFAULTS_NAMES="$DEFAULTS_REL" \
bash -c '
    set -e
    # shellcheck disable=SC1090
    source "$IDF_ACTIVATE" >/dev/null

    cd "$ESP32_DIR"

    STAMP=".sdkconfig.board"

    if [ "$ACTION" = "clean" ]; then
        python "$IDF_PATH/tools/idf.py" -B "$BUILD_DIR" clean
        exit 0
    fi

    if [ "$ACTION" = "fullclean" ]; then
        python "$IDF_PATH/tools/idf.py" -B "$BUILD_DIR" fullclean
        rm -f sdkconfig sdkconfig.old "$STAMP"
        exit 0
    fi

    # (Re)configure when there is no sdkconfig yet, when either defaults file
    # is newer, or when a different board produced the current one.  idf.py
    # only reads the defaults files when sdkconfig is first created, and it
    # takes both the defaults list and the target from the environment.
    needs_configure=""
    if [ ! -f sdkconfig ]; then
        needs_configure=" - no sdkconfig yet"
    elif [ "$(cat "$STAMP" 2>/dev/null || true)" != "$STAMP_VALUE" ]; then
        needs_configure=" - board or defaults changed"
    else
        for defaults_file in $(printf "%s" "$SDKCONFIG_DEFAULTS_ABS" | tr ";" " "); do
            if [ "$defaults_file" -nt sdkconfig ]; then
                needs_configure=" - $(basename "$defaults_file") is newer"
                break
            fi
        done
    fi

    if [ -n "$needs_configure" ]; then
        echo "Configuring ${BOARD} (${ESP_TARGET}) from ${DEFAULTS_NAMES}${needs_configure}"
        rm -f sdkconfig sdkconfig.old
        export SDKCONFIG_DEFAULTS="$SDKCONFIG_DEFAULTS_ABS"
        python "$IDF_PATH/tools/idf.py" -B "$BUILD_DIR" set-target "$ESP_TARGET"
        printf "%s" "$STAMP_VALUE" > "$STAMP"
    fi

    case "$ACTION" in
        flash)   python "$IDF_PATH/tools/idf.py" -B "$BUILD_DIR" -p "$ESP_PORT" flash ;;
        monitor) python "$IDF_PATH/tools/idf.py" -B "$BUILD_DIR" -p "$ESP_PORT" monitor ;;
        *)       python "$IDF_PATH/tools/idf.py" -B "$BUILD_DIR" "$ACTION" ;;
    esac
'
