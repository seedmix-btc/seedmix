# seedmix main component: platform bring-up (display, buttons, HAL), the
# application entry point (main_esp32.c) and the shared app sources from
# ../../../main.

set(SHARED_MAIN_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../main")

idf_component_register(
    SRCS
        "main_esp32.c"
        "debug_screen.c"
        "graphics_test.c"
        "keymap.c"
        "display.c"
        "buttons.c"
        "hal_esp32.c"
    INCLUDE_DIRS
        "."
        "${SHARED_MAIN_DIR}"
        "${SHARED_MAIN_DIR}/util"
        "${SHARED_MAIN_DIR}/crypto"
        "${SHARED_MAIN_DIR}/qr"
        "${SHARED_MAIN_DIR}/ui"
    REQUIRES
        lvgl
        esp_lcd
        driver
        esp_timer
        esp_hw_support
        libwally
        qrencode
        quirc
)

# Shared application sources
set(SHARED_APP_SOURCES
    "${SHARED_MAIN_DIR}/main.c"
    "${SHARED_MAIN_DIR}/ui/ui.c"
    "${SHARED_MAIN_DIR}/assets/splash_480x320_img.c"
    "${SHARED_MAIN_DIR}/assets/splash_240x135_img.c"
    "${SHARED_MAIN_DIR}/assets/logo_img.c"
    "${SHARED_MAIN_DIR}/ui/word_entry.c"
    "${SHARED_MAIN_DIR}/ui/mnemonic_view.c"
    "${SHARED_MAIN_DIR}/ui/log.c"
    "${SHARED_MAIN_DIR}/crypto/mnemonic.c"
    "${SHARED_MAIN_DIR}/crypto/touch.c"
    "${SHARED_MAIN_DIR}/crypto/dice.c"
    "${SHARED_MAIN_DIR}/crypto/coin.c"
    "${SHARED_MAIN_DIR}/crypto/secure_stack.c"
    "${SHARED_MAIN_DIR}/crypto/bip39_wordlist.c"
    "${SHARED_MAIN_DIR}/crypto/seedqr.c"
    "${SHARED_MAIN_DIR}/crypto/txinspect.c"
    "${SHARED_MAIN_DIR}/crypto/descriptor.c"
    "${SHARED_MAIN_DIR}/crypto/ur_descriptor.c"
    "${SHARED_MAIN_DIR}/crypto/ur.c"
    "${SHARED_MAIN_DIR}/crypto/fountain.c"
    "${SHARED_MAIN_DIR}/qr/qr.c"
    "${SHARED_MAIN_DIR}/util/error.c"
    "${SHARED_MAIN_DIR}/util/log.c"
    "${SHARED_MAIN_DIR}/util/utils.c"
)
target_sources(${COMPONENT_LIB} PRIVATE ${SHARED_APP_SOURCES})
