/**
 * @file display.h
 * @brief ESP-IDF LVGL display driver (esp_lcd SPI panels).
 */

#ifndef SEEDMIX_ESP32_DISPLAY_H
#define SEEDMIX_ESP32_DISPLAY_H

#include <stdint.h>

#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Resolved display dimensions from Kconfig. */
#if defined(CONFIG_SEEDMIX_DISPLAY_RESOLUTION_CUSTOM)
#define DISPLAY_WIDTH CONFIG_SEEDMIX_DISPLAY_WIDTH_CUSTOM
#define DISPLAY_HEIGHT CONFIG_SEEDMIX_DISPLAY_HEIGHT_CUSTOM
#else
#define DISPLAY_WIDTH CONFIG_SEEDMIX_DISPLAY_WIDTH
#define DISPLAY_HEIGHT CONFIG_SEEDMIX_DISPLAY_HEIGHT
#endif

/**
 * @brief Initialize the SPI display and register an LVGL display.
 *
 * Reads the seedmix display Kconfig options.  Must be called after
 * lv_init() and lv_tick_set_cb().
 */
void display_init(void);

/**
 * @brief Pixels sent to the panel since the previous call, and reset to zero.
 *
 * Pairs with the LVGL pass duration to tell a render-bound pass from a
 * transfer-bound one.
 */
uint32_t display_flush_pixels_take(void);

#ifdef __cplusplus
}
#endif

#endif /* SEEDMIX_ESP32_DISPLAY_H */
