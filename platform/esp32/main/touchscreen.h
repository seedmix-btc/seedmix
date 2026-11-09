/**
 * @file touchscreen.h
 * @brief Capacitive touchscreen bring-up (esp_lcd_touch) for the ESP32 port.
 *
 * Wraps the official `esp_lcd_touch` framework plus a controller driver and
 * bridges it to an LVGL pointer input device. The Waveshare board's FT6336 is
 * register compatible with the FT5x06 family (same 0x38 address), so
 * `espressif/esp_lcd_touch_ft5x06` drives it.
 */

#ifndef SEEDMIX_ESP32_TOUCHSCREEN_H
#define SEEDMIX_ESP32_TOUCHSCREEN_H

#include <stdbool.h>

#include "esp_err.h"
#include "lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Bring up the touch controller and register an LVGL pointer indev.
 *
 * Requires i2c_bus_init() and display_init(). Returns ESP_ERR_NOT_FOUND
 * (without aborting) when the controller does not answer, so the board stays
 * usable through its buttons.
 */
esp_err_t touchscreen_init(void);

/**
 * @brief The LVGL pointer input device, or NULL if there is no touchscreen.
 */
lv_indev_t* touchscreen_get_indev(void);

/**
 * @brief Snapshot of the touch state, for the hardware debug screen.
 *
 * `raw_x` / `raw_y` are what the controller reported before the swap/invert
 * flags; `x` / `y` are the post-transform values LVGL sees. Comparing them
 * tells an orientation mistake apart from a broken panel.
 */
typedef struct {
    bool     present; /**< A controller was found and initialized. */
    bool     pressed; /**< LVGL currently sees a pressed pointer. */
    uint8_t  points;  /**< Touch points the controller reported last read. */
    uint16_t raw_x;   /**< Controller X, before swap/mirror. */
    uint16_t raw_y;   /**< Controller Y, before swap/mirror. */
    uint16_t x;       /**< X after swap/mirror (what LVGL uses). */
    uint16_t y;       /**< Y after swap/mirror (what LVGL uses). */
} touchscreen_debug_t;

/**
 * @brief Copy the latest touch state.
 *
 * `present` is false when there is no touchscreen.
 */
void touchscreen_debug_get(touchscreen_debug_t* out);

/**
 * @brief True when a touch controller was found and initialized.
 */
bool touchscreen_is_present(void);

#ifdef __cplusplus
}
#endif

#endif /* SEEDMIX_ESP32_TOUCHSCREEN_H */
