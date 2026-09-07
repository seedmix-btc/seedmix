/**
 * @file keymap.h
 * @brief Translation layer: physical buttons -> logical LVGL keys.
 *
 *   button 0 alone       -> LV_KEY_LEFT  (previous focusable item)
 *   button 1 alone       -> LV_KEY_RIGHT (next focusable item)
 *   button 0 + button 1  -> LV_KEY_ENTER (confirm / activate)
 *
 * A single-button key is only committed after a short combo window so a
 * slightly staggered two-button press is still recognised as ENTER.
 */

#ifndef SEEDMIX_ESP32_KEYMAP_H
#define SEEDMIX_ESP32_KEYMAP_H

#include "lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create the keypad input device with the button translation.
 *
 * Must be called after buttons_init() and lv_init().
 */
void keymap_init(void);

/**
 * @brief Get the keypad input device (NULL if buttons are disabled).
 */
lv_indev_t* keymap_get_indev(void);

/**
 * @brief The currently-active logical key (debounced), or 0 if none.
 *
 * Returns LV_KEY_LEFT, LV_KEY_RIGHT, LV_KEY_ENTER, or 0, mirroring the
 * translation done for the keypad.  Useful for polling the live state of the
 * buttons.
 */
lv_key_t keymap_current_key(void);

#ifdef __cplusplus
}
#endif

#endif /* SEEDMIX_ESP32_KEYMAP_H */
