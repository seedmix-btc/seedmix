/**
 * @file touch_test.h
 * @brief Touchscreen test screen: crosshair plus coordinate readout.
 */

#ifndef SEEDMIX_ESP32_TOUCH_TEST_H
#define SEEDMIX_ESP32_TOUCH_TEST_H

#include "lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Build the touchscreen test screen.
 *
 * The screen follows the finger with a crosshair and prints both the
 * controller-native coordinates and the values LVGL receives, so an
 * orientation (swap/mirror) mistake is distinguishable from a dead panel.
 *
 * @return The created screen.
 */
lv_obj_t* touch_test_create(void);

/**
 * @brief Redraw the crosshair and the coordinate readout.
 *
 * A cheap no-op unless the touch test screen is the active one, so it is
 * safe to call from a timer on every tick.
 */
void touch_test_update(void);

#ifdef __cplusplus
}
#endif

#endif /* SEEDMIX_ESP32_TOUCH_TEST_H */
