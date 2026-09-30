/**
 * @file camera_test.h
 * @brief Camera test screen: live RGB565 preview from the HAL camera.
 */

#ifndef SEEDMIX_ESP32_CAMERA_TEST_H
#define SEEDMIX_ESP32_CAMERA_TEST_H

#include "lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Build the camera test screen.
 *
 * Pulls frames through hal_camera_grab(), so it exercises exactly the path the
 * application uses. The frame counter and reported dimensions make a stalled
 * camera obvious.
 *
 * @return The created screen.
 */
lv_obj_t* camera_test_create(void);

/**
 * @brief Grab and display the next frame.
 *
 * No-op unless the camera test screen is active, so it is safe to call from a
 * timer on every tick.
 */
void camera_test_update(void);

#ifdef __cplusplus
}
#endif

#endif /* SEEDMIX_ESP32_CAMERA_TEST_H */
