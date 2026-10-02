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
 * Pulls frames through hal_camera_grab() so it exercises exactly the path the
 * application uses.  The image is drawn at a fixed preview size and scaled to
 * fit; the frame counter and the reported dimensions are what make a stalled
 * or half-working camera obvious.
 *
 * @return The created screen.
 */
lv_obj_t* camera_test_create(void);

/**
 * @brief Grab and display the next frame.
 *
 * Cheap no-op unless the camera test screen is the active one, so it is safe
 * to call from a timer on every tick.  Frames are rate-limited internally.
 */
void camera_test_update(void);

#ifdef __cplusplus
}
#endif

#endif /* SEEDMIX_ESP32_CAMERA_TEST_H */
