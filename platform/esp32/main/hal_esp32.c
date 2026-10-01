/**
 * @file hal_esp32.c
 * @brief ESP32 HAL implementation.
 *
 * Entropy comes from the on-chip hardware RNG via esp_fill_random(), which
 * does NOT require the WiFi or Bluetooth radio to be enabled.  The camera
 * entropy source is a stub until esp_camera is integrated (see the Kconfig
 * "Camera" menu).
 */

#include "hal.h"
#include "sdkconfig.h"
#include "util/error.h"
#include "util/utils.h"

#include <stdlib.h>
#include <string.h>

#if CONFIG_SEEDMIX_TRNG_SOURCE_HARDWARE
#include "esp_random.h"
#endif

/* -- Random ----------------------------------------------------------- */
const char* hal_get_random_source(void) {
#if CONFIG_SEEDMIX_TRNG_SOURCE_HARDWARE
    return "ESP32 hardware RNG";
#else
    return "disabled";
#endif
}

void hal_get_random(uint8_t* buf, size_t len) {
    ASSERT_OR_DIE(buf && len > 0, "hal_get_random: invalid buffer");

#if CONFIG_SEEDMIX_TRNG_SOURCE_HARDWARE
    esp_fill_random(buf, len);
#else
    (void)buf;
    (void)len;
    ASSERT_OR_DIE(0, "hal_get_random: TRNG disabled in Kconfig");
#endif
}

/* -- Camera ----------------------------------------------------------- */
bool hal_camera_available(void) {
#if CONFIG_SEEDMIX_CAMERA_ENABLE
    // TODO: probe the esp_camera sensor
    return false;
#else
    return false;
#endif
}

hal_camera_t* hal_camera_open(void) {
#if CONFIG_SEEDMIX_CAMERA_ENABLE
    // TODO: open esp_camera
#endif
    return NULL;
}

bool hal_camera_grab(hal_camera_t* cam, hal_camera_frame_t* out) {
    (void)cam;
    (void)out;
    return false;
}

void hal_camera_close(hal_camera_t* cam) { (void)cam; }

void hal_camera_frame_free(hal_camera_frame_t* frame) {
    if (!frame) return;
    if (frame->data) {
        secure_memzero(frame->data, frame->size);
        free(frame->data);
    }
    memset(frame, 0, sizeof(*frame));
}

/* -- Image files ------------------------------------------------------ */
/* QR codes come from the camera on this target: there is no file chooser, and
 * hal_file_image_available() == false hides the UI for it. */
bool hal_file_image_available(void) { return false; }

void hal_file_image_pick(void) {}

void hal_file_image_reset(void) {}

hal_file_image_status_t hal_file_image_poll(hal_camera_frame_t* out) {
    (void)out;
    return HAL_FILE_IMAGE_NONE;
}

/* -- Touch / pointer input ------------------------------------------- */
bool hal_touch_available(void) { return false; }
