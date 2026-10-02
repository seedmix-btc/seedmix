/**
 * @file hal_esp32.c
 * @brief ESP32 HAL implementation.
 *
 * Entropy comes from the on-chip hardware RNG via esp_fill_random(), which
 * does NOT require the WiFi or Bluetooth radio to be enabled.  Camera frames
 * come from the official esp_camera driver, which talks SCCB over the shared
 * I2C bus (see the Kconfig "Camera" menu).
 */

#include "hal.h"
#include "sdkconfig.h"
#include "touchscreen.h"
#include "util/error.h"
#include "util/utils.h"

#include <stdlib.h>
#include <string.h>

#if CONFIG_SEEDMIX_TRNG_SOURCE_HARDWARE
#include "esp_random.h"
#endif

#if CONFIG_SEEDMIX_CAMERA_ENABLE
#include "driver/ledc.h"
#include "esp_camera.h"
#include "esp_log.h"
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
#if CONFIG_SEEDMIX_CAMERA_ENABLE

static const char* TAG = "camera";

/* Frame size and buffer count for the preview/QR path.  QVGA RGB565 is 150 KB
 * per frame and lives in PSRAM; the app only ever wants a preview-sized image
 * and decodes QR codes from it, so there is nothing to gain from capturing
 * more. */
#define CAMERA_FRAME_SIZE FRAMESIZE_QVGA
#define CAMERA_FB_COUNT 2

static bool s_camera_ready = false;

/* hal.h keeps the session opaque; the ESP32 side needs nothing beyond the
 * fact that a session is open, because esp_camera streams as soon as it is
 * initialised. */
struct hal_camera {
    bool open;
};

/* Maps the esp_camera format onto the HAL's platform-independent one. */
static hal_camera_pixfmt_t camera_pixfmt(pixformat_t format) {
    switch (format) {
    case PIXFORMAT_RGB565:
        return HAL_CAMERA_FMT_RGB565;
    case PIXFORMAT_GRAYSCALE:
        return HAL_CAMERA_FMT_GRAY8;
    case PIXFORMAT_YUV422:
        return HAL_CAMERA_FMT_YUYV;
    case PIXFORMAT_JPEG:
        return HAL_CAMERA_FMT_JPEG;
    default:
        return HAL_CAMERA_FMT_UNKNOWN;
    }
}

/* Bring the sensor up on the shared I2C bus.  Idempotent: the driver cannot
 * usefully be re-initialised, and it is deliberately left running when a
 * session is closed so re-opening the camera view is instant. */
static bool camera_ensure_init(void) {
    if (s_camera_ready) {
        return true;
    }

    const camera_config_t cfg = {
        /* Neither pin is routed on the Waveshare board */
        .pin_pwdn  = -1,
        .pin_reset = -1,
        .pin_xclk  = CONFIG_SEEDMIX_CAMERA_PIN_XCLK,

        /* Talk SCCB over the existing shared I2C bus rather than letting the
         * driver install its own: the touch controller, the IO expander and
         * the camera all hang off the same two pins.  esp32-camera uses the
         * new i2c_master API on IDF >= 5.4, so it attaches to the bus
         * i2c_bus_init() created and shares its locking. */
        .pin_sccb_sda  = -1,
        .pin_sccb_scl  = -1,
        .sccb_i2c_port = CONFIG_SEEDMIX_I2C_PORT,

        .pin_d7    = CONFIG_SEEDMIX_CAMERA_PIN_DATA7,
        .pin_d6    = CONFIG_SEEDMIX_CAMERA_PIN_DATA6,
        .pin_d5    = CONFIG_SEEDMIX_CAMERA_PIN_DATA5,
        .pin_d4    = CONFIG_SEEDMIX_CAMERA_PIN_DATA4,
        .pin_d3    = CONFIG_SEEDMIX_CAMERA_PIN_DATA3,
        .pin_d2    = CONFIG_SEEDMIX_CAMERA_PIN_DATA2,
        .pin_d1    = CONFIG_SEEDMIX_CAMERA_PIN_DATA1,
        .pin_d0    = CONFIG_SEEDMIX_CAMERA_PIN_DATA0,
        .pin_vsync = CONFIG_SEEDMIX_CAMERA_PIN_VSYNC,
        .pin_href  = CONFIG_SEEDMIX_CAMERA_PIN_HREF,
        .pin_pclk  = CONFIG_SEEDMIX_CAMERA_PIN_PCLK,

        .xclk_freq_hz = CONFIG_SEEDMIX_CAMERA_XCLK_HZ,
        /* The backlight PWM owns LEDC timer 1 / channel 0 in display.c */
        .ledc_timer   = LEDC_TIMER_0,
        .ledc_channel = LEDC_CHANNEL_1,

        .pixel_format = PIXFORMAT_RGB565,
        .frame_size   = CAMERA_FRAME_SIZE,
        .jpeg_quality = 12,
        .fb_count     = CAMERA_FB_COUNT,
        .fb_location  = CAMERA_FB_IN_PSRAM,
        /* Continuous capture, so a grab always finds the newest frame instead
         * of having to wait for one to be acquired. */
        .grab_mode = CAMERA_GRAB_LATEST,
    };

    const esp_err_t err = esp_camera_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "camera init failed: %s", esp_err_to_name(err));
        return false;
    }

    const sensor_t* sensor = esp_camera_sensor_get();
    ESP_LOGI(TAG, "camera ready: PID 0x%04x", sensor ? (unsigned)sensor->id.PID : 0u);

    s_camera_ready = true;
    return true;
}

bool hal_camera_available(void) { return camera_ensure_init(); }

hal_camera_t* hal_camera_open(void) {
    if (!camera_ensure_init()) {
        return NULL;
    }

    /* The driver streams on its own once initialised; the session only exists
     * so the app has something to hand back to hal_camera_close(). */
    hal_camera_t* cam = calloc(1, sizeof(hal_camera_t));
    ASSERT_OR_DIE(cam, "out of memory for camera session");
    cam->open = true;
    return cam;
}

bool hal_camera_grab(hal_camera_t* cam, hal_camera_frame_t* out) {
    (void)cam;
    if (!out || !s_camera_ready) {
        return false;
    }

    /* Never block: this runs from an LVGL timer, and showing the previous
     * frame for one more tick beats stalling the UI. */
    if (!esp_camera_available_frames()) {
        return false;
    }

    camera_fb_t* fb = esp_camera_fb_get();
    if (!fb) {
        return false;
    }

    /* The HAL owns its frame buffers: the app frees them with
     * hal_camera_frame_free() whenever it likes, which the driver's pool
     * cannot allow. */
    uint8_t* copy = malloc(fb->len);
    if (!copy) {
        esp_camera_fb_return(fb);
        return false;
    }

    const hal_camera_pixfmt_t fmt = camera_pixfmt(fb->format);
    if (fmt == HAL_CAMERA_FMT_RGB565) {
        /* The sensor shifts out the high byte of every pixel first, while
         * LVGL (and the Linux/web HALs) treat RGB565 as native-endian.  Swap
         * while copying so the shared UI sees one consistent format. */
        for (size_t i = 0; i + 1 < fb->len; i += 2) {
            copy[i]     = fb->buf[i + 1];
            copy[i + 1] = fb->buf[i];
        }
    } else {
        memcpy(copy, fb->buf, fb->len);
    }

    out->data           = copy;
    out->size           = fb->len;
    out->width          = fb->width;
    out->height         = fb->height;
    out->bytes_per_line = fb->width * (fmt == HAL_CAMERA_FMT_GRAY8 ? 1u : 2u);
    out->pixfmt         = fmt;

    esp_camera_fb_return(fb);
    return true;
}

/* The sensor deliberately stays initialised: esp_camera_init() may only be
 * called once per boot, and re-opening the camera view is common. */
void hal_camera_close(hal_camera_t* cam) { free(cam); }

#else /* !CONFIG_SEEDMIX_CAMERA_ENABLE */

bool hal_camera_available(void) { return false; }

hal_camera_t* hal_camera_open(void) { return NULL; }

bool hal_camera_grab(hal_camera_t* cam, hal_camera_frame_t* out) {
    (void)cam;
    (void)out;
    return false;
}

void hal_camera_close(hal_camera_t* cam) { (void)cam; }

#endif /* CONFIG_SEEDMIX_CAMERA_ENABLE */

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
bool hal_touch_available(void) { return touchscreen_is_present(); }
