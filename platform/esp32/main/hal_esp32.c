/**
 * @file hal_esp32.c
 * @brief ESP32 HAL implementation.
 *
 * Entropy comes from the on-chip hardware RNG via esp_fill_random(), which
 * does NOT require the WiFi or Bluetooth radio. Camera frames come from the
 * official esp_camera driver, which talks SCCB over the shared I2C bus.
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

/* Capture size sets how many pixels each QR module gets: QVGA is enough for a
 * preview but leaves dense codes unreadable, VGA gives 4x. RGB565 frames live
 * in PSRAM. Kconfig picks the start size; hal_camera_set_size() switches. */
#define CAMERA_FB_COUNT 2

/* Tile side for the orientation transform. A quarter turn maps a destination
 * row onto a source column, so a row-major pass would read one pixel per cache
 * line; a tile keeps the rows it touches in cache. */
#define CAMERA_TILE 64

// always_inline keeps these per-pixel helpers fused into the transform loop at
// the IDF debug default (-Og), where a call per pixel costs more than the work.
#define CAMERA_INLINE static inline __attribute__((always_inline))

#if CONFIG_SEEDMIX_CAMERA_FRAMESIZE_QVGA
#define CAMERA_DEFAULT_SIZE HAL_CAMERA_SIZE_QVGA
#else
#define CAMERA_DEFAULT_SIZE HAL_CAMERA_SIZE_VGA
#endif

// Orientation of the frame handed to the app. A quarter turn is done in
// software in hal_camera_grab(); 90 and 270 swap width and height.
#if CONFIG_SEEDMIX_CAMERA_ROTATION_90
#define CAMERA_ROTATION 90
#elif CONFIG_SEEDMIX_CAMERA_ROTATION_180
#define CAMERA_ROTATION 180
#elif CONFIG_SEEDMIX_CAMERA_ROTATION_270
#define CAMERA_ROTATION 270
#else
#define CAMERA_ROTATION 0
#endif

// 1/0 rather than the Kconfig symbols: an unset bool is undefined, not 0, and
// these are used as values.
#if CONFIG_SEEDMIX_CAMERA_HMIRROR
#define CAMERA_HMIRROR 1
#else
#define CAMERA_HMIRROR 0
#endif

#if CONFIG_SEEDMIX_CAMERA_VFLIP
#define CAMERA_VFLIP 1
#else
#define CAMERA_VFLIP 0
#endif

static bool              s_camera_ready  = false;
static bool              s_camera_probed = false; /* esp_camera_init() already tried */
static hal_camera_size_t s_camera_size   = CAMERA_DEFAULT_SIZE;

// hal.h keeps the session opaque; the ESP32 side only needs to know one is open.
struct hal_camera {
    bool open;
};

/* Copy one pixel, with the byte swap the sensor's RGB565 order needs. Inner
 * loop of the frame copy, so small and dependency-free on purpose. */
CAMERA_INLINE void camera_copy_pixel(uint8_t* dst, const uint8_t* src, size_t bpp, bool swap) {
    if (swap) {
        dst[0] = src[1];
        dst[1] = src[0];
    } else {
        memcpy(dst, src, bpp);
    }
}

/* One RGB565 pixel, byte-swapped on the way in. Bytes are assembled rather
 * than read as a halfword: the source address is rarely even. */
CAMERA_INLINE uint16_t camera_read_pixel16(const uint8_t* src, bool swap) {
    const uint16_t v = (uint16_t)((uint16_t)src[0] | ((uint16_t)src[1] << 8));
    return swap ? (uint16_t)((v >> 8) | (v << 8)) : v;
}

/* Two RGB565 pixels in one 32-bit store. The cost is writing to PSRAM, not
 * reading: at VGA/8 fps every extra store per pixel is tens of ms. */
CAMERA_INLINE void camera_store_pixel2(uint8_t* dst, uint16_t a, uint16_t b) {
    *(uint32_t*)(void*)dst = (uint32_t)a | ((uint32_t)b << 16);
}

/* Source pixel index (row-major) of destination pixel (ox, oy), for a frame
 * rotated clockwise by `rot`. Mirror/flip are applied by the caller first. */
CAMERA_INLINE size_t camera_rotate_index(size_t src_w, size_t src_h, int rot, size_t ox,
                                         size_t oy) {
    size_t sx = ox;
    size_t sy = oy;
    switch (rot) {
    case 90: /* clockwise: source bottom-left -> top-left */
        sx = oy;
        sy = src_h - 1 - ox;
        break;
    case 180:
        sx = src_w - 1 - ox;
        sy = src_h - 1 - oy;
        break;
    case 270: /* clockwise: source top-right -> top-left */
        sx = src_w - 1 - oy;
        sy = ox;
        break;
    default:
        break;
    }
    return sy * src_w + sx;
}

// Map esp_camera's format onto the HAL's.
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

// The driver's name for a HAL capture size.
static framesize_t camera_framesize(hal_camera_size_t size) {
    return (size == HAL_CAMERA_SIZE_QVGA) ? FRAMESIZE_QVGA : FRAMESIZE_VGA;
}

// One config for both the first init and a later size change (the driver is
// re-initialised with it), so it has to be built rather than spelled inline.
static camera_config_t camera_config_build(void) {
    return (camera_config_t){
        // Neither pin is routed on the Waveshare board
        .pin_pwdn  = -1,
        .pin_reset = -1,
        .pin_xclk  = CONFIG_SEEDMIX_CAMERA_PIN_XCLK,

        /* Talk SCCB over the existing shared I2C bus: the touch controller, IO
         * expander and camera all hang off the same two pins. esp32-camera
         * uses the new i2c_master API on IDF >= 5.4 and shares the i2c_bus. */
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
        // The backlight PWM owns LEDC timer 1 / channel 0 in display.c
        .ledc_timer   = LEDC_TIMER_0,
        .ledc_channel = LEDC_CHANNEL_1,

        .pixel_format = PIXFORMAT_RGB565,
        .frame_size   = camera_framesize(s_camera_size),
        .jpeg_quality = 12,
        .fb_count     = CAMERA_FB_COUNT,
        .fb_location  = CAMERA_FB_IN_PSRAM,
        // Continuous capture, so a grab always finds the newest frame.
        .grab_mode = CAMERA_GRAB_LATEST,
    };
}

/* Bring the sensor up on the shared I2C bus. Idempotent: the driver can only
 * be initialised once per boot. It is left running when a session closes, so
 * re-opening the camera view is instant. */
static bool camera_ensure_init(void) {
    if (s_camera_ready) {
        return true;
    }
    if (s_camera_probed) {
        return false;
    }
    s_camera_probed = true;

    const camera_config_t cfg = camera_config_build();
    const esp_err_t       err = esp_camera_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "camera init failed: %s", esp_err_to_name(err));
        return false;
    }

    /* The whole orientation (rotation, mirror, flip) is applied in
     * hal_camera_grab(), not in the sensor: with a quarter turn the sensor's
     * vflip would come out wrong, so the registers are left alone. */
    const sensor_t* sensor = esp_camera_sensor_get();
    ESP_LOGI(TAG, "camera ready: PID 0x%04x, rotation %d deg, hmirror %d, vflip %d",
             sensor ? (unsigned)sensor->id.PID : 0u, CAMERA_ROTATION, CAMERA_HMIRROR, CAMERA_VFLIP);

    s_camera_ready = true;
    return true;
}

bool hal_camera_available(void) { return camera_ensure_init(); }

hal_camera_t* hal_camera_open(void) {
    if (!camera_ensure_init()) {
        return NULL;
    }

    // The driver streams on its own; the session exists only to be handed back.
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

    // Never block: this runs from an LVGL timer; one stale frame beats a stall.
    if (!esp_camera_available_frames()) {
        return false;
    }

    camera_fb_t* fb = esp_camera_fb_get();
    if (!fb) {
        return false;
    }

    /* The copy below walks the frame as raw pixels, so a format it cannot
     * describe (JPEG) would read past the buffer. Only the raw formats the
     * driver can be configured for are accepted. */
    const hal_camera_pixfmt_t fmt = camera_pixfmt(fb->format);
    if (fmt != HAL_CAMERA_FMT_RGB565 && fmt != HAL_CAMERA_FMT_GRAY8 && fmt != HAL_CAMERA_FMT_YUYV) {
        esp_camera_fb_return(fb);
        return false;
    }
    const size_t bpp = (fmt == HAL_CAMERA_FMT_GRAY8) ? 1u : 2u;

    // The HAL owns its frame buffers: the app frees them with
    // hal_camera_frame_free() whenever it likes, which the driver's pool cannot.
    uint8_t* copy = malloc(fb->len);
    if (!copy) {
        esp_camera_fb_return(fb);
        return false;
    }

    /* The sensor shifts out the high byte first, while LVGL (and the Linux/web
     * HALs) treat RGB565 as native-endian. Swap while copying. */
    const bool swap = (fmt == HAL_CAMERA_FMT_RGB565);

    /* YUYV packs two pixels around one chroma sample, so it is never rotated;
     * the camera is configured for RGB565, so this is a safety net. */
    const int  rot  = (fmt == HAL_CAMERA_FMT_YUYV) ? 0 : CAMERA_ROTATION;
    const bool turn = (rot == 90 || rot == 270);

    const size_t src_w = fb->width;
    const size_t src_h = fb->height;
    const size_t dst_w = turn ? src_h : src_w;
    const size_t dst_h = turn ? src_w : src_h;

    /* A 32-bit store covers two pixels, so the destination pair must start on a
     * word boundary: even pixel index, even-width row, word-aligned buffer. */
    const bool pack2 =
        (bpp == 2) && ((dst_w % 2u) == 0) && (((uintptr_t)copy & (sizeof(uint32_t) - 1u)) == 0);

    if (rot == 0 && !CAMERA_HMIRROR && !CAMERA_VFLIP) {
        // No geometry change: a straight copy (with an optional byte swap).
        const size_t count = src_w * src_h;
        size_t       i     = 0;
        if (pack2) {
            for (; i + 1 < count; i += 2) {
                camera_store_pixel2(copy + i * 2, camera_read_pixel16(fb->buf + i * 2, swap),
                                    camera_read_pixel16(fb->buf + (i + 1) * 2, swap));
            }
        }
        for (; i < count; i++) {
            camera_copy_pixel(copy + i * bpp, fb->buf + i * bpp, bpp, swap);
        }
    } else {
        /* One pass over the destination in tiles. Mirror/flip are applied to
         * the finished picture (after rotation), so the Kconfig flags mean what
         * the user sees; the rotation maps back to the sensor's frame.
         *
         * The tiling is what makes this usable: after a quarter turn a
         * row-major pass reads one pixel per cache line (~250 ms/frame at VGA),
         * while a tile keeps the rows it touches in cache. */
        for (size_t ty = 0; ty < dst_h; ty += CAMERA_TILE) {
            const size_t ty_end = (ty + CAMERA_TILE < dst_h) ? (ty + CAMERA_TILE) : dst_h;
            for (size_t tx = 0; tx < dst_w; tx += CAMERA_TILE) {
                const size_t tx_end = (tx + CAMERA_TILE < dst_w) ? (tx + CAMERA_TILE) : dst_w;
                for (size_t dy = ty; dy < ty_end; dy++) {
                    uint8_t*     drow = copy + (dy * dst_w) * bpp;
                    const size_t oy   = CAMERA_VFLIP ? (dst_h - 1 - dy) : dy;
                    size_t       dx   = tx;

                    if (pack2) {
                        for (; dx + 1 < tx_end; dx += 2) {
                            const size_t   ox0 = CAMERA_HMIRROR ? (dst_w - 1 - dx) : dx;
                            const size_t   ox1 = CAMERA_HMIRROR ? (dst_w - 2 - dx) : (dx + 1);
                            const uint16_t a   = camera_read_pixel16(
                                fb->buf + camera_rotate_index(src_w, src_h, rot, ox0, oy) * bpp,
                                swap);
                            const uint16_t b = camera_read_pixel16(
                                fb->buf + camera_rotate_index(src_w, src_h, rot, ox1, oy) * bpp,
                                swap);
                            camera_store_pixel2(drow + dx * bpp, a, b);
                        }
                    }

                    // Odd tail: odd tile width, or the last pixel of a row.
                    for (; dx < tx_end; dx++) {
                        const size_t ox = CAMERA_HMIRROR ? (dst_w - 1 - dx) : dx;
                        camera_copy_pixel(drow + dx * bpp,
                                          fb->buf +
                                              camera_rotate_index(src_w, src_h, rot, ox, oy) * bpp,
                                          bpp, swap);
                    }
                }
            }
        }
    }

    out->data           = copy;
    out->size           = fb->len;
    out->width          = (uint32_t)dst_w;
    out->height         = (uint32_t)dst_h;
    out->bytes_per_line = (uint32_t)(dst_w * bpp);
    out->pixfmt         = fmt;

    esp_camera_fb_return(fb);
    return true;
}

/* The sensor stays initialised: esp_camera_init() may only run once per boot,
 * and re-opening the camera view is common. */
void hal_camera_close(hal_camera_t* cam) { free(cam); }

bool hal_camera_size_switchable(void) { return true; }

hal_camera_size_t hal_camera_size(void) { return s_camera_size; }

bool hal_camera_set_size(hal_camera_size_t size) {
    if (size >= HAL_CAMERA_SIZE_COUNT) {
        return false;
    }
    if (size == s_camera_size) {
        return true;
    }

    // Nothing running yet: the size applies when the camera comes up, and a
    // switch re-arms a previously failed init.
    if (!s_camera_ready) {
        s_camera_size   = size;
        s_camera_probed = false;
        return true;
    }

    const hal_camera_size_t previous = s_camera_size;
    s_camera_size                    = size;

    /* Size is baked into the driver's frame buffers, so switching restarts the
     * driver. A session holds no driver state and stays valid. */
    const camera_config_t cfg = camera_config_build();
    const esp_err_t       err = esp_camera_reconfigure(&cfg);
    if (err == ESP_OK) {
        return true;
    }

    ESP_LOGW(TAG, "capture size switch failed: %s", esp_err_to_name(err));

    // Go back to the size that was working; if that fails too, the driver is
    // down and the next camera_ensure_init() will bring it back up.
    s_camera_size             = previous;
    const camera_config_t old = camera_config_build();
    if (esp_camera_reconfigure(&old) != ESP_OK) {
        /* The driver is down: allow the next camera_ensure_init() to re-init. */
        s_camera_ready  = false;
        s_camera_probed = false;
    }
    return false;
}

#else /* !CONFIG_SEEDMIX_CAMERA_ENABLE */

bool hal_camera_available(void) { return false; }

hal_camera_t* hal_camera_open(void) { return NULL; }

bool hal_camera_grab(hal_camera_t* cam, hal_camera_frame_t* out) {
    (void)cam;
    (void)out;
    return false;
}

void hal_camera_close(hal_camera_t* cam) { (void)cam; }

// Camera not built in, so there is no size to switch.
bool hal_camera_size_switchable(void) { return false; }

hal_camera_size_t hal_camera_size(void) { return HAL_CAMERA_SIZE_QVGA; }

bool hal_camera_set_size(hal_camera_size_t size) {
    (void)size;
    return false;
}

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
