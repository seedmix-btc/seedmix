/**
 * @file main/main.c
 * @brief BIP39 mnemonic generator workflow - generates, enters, combines, and finalizes mnemonics.
 */

#include "app.h"
#include "crypto/coin.h"
#include "crypto/descriptor.h"
#include "crypto/dice.h"
#include "crypto/mnemonic.h"
#include "crypto/seedqr.h"
#include "crypto/touch.h"
#include "crypto/txinspect.h"
#include "crypto/ur_descriptor.h"
#include "crypto/ur_psbt.h"
#include "hal.h"
#include "lvgl.h"
#include "qr/qr.h"
#include "ui/log.h"
#include "ui/ui.h"
#include "ui/word_entry.h"
#include "util/error.h"
#include "util/log.h"
#include "util/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -- Workflow state --------------------------------------------------- */
static mnemonic_t* current     = NULL;
static unsigned    word_count  = 12;
static qr_grid_t   exported_qr = {0};

/* -- Forward declarations --------------------------------------------- */
/* Where a decoded QR payload came from.  The camera keeps streaming, so a
 * payload the screen cannot use is quietly passed over; a file is read once,
 * so the screen says so instead. */
typedef enum {
    QR_SOURCE_CAMERA = 0,
    QR_SOURCE_FILE,
} qr_source_t;

static void on_other_source(void);
static void on_camera_image(void);
static void on_camera_use(void);
static void on_camera_cancel(void);
static void on_scan_qr(void);
static void on_scan_file(void);
static bool on_seedqr_payload(qr_source_t source, const uint8_t* payload, size_t plen);
static void on_qr_scan_cancel(void);
static bool qr_scan_deliver(qr_source_t source, const uint8_t* payload, size_t plen);
static void qr_scan_poll_file(void);
static void qr_scan_error(const char* msg);
static void qr_scan_screen_show(void);
static void on_inspect_tx(lv_event_t* e);
static bool on_tx_payload(qr_source_t source, const uint8_t* payload, size_t plen);
static bool on_descriptor_payload(qr_source_t source, const uint8_t* payload, size_t plen);
static void on_inspect_tx_cancel(void);
static void on_inspect_tx_done(void);
static void on_descriptor_cancel(void);
static void on_scan_descriptor(void);
static void on_skip_descriptor(void);
static void on_descriptor_overview_continue(void);
static void on_descriptor_overview_cancel(void);
static void start_tx_scan(void);
static void on_export_seedqr(void);
static void on_export_done(void);
static void on_dice_rolls(void);
static void on_coin_flips(void);
static void on_touch_screen(void);
static void on_touch_tap(lv_coord_t x, lv_coord_t y);
static void on_show_state(void);
static void go_back_source(void);
static void go_source(void);
static void on_finish(void);
static void on_finish_done(void);
static void show_merge_screen(mnemonic_t* new_m, const char* source_desc);
static void on_we_ok(void);
static void on_we_error_cancel(void);
static void on_we_error_retry(void);
static void on_we_error_choose(void);
static void on_we_word_selected(const char* word);
static void on_create_mnemonic(lv_event_t* e);
static void on_test_error(lv_event_t* e);
static void show_main_screen(void);

static void on_generating_msg(const char* msg) {
    ui_show_msg(msg);
    ui_delay_ms(1500);
}

// Combine `m` into `current` if the word counts match, otherwise discard `m`
// and return to the source screen
static void merge_or_reject(mnemonic_t* m, mnemonic_type_t result_type, const char* source_desc) {
    if (current && mnemonic_entropy_size(current) != mnemonic_entropy_size(m)) {
        ui_log_add("rejected %s: word count mismatch", source_desc);
        mnemonic_discard(m);
        ui_show_msg("Word count mismatch - mnemonic discarded");
        ui_delay_ms(1500);
        go_source();
        return;
    }
    if (current) {
        show_merge_screen(m, source_desc);
    } else {
        current = m;
        ui_log_add("started with %s", source_desc);
        ui_show_mnemonic(mnemonic_words(current), result_type, go_source, NULL);
    }
}

static void on_generate(void) {
    ui_show_msg("Generating words...");
    ui_delay_ms(500);
    mnemonic_t* m = mnemonic_generate(word_count, on_generating_msg);
    char        desc[64];
    int         res = snprintf(desc, sizeof(desc), "generated %u-word from %s", word_count,
                       hal_get_random_source());
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(desc), "description string too long");
    merge_or_reject(m, MNEMONIC_TYPE_GENERATED, desc);
}

static word_entry_handle_t we_handle   = NULL;
static mnemonic_t*         pending_new = NULL;
static char                pending_desc[64];
static char                we_entered[MNEMONIC_MAX_INPUT_LEN];

static void on_enter_manual(void);
static void on_we_complete(void);

static void on_merge_done(void) {
    ASSERT_OR_DIE(pending_new, "no pending mnemonic");
    // The merge screen still holds entropy hex + words, it stays the active
    // screen until ui_swap_screen() runs inside ui_show_mnemonic(), so scrub
    // it now instead of waiting for deferred deletion
    ui_scrub_screen(lv_screen_active());
    current     = mnemonic_combine(current, pending_new);
    pending_new = NULL;
    ui_log_add("merged with %s", pending_desc);
    ui_show_mnemonic(mnemonic_words(current), MNEMONIC_TYPE_MERGED, go_source, NULL);
}

static void show_merge_screen(mnemonic_t* new_m, const char* source_desc) {
    uint8_t ca[32], na[32], ma[32];
    size_t  elen = mnemonic_entropy_size(current);
    mnemonic_to_entropy(current, ca);
    mnemonic_to_entropy(new_m, na);
    for (size_t i = 0; i < elen; i++) ma[i] = ca[i] ^ na[i];

    mnemonic_t* preview = mnemonic_from_entropy(ma, elen);

    char ca_hex[2 * 32 + 1], na_hex[2 * 32 + 1], ma_hex[2 * 32 + 1];
    ASSERT_OR_DIE(bytes_to_hex(ca, elen, ca_hex, sizeof(ca_hex)), "merge hex buffer too small");
    ASSERT_OR_DIE(bytes_to_hex(na, elen, na_hex, sizeof(na_hex)), "merge hex buffer too small");
    ASSERT_OR_DIE(bytes_to_hex(ma, elen, ma_hex, sizeof(ma_hex)), "merge hex buffer too small");

    secure_memzero(ma, sizeof(ma));
    secure_memzero(na, sizeof(na));
    secure_memzero(ca, sizeof(ca));

    pending_new = new_m;
    snprintf(pending_desc, sizeof(pending_desc), "%s", source_desc);

    ui_show_merge_process(mnemonic_words(current), ca_hex, na_hex, ma_hex, mnemonic_words(preview),
                          on_merge_done);

    mnemonic_discard(preview);
    // Wipe the hex renderings after use
    secure_memzero(ca_hex, sizeof(ca_hex));
    secure_memzero(na_hex, sizeof(na_hex));
    secure_memzero(ma_hex, sizeof(ma_hex));
}

static void on_we_cancel(void) {
    ui_word_entry_discard(we_handle);
    we_handle = NULL;
    ui_show_source(on_generate, on_enter_manual, on_other_source, on_show_state, on_finish,
                   current != NULL);
}

static void on_enter_manual(void) {
    we_handle = ui_word_entry_begin(word_count, on_we_complete, on_we_cancel);
}

static void on_other_source(void) {
    ui_show_other_source(on_camera_image, on_scan_qr, on_dice_rolls, on_coin_flips, on_touch_screen,
                         go_source);
}

/* -- Camera image source --------------------------------------------- */
static hal_camera_t*      camera = NULL; /* open streaming session */
static hal_camera_frame_t camera_frame;  /* latest captured frame (owned) */
static uint8_t*           camera_rgb565; /* RGB565 preview buffer (owned, reused) */
static uint32_t           camera_w = 0, camera_h = 0;
static lv_timer_t*        camera_timer = NULL; /* live feed timer */

static void rgb565_to_gray(const uint8_t* rgb565, uint32_t w, uint32_t h, uint8_t* gray);

/* Continuous QR scanning: the live feed auto-decodes and dispatches payloads.
 * The callback returns true when the payload belongs to the screen being
 * scanned (or is a usable part of one), which is how a file holding an
 * unrelated QR code is told apart from one that is simply being waited on. */
typedef bool (*qr_payload_cb_t)(qr_source_t source, const uint8_t* payload, size_t plen);
static qr_payload_cb_t qr_scan_cb       = NULL;
static unsigned        qr_scan_tick     = 0;
static uint8_t*        qr_scan_last     = NULL; /* last decoded payload (dedup) */
static size_t          qr_scan_last_len = 0;
static uint8_t*        qr_gray_buf      = NULL; /* reusable grayscale buffer */
static size_t          qr_gray_len      = 0;
static uint8_t*        qr_payload_buf   = NULL; /* reusable decode buffer */

/* The scan screen that is running, so an error message can bring it back. */
static const char* qr_scan_title  = NULL;
static ui_cb_t     qr_scan_cancel = NULL;
static bool        qr_scan_paused = false; /* an error message owns the screen */

static void qr_scan_stop(void) {
    qr_scan_cb     = NULL;
    qr_scan_tick   = 0;
    qr_scan_title  = NULL;
    qr_scan_cancel = NULL;
    qr_scan_paused = false;
    if (qr_scan_last) {
        free(qr_scan_last);
        qr_scan_last     = NULL;
        qr_scan_last_len = 0;
    }
    if (qr_gray_buf) {
        free(qr_gray_buf);
        qr_gray_buf = NULL;
        qr_gray_len = 0;
    }
    if (qr_payload_buf) {
        free(qr_payload_buf);
        qr_payload_buf = NULL;
    }
}

static inline uint8_t clip8(int v) { return (uint8_t)(v < 0 ? 0 : (v > 255 ? 255 : v)); }

static uint16_t yuv_to_rgb565(int y, int u, int v) {
    int c = y - 16;
    int d = u - 128;
    int e = v - 128;
    int r = (298 * c + 409 * e + 128) >> 8;
    int g = (298 * c - 100 * d - 208 * e + 128) >> 8;
    int b = (298 * c + 516 * d + 128) >> 8;
    return (uint16_t)(((clip8(r) >> 3) << 11) | ((clip8(g) >> 2) << 5) | (clip8(b) >> 3));
}

static void camera_release(void) {
    if (camera_rgb565) {
        secure_memzero(camera_rgb565, (size_t)camera_w * camera_h * 2);
        free(camera_rgb565);
        camera_rgb565 = NULL;
    }
    hal_camera_frame_free(&camera_frame);
    camera_w = camera_h = 0;
}

static void camera_frame_to_rgb565(const hal_camera_frame_t* f, uint8_t* rgb) {
    ASSERT_OR_DIE(f && f->data && f->width > 0 && f->height > 0, "invalid camera frame");
    ASSERT_OR_DIE(rgb, "null camera preview buffer");

    uint32_t bpp; // bytes per pixel
    switch (f->pixfmt) {
    case HAL_CAMERA_FMT_GRAY8:
        bpp = 1;
        break;
    case HAL_CAMERA_FMT_YUYV:
    case HAL_CAMERA_FMT_RGB565:
        bpp = 2;
        break;
    default:
        bpp = 0;
        break;
    }

    ASSERT_OR_DIE(bpp != 0, "Unsupported camera pixel format.");
    if (f->size < (size_t)f->width * (size_t)f->height * bpp) {
        FATAL("camera frame too small for declared dimensions");
    }

    uint16_t* dst    = (uint16_t*)rgb;
    uint32_t  stride = f->bytes_per_line ? f->bytes_per_line : f->width * bpp;
    if (stride < f->width * bpp) {
        FATAL("camera frame stride is smaller than the image width");
    }
    if ((size_t)f->height > 0 && (size_t)stride > f->size / (size_t)f->height) {
        FATAL("camera frame stride exceeds the supplied payload size");
    }

    switch (f->pixfmt) {
    case HAL_CAMERA_FMT_RGB565:
        for (uint32_t y = 0; y < f->height; y++) {
            memcpy(dst + (size_t)y * f->width, f->data + (size_t)y * stride, f->width * 2);
        }
        break;
    case HAL_CAMERA_FMT_GRAY8:
        for (uint32_t y = 0; y < f->height; y++) {
            const uint8_t* row = f->data + (size_t)y * stride;
            for (uint32_t x = 0; x < f->width; x++) {
                dst[(size_t)y * f->width + x] = yuv_to_rgb565(row[x], 128, 128);
            }
        }
        break;
    case HAL_CAMERA_FMT_YUYV:
        for (uint32_t y = 0; y < f->height; y++) {
            const uint8_t* row = f->data + (size_t)y * stride;
            for (uint32_t x = 0; x + 1 < f->width; x += 2) {
                uint8_t y0                        = row[x * 2 + 0];
                uint8_t u                         = row[x * 2 + 1];
                uint8_t y1                        = row[x * 2 + 2];
                uint8_t v                         = row[x * 2 + 3];
                dst[(size_t)y * f->width + x]     = yuv_to_rgb565(y0, u, v);
                dst[(size_t)y * f->width + x + 1] = yuv_to_rgb565(y1, u, v);
            }
        }
        break;
    case HAL_CAMERA_FMT_JPEG:
    case HAL_CAMERA_FMT_UNKNOWN:
    default:
        FATAL("Unsupported camera pixel format.");
        break;
    }
}

static const char* camera_pixfmt_name(hal_camera_pixfmt_t f) {
    switch (f) {
    case HAL_CAMERA_FMT_GRAY8:
        return "GRAY8";
    case HAL_CAMERA_FMT_YUYV:
        return "YUYV";
    case HAL_CAMERA_FMT_RGB565:
        return "RGB565";
    case HAL_CAMERA_FMT_JPEG:
        return "JPEG";
    default:
        return "UNKNOWN";
    }
}

/* Hand a decoded payload to the active scan callback.  The camera sees the same
 * QR code in every frame, so a repeat of the last payload is dropped - a file
 * playing an animation repeats frames the same way.  Returns whether the
 * payload belonged to the screen being scanned. */
static bool qr_scan_deliver(qr_source_t source, const uint8_t* payload, size_t plen) {
    bool dup = qr_scan_last && qr_scan_last_len == plen && memcmp(qr_scan_last, payload, plen) == 0;
    if (dup) return true; /* already handed over; not worth reporting twice */

    free(qr_scan_last);
    qr_scan_last = malloc(plen ? plen : 1);
    ASSERT_OR_DIE(qr_scan_last, "out of memory");
    memcpy(qr_scan_last, payload, plen);
    qr_scan_last_len = plen;

    /* The callback may well stop the scan (and with it this buffer), so nothing
     * here is touched after it. */
    return qr_scan_cb(source, payload, plen);
}

// Pixels for the preview and decoder. Reuse the HAL buffer when it is already
// native-endian RGB565; converting copies 600 KB per VGA frame for nothing.
static const uint8_t* camera_frame_pixels(void) {
    if (camera_frame.pixfmt == HAL_CAMERA_FMT_RGB565 &&
        (size_t)camera_frame.bytes_per_line == (size_t)camera_w * 2u) {
        return camera_frame.data;
    }

    if (!camera_rgb565) {
        camera_rgb565 = calloc((size_t)camera_w * camera_h, 2);
        ASSERT_OR_DIE(camera_rgb565, "out of memory for camera preview");
    }
    camera_frame_to_rgb565(&camera_frame, camera_rgb565);
    return camera_rgb565;
}

static void camera_feed_tick(lv_timer_t* t) {
    (void)t;

    /* An error message owns the screen for a moment: the widgets this feed
     * draws into went with the screen it replaced. */
    if (qr_scan_paused) return;

    /* An image file picked while a scan is running arrives through this timer
     * too (only the browser defers the pick, the desktop decodes it in place). */
    qr_scan_poll_file();

    hal_camera_frame_t next;
    memset(&next, 0, sizeof(next));
    const uint32_t t_grab = lv_tick_get();
    if (!hal_camera_grab(camera, &next)) {
        return; /* keep showing the previous frame */
    }

    // Release is timed separately: it zeroes 600 KB before freeing, which is
    // measurable at VGA.
    const uint32_t t_release = lv_tick_get();
    hal_camera_frame_free(&camera_frame);
    camera_frame = next;

    if (camera_frame.width != camera_w || camera_frame.height != camera_h) {
        /* dimensions changed - drop the stale preview buffer */
        if (camera_rgb565) {
            secure_memzero(camera_rgb565, (size_t)camera_w * camera_h * 2);
            free(camera_rgb565);
            camera_rgb565 = NULL;
        }
        camera_w = camera_frame.width;
        camera_h = camera_frame.height;
    }

    const uint32_t t_preview = lv_tick_get();
    const uint8_t* pixels    = camera_frame_pixels();
    ui_camera_feed_update(pixels, camera_w, camera_h);

    const uint32_t t_decode = lv_tick_get();
    if (qr_scan_cb && (++qr_scan_tick % 3u) == 0) {
        /* Throttled continuous decode: scan every 3rd frame (~360 ms). */
        size_t need = (size_t)camera_w * camera_h;
        if (!qr_gray_buf || qr_gray_len < need) {
            free(qr_gray_buf);
            qr_gray_buf = malloc(need);
            ASSERT_OR_DIE(qr_gray_buf, "out of memory");
            qr_gray_len = need;
        }
        if (!qr_payload_buf) {
            qr_payload_buf = malloc(TXINSPECT_MAX_PAYLOAD);
            ASSERT_OR_DIE(qr_payload_buf, "out of memory");
        }

        rgb565_to_gray(pixels, camera_w, camera_h, qr_gray_buf);
        size_t plen = 0;
        if (qr_decode(qr_gray_buf, camera_w, camera_h, qr_payload_buf, TXINSPECT_MAX_PAYLOAD,
                      &plen)) {
            /* A frame that is not for this screen is passed over silently: the
             * next one arrives in a moment. */
            (void)qr_scan_deliver(QR_SOURCE_CAMERA, qr_payload_buf, plen);
        }
    }
    const uint32_t t_end = lv_tick_get();

    // Decode runs every 3rd frame; the per-stage times show where a slow frame
    // goes.
    LOG_INFO("camera frame: %ux%u pixfmt=%s stride=%u size=%zu | grab %ums release %ums "
             "preview %ums decode %ums total %ums",
             (unsigned)camera_frame.width, (unsigned)camera_frame.height,
             camera_pixfmt_name(camera_frame.pixfmt), (unsigned)camera_frame.bytes_per_line,
             camera_frame.size, (unsigned)(t_release - t_grab), (unsigned)(t_preview - t_release),
             (unsigned)(t_decode - t_preview), (unsigned)(t_end - t_decode),
             (unsigned)(t_end - t_grab));
}

static void camera_feed_stop(void) {
    /* A picked file may still be playing frames into the scan. */
    hal_file_image_reset();
    qr_scan_stop();
    if (camera_timer) {
        lv_timer_delete(camera_timer);
        camera_timer = NULL;
    }
    if (camera) {
        hal_camera_close(camera);
        camera = NULL;
    }
    camera_release();
}

static void on_camera_image(void) {
    if (!hal_camera_available()) {
        FATAL("Camera not available.");
    }
    camera = hal_camera_open();
    ASSERT_OR_DIE(camera, "Failed to open camera.");
    ui_show_camera_feed(on_camera_use, on_camera_cancel);
    camera_timer = lv_timer_create(camera_feed_tick, 120, NULL);
}

static void on_camera_cancel(void) {
    camera_feed_stop();
    ui_show_other_source(on_camera_image, on_scan_qr, on_dice_rolls, on_coin_flips, on_touch_screen,
                         go_source);
}

static void on_camera_use(void) {
    /* Stop the feed and close the camera; the last grabbed frame stays valid. */
    if (camera_timer) {
        lv_timer_delete(camera_timer);
        camera_timer = NULL;
    }
    if (camera) {
        hal_camera_close(camera);
        camera = NULL;
    }

    if (!camera_frame.data) {
        FATAL("No camera image captured yet.");
    }

    /* Derive entropy (16 or 32 bytes) from the raw camera bytes. */
    size_t  elen = (word_count == 24) ? 32 : 16;
    uint8_t entropy[32];
    sha256_expand(camera_frame.data, camera_frame.size, entropy, elen);

    mnemonic_t* m = mnemonic_from_entropy(entropy, elen);
    secure_memzero(entropy, sizeof(entropy));

    camera_release();

    char desc[48];
    int  res = snprintf(desc, sizeof(desc), "camera image %u-word", word_count);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(desc), "description string too long");
    merge_or_reject(m, MNEMONIC_TYPE_GENERATED, desc);
}

static void rgb565_to_gray(const uint8_t* rgb565, uint32_t w, uint32_t h, uint8_t* gray) {
    const uint16_t* px = (const uint16_t*)rgb565;
    uint32_t        n  = w * h;
    for (uint32_t i = 0; i < n; i++) {
        uint16_t c = px[i];
        uint32_t r = ((c >> 11) & 0x1F) * 255 / 31;
        uint32_t g = ((c >> 5) & 0x3F) * 255 / 63;
        uint32_t b = (c & 0x1F) * 255 / 31;
        gray[i]    = (uint8_t)((r * 299 + g * 587 + b * 114) / 1000);
    }
}

/* -- Scan screen errors ------------------------------------------------ */
/* How long an error stays on screen before scanning carries on. */
#define QR_SCAN_ERROR_MS 500u

/* Show the scan screen of the running scan. */
static void qr_scan_screen_show(void) {
    ui_show_qr_scan_auto(qr_scan_cancel, qr_scan_title, on_scan_file);

    /* The camera keeps streaming while a message is up, so the new screen
     * starts from the last frame instead of an empty box. */
    if (camera_w && camera_h && camera_frame.data) {
        ui_camera_feed_update(camera_frame_pixels(), camera_w, camera_h);
    }
}

/*
 * A payload the screen cannot use - or a file holding no readable QR code at
 * all - is worth more than a line of small print: the message takes over the
 * screen for a moment and the scan then carries on where it left off.  The
 * camera session, the multi-part UR decoder and the feed timer all stay as they
 * are; the timer only skips its work while the message is up, because the
 * widgets it draws into belong to the screen that was replaced.
 */
static void qr_scan_error(const char* msg) {
    ASSERT_OR_DIE(msg, "null message");
    ASSERT_OR_DIE(qr_scan_cb, "no active scan");

    /* Whatever came out of the file is not for this screen: drop the pick, so
     * a looping animation does not raise the same message over and over. */
    hal_file_image_reset();

    qr_scan_paused = true;
    ui_show_msg(msg);
    ui_delay_ms(QR_SCAN_ERROR_MS);
    qr_scan_paused = false;

    if (!qr_scan_cb) return; /* the scan ended while the message was up */
    qr_scan_screen_show();
}

static void on_scan_qr(void) {
    if (!hal_camera_available()) {
        FATAL("Camera not available.");
    }
    camera = hal_camera_open();
    ASSERT_OR_DIE(camera, "Failed to open camera.");
    qr_scan_cb     = on_seedqr_payload;
    qr_scan_title  = "Scan SeedQR";
    qr_scan_cancel = on_qr_scan_cancel;
    qr_scan_screen_show();
    camera_timer = lv_timer_create(camera_feed_tick, 120, NULL);
}

static void on_qr_scan_cancel(void) {
    camera_feed_stop();
    ui_show_other_source(on_camera_image, on_scan_qr, on_dice_rolls, on_coin_flips, on_touch_screen,
                         go_source);
}

static bool on_seedqr_payload(qr_source_t source, const uint8_t* payload, size_t plen) {
    mnemonic_t* m = NULL;

    if (plen == SEEDQR_STANDARD_12_DIGITS || plen == SEEDQR_STANDARD_24_DIGITS) {
        char digits[SEEDQR_STANDARD_24_DIGITS + 1];
        memcpy(digits, payload, plen);
        digits[plen] = '\0';
        m            = seedqr_standard_decode(digits);
        secure_memzero(digits, sizeof(digits));
    } else if (plen == 16 || plen == 32) {
        m = seedqr_compact_decode(payload, plen);
    }

    if (!m) {
        /* From the camera this means "keep looking"; a picked file has no next
         * frame to look at, so say what was wrong with it. */
        if (source == QR_SOURCE_FILE) qr_scan_error("Not a SeedQR code");
        return false; /* not a SeedQR */
    }

    camera_feed_stop();

    unsigned wc = (mnemonic_entropy_size(m) == 32) ? 24 : 12;
    char     desc[48];
    int      res = snprintf(desc, sizeof(desc), "scanned %u-word SeedQR", wc);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(desc), "description string too long");
    merge_or_reject(m, MNEMONIC_TYPE_ENTERED, desc);
    return true;
}

/* -- Scanning a QR code from an image file ---------------------------- */
/*
 * The desktop and browser builds can load a QR code from an image file (a
 * screenshot exported by another wallet, a photo of a printed SeedQR, ...)
 * instead of pointing the camera at it.  The platform decodes the picked file
 * and hands back grayscale frames, which then take the very same
 * decode/dispatch path as a camera frame.  An animated GIF arrives one frame at
 * a time, so an animated multi-part UR collects its parts just as it would from
 * the camera.
 */
static void on_scan_file(void) {
    if (!qr_scan_cb) return;

    /* Drop the previous message: the picker is about to report something. */
    ui_qr_scan_progress(0, 0);
    hal_file_image_pick();
}

static void qr_scan_poll_file(void) {
    if (!qr_scan_cb) return; /* only the scan screens offer a file pick */

    hal_camera_frame_t frame;
    memset(&frame, 0, sizeof(frame));

    switch (hal_file_image_poll(&frame)) {
    case HAL_FILE_IMAGE_NONE:
        return; /* nothing picked yet, or the picker was cancelled */
    case HAL_FILE_IMAGE_FAILED:
        qr_scan_error("Could not read an image file");
        return;
    case HAL_FILE_IMAGE_READY:
        break;
    }

    if (frame.pixfmt != HAL_CAMERA_FMT_GRAY8 || !frame.data) {
        hal_camera_frame_free(&frame);
        qr_scan_error("Could not read an image file");
        return;
    }

    if (!qr_payload_buf) {
        qr_payload_buf = malloc(TXINSPECT_MAX_PAYLOAD);
        ASSERT_OR_DIE(qr_payload_buf, "out of memory");
    }

    size_t plen = 0;
    if (qr_decode(frame.data, frame.width, frame.height, qr_payload_buf, TXINSPECT_MAX_PAYLOAD,
                  &plen)) {
        LOG_INFO("QR image file decoded: %ux%u", (unsigned)frame.width, (unsigned)frame.height);
        /* A payload this screen cannot use is reported by its own callback:
         * unlike a camera frame, there is no next frame to wait for. */
        (void)qr_scan_deliver(QR_SOURCE_FILE, qr_payload_buf, plen);
    } else {
        qr_scan_error("No QR code found in that image");
    }

    hal_camera_frame_free(&frame);
}

/* -- Inspect transaction/PSBT ---------------------------------------- */
static tx_inspect_t*      inspected   = NULL;
static ur_psbt_decoder_t* ur_decoder  = NULL;
static descriptor_t*      wallet_desc = NULL;

/* Network the scanned payload is interpreted as.  A transaction does not say
 * which network it belongs to: the same output script is spendable on mainnet
 * and on testnet alike, and only the address encoding differs.  The user picks
 * it before scanning, and it decides how addresses are rendered.  The order
 * must match tx_inspect_network_t. */
static const char* const TX_NETWORKS[] = {"Mainnet", "Testnet", "Signet", "Regtest"};
#define TX_NETWORK_COUNT (sizeof(TX_NETWORKS) / sizeof(TX_NETWORKS[0]))

static tx_inspect_network_t tx_network = TX_INSPECT_NETWORK_MAINNET;

static void ur_decoder_reset(void) {
    ur_psbt_decoder_free(ur_decoder);
    ur_decoder = ur_psbt_decoder_new();
}

/* Descriptor UR decoder: lives only while the descriptor QR is being scanned
 * (it accumulates the animated multi-part fragments of a large descriptor). */
static ur_descriptor_decoder_t* desc_decoder = NULL;

static void desc_decoder_reset(void) {
    ur_descriptor_decoder_free(desc_decoder);
    desc_decoder = ur_descriptor_decoder_new();
}

static void desc_decoder_stop(void) {
    ur_descriptor_decoder_free(desc_decoder);
    desc_decoder = NULL;
}

/* Classify an output address against the scanned wallet descriptor (if any). */
static tx_output_kind_t classify_output(void* ctx, size_t out_index, const char* address) {
    (void)out_index;
    descriptor_t* d = ctx;
    if (!d) return TX_OUTPUT_NONE;
    switch (descriptor_classify(d, address)) {
    case DESCRIPTOR_MATCH_CHANGE:
        return TX_OUTPUT_CHANGE;
    case DESCRIPTOR_MATCH_RECEIVE:
        return TX_OUTPUT_RECEIVE;
    case DESCRIPTOR_MATCH_NONE:
        return TX_OUTPUT_NONE;
    }
    return TX_OUTPUT_NONE;
}

static void show_inspected_tx(void) {
    /* The network is chosen before scanning; apply it now so addresses are
     * rendered for it. */
    tx_inspect_set_network(inspected, tx_network);

    char* body = malloc(TXINSPECT_RENDER_MAX);
    ASSERT_OR_DIE(body, "out of memory");
    tx_inspect_render_ex(inspected, body, TXINSPECT_RENDER_MAX, classify_output, wallet_desc);

    char* warning = malloc(TXINSPECT_WARNING_MAX);
    ASSERT_OR_DIE(warning, "out of memory");
    bool warn = tx_inspect_nonce_warning(inspected, warning, TXINSPECT_WARNING_MAX);

    /* Repeat the network in the title: the address lines themselves give no
     * hint of which network they were encoded for. */
    char title[64];
    int  res = snprintf(title, sizeof(title), "%s (%s)", tx_inspect_kind_name(inspected),
                       tx_inspect_network_name(tx_inspect_network(inspected)));
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(title), "title too long");

    ui_show_tx_inspect(title, body, warn ? warning : NULL, on_inspect_tx_done);

    // The UI has copied the strings it needs; scrub and release the buffers.
    secure_memzero(warning, TXINSPECT_WARNING_MAX);
    free(warning);
    secure_memzero(body, TXINSPECT_RENDER_MAX);
    free(body);
}

/* Ask whether to scan a wallet descriptor first, so change outputs can be
 * flagged on the transaction summary. */
static void ask_descriptor_or_scan(void) {
    ui_show_confirm("Scan Transaction/PSBT",
                    "Scan a wallet descriptor first?\n\nA descriptor lets you "
                    "verify which outputs are your change.",
                    "Scan descriptor", "Just scan", on_scan_descriptor, on_skip_descriptor);
}

static void on_network_chosen(uint8_t index) {
    tx_network =
        index < TX_NETWORK_COUNT ? (tx_inspect_network_t)index : TX_INSPECT_NETWORK_MAINNET;
    ask_descriptor_or_scan();
}

static void on_inspect_tx(lv_event_t* e) {
    (void)e;
    if (!hal_camera_available()) {
        FATAL("Camera not available.");
    }
    ui_show_choice("Transaction Network", "Which network is this transaction for?", TX_NETWORKS,
                   TX_NETWORK_COUNT, on_network_chosen, show_main_screen);
}

static void on_skip_descriptor(void) { start_tx_scan(); }

static void on_scan_descriptor(void) {
    if (!hal_camera_available()) {
        FATAL("Camera not available.");
    }
    camera = hal_camera_open();
    ASSERT_OR_DIE(camera, "Failed to open camera.");
    qr_scan_cb     = on_descriptor_payload;
    qr_scan_title  = "Scan Wallet Descriptor";
    qr_scan_cancel = on_descriptor_cancel;
    desc_decoder_reset();
    qr_scan_screen_show();
    camera_timer = lv_timer_create(camera_feed_tick, 120, NULL);
}

static void on_descriptor_cancel(void) {
    camera_feed_stop();
    desc_decoder_stop();
    on_inspect_tx(NULL);
}

/* Show what was scanned before the descriptor is used: the scan only proves
 * the text parses, not that it is the wallet the user meant to load. */
static void show_descriptor_overview(void) {
    char* body = malloc(DESCRIPTOR_OVERVIEW_MAX);
    ASSERT_OR_DIE(body, "out of memory");

    size_t len = descriptor_overview(wallet_desc, body, DESCRIPTOR_OVERVIEW_MAX);
    if (len == 0) {
        /* Nothing to review (should not happen for a parsed descriptor):
         * carry on rather than block the scan. */
        free(body);
        start_tx_scan();
        return;
    }

    ui_show_descriptor_overview("Wallet Descriptor", body, on_descriptor_overview_continue,
                                on_descriptor_overview_cancel);

    // The UI has copied the text it needs; scrub and release the buffer.
    secure_memzero(body, DESCRIPTOR_OVERVIEW_MAX);
    free(body);
}

static void on_descriptor_overview_continue(void) { start_tx_scan(); }

static void on_descriptor_overview_cancel(void) {
    descriptor_free(wallet_desc);
    wallet_desc = NULL;
    on_inspect_tx(NULL);
}

static bool descriptor_accept(descriptor_status_t st, descriptor_t* d, qr_source_t source) {
    if (!d) {
        if (st == DESCRIPTOR_ERR_TOO_LONG) {
            camera_feed_stop();
            desc_decoder_stop();
            ui_show_msg("Descriptor is too long to scan.");
            ui_delay_ms(2000);
            on_inspect_tx(NULL);
            return true;
        }

        if (source == QR_SOURCE_FILE) qr_scan_error("Not a wallet descriptor");
        return false; /* not a descriptor (or an unsupported one) */
    }

    camera_feed_stop();
    desc_decoder_stop();
    descriptor_free(wallet_desc);
    wallet_desc = d;
    show_descriptor_overview();
    return true;
}

static bool on_descriptor_payload(qr_source_t source, const uint8_t* payload, size_t plen) {
    /* UR-encoded descriptor: single-part or animated multi-part
     * ur:output-descriptor / ur:crypto-output. */
    if (plen >= 3 && (payload[0] == 'u' || payload[0] == 'U') &&
        (payload[1] == 'r' || payload[1] == 'R') && payload[2] == ':') {
        if (!desc_decoder) desc_decoder = ur_descriptor_decoder_new();

        char* text = NULL;
        int   r    = ur_descriptor_decoder_receive(desc_decoder, (const char*)payload, plen, &text);
        if (r == 0) { /* a part; the rest of the descriptor is still to come */
            ui_qr_scan_progress(ur_descriptor_decoder_received(desc_decoder),
                                ur_descriptor_decoder_expected(desc_decoder));
            return true;
        }
        if (r == 1) {
            descriptor_status_t st = DESCRIPTOR_ERR_NOT_DESC;
            descriptor_t*       d  = descriptor_parse((const uint8_t*)text, strlen(text), &st);
            secure_memzero(text, strlen(text));
            free(text);
            return descriptor_accept(st, d, source);
        }

        if (source == QR_SOURCE_FILE) qr_scan_error("Not a wallet descriptor");
        return false; /* not a descriptor UR part */
    }

    descriptor_status_t st = DESCRIPTOR_ERR_NOT_DESC;
    descriptor_t*       d  = descriptor_parse(payload, plen, &st);
    return descriptor_accept(st, d, source);
}

static void start_tx_scan(void) {
    if (!hal_camera_available()) {
        FATAL("Camera not available.");
    }
    ur_decoder_reset();
    camera = hal_camera_open();
    ASSERT_OR_DIE(camera, "Failed to open camera.");
    qr_scan_cb     = on_tx_payload;
    qr_scan_title  = "Scan Transaction/PSBT";
    qr_scan_cancel = on_inspect_tx_cancel;
    qr_scan_screen_show();
    camera_timer = lv_timer_create(camera_feed_tick, 120, NULL);
}

static void on_inspect_tx_cancel(void) {
    camera_feed_stop();
    ur_psbt_decoder_free(ur_decoder);
    ur_decoder = NULL;
    desc_decoder_stop();
    descriptor_free(wallet_desc);
    wallet_desc = NULL;
    show_main_screen();
}

static void on_inspect_tx_done(void) {
    tx_inspect_free(inspected);
    inspected = NULL;
    ur_psbt_decoder_free(ur_decoder);
    ur_decoder = NULL;
    desc_decoder_stop();
    descriptor_free(wallet_desc);
    wallet_desc = NULL;
    show_main_screen();
}

static bool on_tx_payload(qr_source_t source, const uint8_t* payload, size_t plen) {
    /* UR-encoded PSBT: single-part or animated multi-part (fountain). */
    if (plen >= 3 && (payload[0] == 'u' || payload[0] == 'U') &&
        (payload[1] == 'r' || payload[1] == 'R') && payload[2] == ':') {
        if (!ur_decoder) ur_decoder = ur_psbt_decoder_new();

        uint8_t* psbt     = NULL;
        size_t   psbt_len = 0;
        int r = ur_psbt_decoder_receive(ur_decoder, (const char*)payload, plen, &psbt, &psbt_len);

        if (r == 1) {
            inspected = tx_inspect_parse(psbt, psbt_len);
            secure_memzero(psbt, psbt_len);
            free(psbt);
            camera_feed_stop();
            if (!inspected) {
                ui_show_msg("Not a valid PSBT");
                ui_delay_ms(1500);
                on_inspect_tx_cancel();
                return true; /* the user was told why */
            }
            show_inspected_tx();
            return true;
        }
        if (r == 0) { /* a part; the rest of the PSBT is still to come */
            ui_qr_scan_progress(ur_psbt_decoder_received(ur_decoder),
                                ur_psbt_decoder_expected(ur_decoder));
            return true;
        }

        /* r == -1: not a valid PSBT UR part. */
        if (source == QR_SOURCE_FILE) qr_scan_error("Not a transaction or PSBT");
        return false;
    }

    /* Raw transaction / PSBT (hex or base64). */
    inspected = tx_inspect_parse(payload, plen);
    if (!inspected) {
        if (source == QR_SOURCE_FILE) qr_scan_error("Not a transaction or PSBT");
        return false;
    }

    camera_feed_stop();
    show_inspected_tx();
    return true;
}

static void on_export_seedqr(void) {
    if (!current) {
        ui_go_main();
        return;
    }

    uint8_t entropy[32];
    size_t  n = seedqr_compact_encode(current, entropy, sizeof(entropy));
    ASSERT_OR_DIE(n == 16 || n == 32, "unexpected entropy length");

    if (!qr_encode(entropy, n, QR_MODE_BYTE, &exported_qr)) {
        secure_memzero(entropy, sizeof(entropy));
        FATAL("SeedQR encode failed");
    }
    secure_memzero(entropy, sizeof(entropy));

    ui_show_seedqr(exported_qr.cells, exported_qr.size, on_export_done);
}

static void on_export_done(void) {
    ui_seedqr_cleanup();
    qr_grid_free(&exported_qr);
    ui_show_mnemonic(mnemonic_words(current), MNEMONIC_TYPE_FINAL, on_finish_done,
                     on_export_seedqr);
}

/* -- Dice roll entropy source ---------------------------------------- */
static dice_entropy_t* dice = NULL;

static void on_dice_roll(uint8_t value) {
    ASSERT_OR_DIE(dice, "no active dice session");
    dice_entropy_add_roll(dice, value);

    if (!dice_entropy_ready(dice)) {
        char status[64];
        int  res = snprintf(status, sizeof(status), "Entropy: %u / %u bits (%u rolls)",
                           (unsigned)dice_entropy_bits(dice), (unsigned)dice_entropy_needed(dice),
                           dice_entropy_rolls(dice));
        ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(status), "status string too long");
        ui_dice_set_status(status);
        return;
    }

    unsigned rolls = dice_entropy_rolls(dice);
    unsigned sides = dice_entropy_sides(dice);
    uint8_t  entropy[32];
    size_t   elen = dice_entropy_derive(dice, entropy, sizeof(entropy));
    ASSERT_OR_DIE(elen == 16 || elen == 32, "unexpected entropy length");
    mnemonic_t* m = mnemonic_from_entropy(entropy, elen);
    secure_memzero(entropy, sizeof(entropy));
    dice_entropy_discard(dice);
    dice = NULL;

    char desc[48];
    int res = snprintf(desc, sizeof(desc), "d%u dice %u-word (%u rolls)", sides, word_count, rolls);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(desc), "description string too long");
    merge_or_reject(m, MNEMONIC_TYPE_GENERATED, desc);
}

static void on_dice_cancel(void) {
    if (dice) {
        dice_entropy_discard(dice);
        dice = NULL;
    }
    ui_show_other_source(on_camera_image, on_scan_qr, on_dice_rolls, on_coin_flips, on_touch_screen,
                         go_source);
}

static void on_dice_sides_chosen(uint8_t sides) {
    ASSERT_OR_DIE(!dice, "dice session already active");
    dice = dice_entropy_begin(word_count, sides);
    ui_show_dice(sides, on_dice_roll, on_dice_cancel);
}

static void on_dice_sides_cancel(void) {
    ui_show_other_source(on_camera_image, on_scan_qr, on_dice_rolls, on_coin_flips, on_touch_screen,
                         go_source);
}

static void on_dice_rolls(void) { ui_show_dice_sides(on_dice_sides_chosen, on_dice_sides_cancel); }

/* -- Coin flip entropy source ---------------------------------------- */
static coin_entropy_t* coin = NULL;

static void on_coin_flip(uint8_t value) {
    ASSERT_OR_DIE(coin, "no active coin session");
    coin_entropy_add_flip(coin, value);

    if (!coin_entropy_ready(coin)) {
        char status[64];
        int  res = snprintf(status, sizeof(status), "Entropy: %u / %u bits (%u flips)",
                           (unsigned)coin_entropy_bits(coin), (unsigned)coin_entropy_needed(coin),
                           coin_entropy_flips(coin));
        ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(status), "status string too long");
        ui_coin_set_status(status);
        return;
    }

    unsigned flips = coin_entropy_flips(coin);
    uint8_t  entropy[32];
    size_t   elen = coin_entropy_derive(coin, entropy, sizeof(entropy));
    ASSERT_OR_DIE(elen == 16 || elen == 32, "unexpected entropy length");
    mnemonic_t* m = mnemonic_from_entropy(entropy, elen);
    secure_memzero(entropy, sizeof(entropy));
    coin_entropy_discard(coin);
    coin = NULL;

    char desc[48];
    int  res = snprintf(desc, sizeof(desc), "coin flips %u-word (%u flips)", word_count, flips);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(desc), "description string too long");
    merge_or_reject(m, MNEMONIC_TYPE_GENERATED, desc);
}

static void on_coin_cancel(void) {
    if (coin) {
        coin_entropy_discard(coin);
        coin = NULL;
    }
    ui_show_other_source(on_camera_image, on_scan_qr, on_dice_rolls, on_coin_flips, on_touch_screen,
                         go_source);
}

static void on_coin_flips(void) {
    ASSERT_OR_DIE(!coin, "coin session already active");
    coin = coin_entropy_begin(word_count);
    ui_show_coin(on_coin_flip, on_coin_cancel);
}

/* -- Touch screen entropy source -------------------------------------- */
static touch_entropy_t* touch = NULL;

static void on_touch_tap(lv_coord_t x, lv_coord_t y) {
    ASSERT_OR_DIE(touch, "no active touch session");
    touch_entropy_add_tap(touch, x, y);

    if (!touch_entropy_ready(touch)) {
        char status[64];
        int  res =
            snprintf(status, sizeof(status), "Entropy: %u / %u bits",
                     (unsigned)touch_entropy_bits(touch), (unsigned)touch_entropy_needed(touch));
        ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(status), "status string too long");
        ui_touch_screen_set_status(status);
        return;
    }

    unsigned taps = touch_entropy_taps(touch);
    uint8_t  entropy[32];
    size_t   elen = touch_entropy_derive(touch, entropy, sizeof(entropy));
    ASSERT_OR_DIE(elen == 16 || elen == 32, "unexpected entropy length");
    mnemonic_t* m = mnemonic_from_entropy(entropy, elen);
    secure_memzero(entropy, sizeof(entropy));
    touch_entropy_discard(touch);
    touch = NULL;

    char desc[48];
    int  res = snprintf(desc, sizeof(desc), "touch screen %u-word (%u taps)", word_count, taps);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(desc), "description string too long");
    merge_or_reject(m, MNEMONIC_TYPE_GENERATED, desc);
}

static void on_touch_cancel(void) {
    if (touch) {
        touch_entropy_discard(touch);
        touch = NULL;
    }
    go_source();
}

static void on_touch_screen(void) {
    ASSERT_OR_DIE(!touch, "touch session already active");

    lv_display_t* disp  = lv_display_get_default();
    uint32_t      res_x = (uint32_t)lv_display_get_horizontal_resolution(disp);
    uint32_t      res_y = (uint32_t)lv_display_get_vertical_resolution(disp);

    touch = touch_entropy_begin(word_count, res_x, res_y);
    ui_show_touch_screen(on_touch_tap, on_touch_cancel);
}

static void on_we_complete(void) {
    const char* txt = ui_word_entry_result(we_handle);
    char        buf[MNEMONIC_MAX_INPUT_LEN];
    size_t      txt_len = txt ? strlen(txt) : 0;
    if (txt_len >= sizeof(buf)) {
        FATAL("mnemonic input too long");
    }
    memcpy(buf, txt, txt_len);
    buf[txt_len] = '\0';
    // Keep a copy so the error screen can offer to re-enter or auto-fix the
    // last word.
    strncpy(we_entered, buf, sizeof(we_entered) - 1);
    we_entered[sizeof(we_entered) - 1] = '\0';

    ui_word_entry_discard(we_handle);
    we_handle = NULL;

    mnemonic_t* m = mnemonic_from_string(buf);
    secure_memzero(buf, sizeof(buf));
    if (!m) {
        ui_show_mnemonic_error(on_we_error_cancel, on_we_error_retry, on_we_error_choose);
        return;
    }
    int res = snprintf(pending_desc, sizeof(pending_desc), "entered %u-word", word_count);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(pending_desc), "description string too long");

    // Show the completed mnemonic and ask the user to confirm before it is
    // used
    pending_new = m;
    ui_show_mnemonic(mnemonic_words(m), MNEMONIC_TYPE_ENTERED, on_we_ok, NULL);
}

static void on_we_ok(void) {
    ASSERT_OR_DIE(pending_new, "no pending mnemonic");
    mnemonic_t* m = pending_new;
    pending_new   = NULL;

    if (!current) {
        // First source: the entered mnemonic was already shown for approval.
        current = m;
        ui_log_add("started with %s", pending_desc);
        go_source();
        return;
    }
    merge_or_reject(m, MNEMONIC_TYPE_ENTERED, pending_desc);
}

static void on_we_error_cancel(void) { go_source(); }

// Copy the first (word_count - 1) words of `we_entered` into `prefix`.
// Returns false if there is no separator (fewer than two words entered).
static bool we_split_prefix(char* prefix, size_t cap) {
    const char* last = strrchr(we_entered, ' ');
    if (!last) return false;
    size_t len = (size_t)(last - we_entered);
    if (len >= cap) len = cap - 1;
    memcpy(prefix, we_entered, len);
    prefix[len] = '\0';
    return true;
}

static void on_we_error_retry(void) {
    // Re-enter only the last (checksum) word, keeping the first N-1 words.
    char prefix[MNEMONIC_MAX_INPUT_LEN];
    if (!we_split_prefix(prefix, sizeof(prefix)) || word_count == 0) {
        on_enter_manual(); // nothing entered yet; start from scratch
        return;
    }
    we_handle =
        ui_word_entry_resume(word_count, word_count - 1, prefix, on_we_complete, on_we_cancel);
}

static void on_we_error_back(void) {
    ui_show_mnemonic_error(on_we_error_cancel, on_we_error_retry, on_we_error_choose);
}

static void on_we_error_choose(void) {
    static const char* candidates[128];
    char               prefix[MNEMONIC_MAX_INPUT_LEN];
    if (!we_split_prefix(prefix, sizeof(prefix))) {
        on_generate(); // cannot determine a prefix; fall back to generation
        return;
    }
    size_t count = mnemonic_last_word_candidates(we_entered, candidates, 128);
    if (count == 0) {
        on_generate(); // prefix not parseable; fall back to generation
        return;
    }
    ui_show_word_picker("Choose Last Word", candidates, count, on_we_word_selected,
                        on_we_error_back);
}

static void on_we_word_selected(const char* last_word) {
    ASSERT_OR_DIE(last_word && *last_word, "null selected word");
    char full[MNEMONIC_MAX_INPUT_LEN];
    char prefix[MNEMONIC_MAX_INPUT_LEN];
    if (!we_split_prefix(prefix, sizeof(prefix))) {
        FATAL("missing mnemonic prefix for last-word selection");
    }
    int res = snprintf(full, sizeof(full), "%s %s", prefix, last_word);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(full), "mnemonic too long");

    mnemonic_t* m = mnemonic_from_string(full);
    secure_memzero(full, sizeof(full));
    if (!m) {
        FATAL("chosen last word failed validation");
    }
    res = snprintf(pending_desc, sizeof(pending_desc), "entered %u-word (chosen last word)",
                   word_count);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(pending_desc), "description string too long");
    pending_new = m;
    ui_show_mnemonic(mnemonic_words(m), MNEMONIC_TYPE_ENTERED, on_we_ok, NULL);
}

// -- Re-enter source with correct title based on state -----------------
static void go_source(void) {
    ui_show_source(on_generate, on_enter_manual, on_other_source, on_show_state, on_finish,
                   current != NULL);
}

static void go_back_source(void) {
    ui_show_source(on_generate, on_enter_manual, on_other_source, on_show_state, on_finish,
                   current != NULL);
}

/* -- Step: word count chosen ------------------------------------------ */
static void on_12(void) {
    word_count = 12;
    ui_show_source(on_generate, on_enter_manual, on_other_source, on_show_state, on_finish,
                   current != NULL);
}
static void on_24(void) {
    word_count = 24;
    ui_show_source(on_generate, on_enter_manual, on_other_source, on_show_state, on_finish,
                   current != NULL);
}

/* -- State screen ----------------------------------------------------- */
static void on_show_state(void) {
    ui_show_state(go_back_source, current ? mnemonic_words(current) : NULL);
}

static void on_finish_done(void) {
    if (we_handle) {
        ui_word_entry_discard(we_handle);
        we_handle = NULL;
    }
    secure_memzero(we_entered, sizeof(we_entered));
    mnemonic_discard(current);
    current = NULL;
    ui_go_main();
}

static void on_finish(void) {
    if (!current) {
        ui_go_main();
        return;
    }
    ui_show_mnemonic(mnemonic_words(current), MNEMONIC_TYPE_FINAL, on_finish_done,
                     on_export_seedqr);
    ui_log_add("finished");
}

/* -- Entry: "Create Mnemonic Seed" button --------------------------------------- */
static void on_create_mnemonic(lv_event_t* e) {
    (void)e;
    ASSERT_OR_DIE(!current, "current mnemonic should be NULL");
    ASSERT_OR_DIE(!we_handle, "word entry handle should be NULL");
    ui_show_word_count(on_12, on_24);
}

/* -- Test error screen ------------------------------------------------ */
static void on_test_error(lv_event_t* e) {
    (void)e;
    FATAL("This is a test of the fatal error screen.");
}

/* -- Initialization --------------------------------------------------- */
static void show_main_screen(void) {
    ui_show_main(on_create_mnemonic, on_inspect_tx, on_test_error);
}

void app_init(void) {
    lv_display_t* disp = lv_display_get_default();
    lv_theme_t*   th =
        lv_theme_default_init(disp, lv_color_hex(UI_COLOR_MIX_GREEN),
                              lv_color_hex(UI_COLOR_SEED_GREEN), true, &lv_font_montserrat_20);
    lv_disp_set_theme(disp, th);

    mnemonic_init();

    ui_show_splash(show_main_screen);
}
