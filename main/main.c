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
#include "crypto/ur.h"
#include "crypto/ur_descriptor.h"
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
static void on_other_source(void);
static void on_camera_image(void);
static void on_camera_use(void);
static void on_camera_cancel(void);
static void on_scan_qr(void);
static void on_seedqr_payload(const uint8_t* payload, size_t plen);
static void on_qr_scan_cancel(void);
static void on_inspect_tx(lv_event_t* e);
static void on_tx_payload(const uint8_t* payload, size_t plen);
static void on_descriptor_payload(const uint8_t* payload, size_t plen);
static void on_inspect_tx_cancel(void);
static void on_inspect_tx_done(void);
static void on_descriptor_cancel(void);
static void on_scan_descriptor(void);
static void on_skip_descriptor(void);
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

    char ca_hex[65], na_hex[65], ma_hex[65];
    bytes_to_hex(ca, elen, ca_hex, sizeof(ca_hex));
    bytes_to_hex(na, elen, na_hex, sizeof(na_hex));
    bytes_to_hex(ma, elen, ma_hex, sizeof(ma_hex));

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

/* Continuous QR scanning: the live feed auto-decodes and dispatches payloads. */
typedef void (*qr_payload_cb_t)(const uint8_t* payload, size_t plen);
static qr_payload_cb_t qr_scan_cb       = NULL;
static unsigned        qr_scan_tick     = 0;
static uint8_t*        qr_scan_last     = NULL; /* last decoded payload (dedup) */
static size_t          qr_scan_last_len = 0;
static uint8_t*        qr_gray_buf      = NULL; /* reusable grayscale buffer */
static size_t          qr_gray_len      = 0;
static uint8_t*        qr_payload_buf   = NULL; /* reusable decode buffer */

static void qr_scan_stop(void) {
    qr_scan_cb   = NULL;
    qr_scan_tick = 0;
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

static void camera_feed_tick(lv_timer_t* t) {
    (void)t;

    hal_camera_frame_t next;
    memset(&next, 0, sizeof(next));
    if (!hal_camera_grab(camera, &next)) {
        return; /* keep showing the previous frame */
    }

    hal_camera_frame_free(&camera_frame);
    camera_frame = next;

    LOG_INFO("camera frame: %ux%u pixfmt=%s size=%zu bytes_per_line=%u",
             (unsigned)camera_frame.width, (unsigned)camera_frame.height,
             camera_pixfmt_name(camera_frame.pixfmt), camera_frame.size,
             (unsigned)camera_frame.bytes_per_line);

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

    if (!camera_rgb565) {
        camera_rgb565 = calloc((size_t)camera_w * camera_h, 2);
        ASSERT_OR_DIE(camera_rgb565, "out of memory for camera preview");
    }

    camera_frame_to_rgb565(&camera_frame, camera_rgb565);
    ui_camera_feed_update(camera_rgb565, camera_w, camera_h);

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

        rgb565_to_gray(camera_rgb565, camera_w, camera_h, qr_gray_buf);
        size_t plen = 0;
        if (qr_decode(qr_gray_buf, camera_w, camera_h, qr_payload_buf, TXINSPECT_MAX_PAYLOAD,
                      &plen)) {
            bool dup = qr_scan_last && qr_scan_last_len == plen &&
                       memcmp(qr_scan_last, qr_payload_buf, plen) == 0;
            if (!dup) {
                if (qr_scan_last) free(qr_scan_last);
                qr_scan_last = malloc(plen ? plen : 1);
                ASSERT_OR_DIE(qr_scan_last, "out of memory");
                memcpy(qr_scan_last, qr_payload_buf, plen);
                qr_scan_last_len = plen;
                qr_scan_cb(qr_payload_buf, plen);
            }
        }
    }
}

static void camera_feed_stop(void) {
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

static void on_scan_qr(void) {
    if (!hal_camera_available()) {
        FATAL("Camera not available.");
    }
    camera = hal_camera_open();
    ASSERT_OR_DIE(camera, "Failed to open camera.");
    qr_scan_cb = on_seedqr_payload;
    ui_show_qr_scan_auto(on_qr_scan_cancel, "Scan SeedQR");
    camera_timer = lv_timer_create(camera_feed_tick, 120, NULL);
}

static void on_qr_scan_cancel(void) {
    camera_feed_stop();
    ui_show_other_source(on_camera_image, on_scan_qr, on_dice_rolls, on_coin_flips, on_touch_screen,
                         go_source);
}

static void on_seedqr_payload(const uint8_t* payload, size_t plen) {
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

    if (!m) return; /* not a SeedQR; keep scanning */

    camera_feed_stop();

    unsigned wc = (mnemonic_entropy_size(m) == 32) ? 24 : 12;
    char     desc[48];
    int      res = snprintf(desc, sizeof(desc), "scanned %u-word SeedQR", wc);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(desc), "description string too long");
    merge_or_reject(m, MNEMONIC_TYPE_ENTERED, desc);
}

/* -- Inspect transaction/PSBT ---------------------------------------- */
static tx_inspect_t*      inspected   = NULL;
static ur_psbt_decoder_t* ur_decoder  = NULL;
static descriptor_t*      wallet_desc = NULL;

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
    char* body = malloc(TXINSPECT_RENDER_MAX);
    ASSERT_OR_DIE(body, "out of memory");
    tx_inspect_render_ex(inspected, body, TXINSPECT_RENDER_MAX, classify_output, wallet_desc);

    char* warning = malloc(TXINSPECT_WARNING_MAX);
    ASSERT_OR_DIE(warning, "out of memory");
    bool warn = tx_inspect_nonce_warning(inspected, warning, TXINSPECT_WARNING_MAX);

    ui_show_tx_inspect(tx_inspect_kind_name(inspected), body, warn ? warning : NULL,
                       on_inspect_tx_done);

    // The UI has copied the strings it needs; scrub and release the buffers.
    secure_memzero(warning, TXINSPECT_WARNING_MAX);
    free(warning);
    secure_memzero(body, TXINSPECT_RENDER_MAX);
    free(body);
}

/* Ask whether to scan a wallet descriptor first, so change outputs can be
 * flagged on the transaction summary. */
static void on_inspect_tx(lv_event_t* e) {
    (void)e;
    if (!hal_camera_available()) {
        FATAL("Camera not available.");
    }
    ui_show_confirm("Scan Transaction/PSBT",
                    "Scan a wallet descriptor first?\n\nA descriptor lets you "
                    "verify which outputs are your change.",
                    "Scan descriptor", "Just scan", on_scan_descriptor, on_skip_descriptor);
}

static void on_skip_descriptor(void) { start_tx_scan(); }

static void on_scan_descriptor(void) {
    if (!hal_camera_available()) {
        FATAL("Camera not available.");
    }
    camera = hal_camera_open();
    ASSERT_OR_DIE(camera, "Failed to open camera.");
    qr_scan_cb = on_descriptor_payload;
    desc_decoder_reset();
    ui_show_qr_scan_auto(on_descriptor_cancel, "Scan Wallet Descriptor");
    camera_timer = lv_timer_create(camera_feed_tick, 120, NULL);
}

static void on_descriptor_cancel(void) {
    camera_feed_stop();
    desc_decoder_stop();
    on_inspect_tx(NULL);
}

static void descriptor_accept(descriptor_status_t st, descriptor_t* d) {
    if (!d) {
        if (st == DESCRIPTOR_ERR_PRIVATE) {
            camera_feed_stop();
            desc_decoder_stop();
            ui_show_msg("Descriptor has private keys.\nScan a public (xpub) descriptor.");
            ui_delay_ms(2000);
            on_inspect_tx(NULL);
        } else if (st == DESCRIPTOR_ERR_TOO_LONG) {
            camera_feed_stop();
            desc_decoder_stop();
            ui_show_msg("Descriptor is too long to scan.");
            ui_delay_ms(2000);
            on_inspect_tx(NULL);
        }
        return; /* not a descriptor (or an unsupported one); keep scanning */
    }

    camera_feed_stop();
    desc_decoder_stop();
    wallet_desc = d;
    start_tx_scan();
}

static void on_descriptor_payload(const uint8_t* payload, size_t plen) {
    /* UR-encoded descriptor: single-part or animated multi-part
     * ur:output-descriptor / ur:crypto-output. */
    if (plen >= 3 && (payload[0] == 'u' || payload[0] == 'U') &&
        (payload[1] == 'r' || payload[1] == 'R') && payload[2] == ':') {
        if (!desc_decoder) desc_decoder = ur_descriptor_decoder_new();

        char* text = NULL;
        int   r    = ur_descriptor_decoder_receive(desc_decoder, (const char*)payload, plen, &text);
        if (r == 0) {
            ui_qr_scan_progress(ur_descriptor_decoder_received(desc_decoder),
                                ur_descriptor_decoder_expected(desc_decoder));
        } else if (r == 1) {
            descriptor_status_t st = DESCRIPTOR_ERR_NOT_DESC;
            descriptor_t*       d  = descriptor_parse((const uint8_t*)text, strlen(text), &st);
            secure_memzero(text, strlen(text));
            free(text);
            descriptor_accept(st, d);
        }
        return; /* not a descriptor UR part; keep scanning */
    }

    descriptor_status_t st = DESCRIPTOR_ERR_NOT_DESC;
    descriptor_t*       d  = descriptor_parse(payload, plen, &st);
    descriptor_accept(st, d);
}

static void start_tx_scan(void) {
    if (!hal_camera_available()) {
        FATAL("Camera not available.");
    }
    ur_decoder_reset();
    camera = hal_camera_open();
    ASSERT_OR_DIE(camera, "Failed to open camera.");
    qr_scan_cb = on_tx_payload;
    ui_show_qr_scan_auto(on_inspect_tx_cancel, "Scan Transaction/PSBT");
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

static void on_tx_payload(const uint8_t* payload, size_t plen) {
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
                return;
            }
            show_inspected_tx();
        } else if (r == 0) {
            ui_qr_scan_progress(ur_psbt_decoder_received(ur_decoder),
                                ur_psbt_decoder_expected(ur_decoder));
        }
        /* r == -1: not a valid PSBT UR part; keep scanning. */
        return;
    }

    /* Raw transaction / PSBT (hex or base64). */
    inspected = tx_inspect_parse(payload, plen);
    if (!inspected) return; /* not recognised; keep scanning */

    camera_feed_stop();
    show_inspected_tx();
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
