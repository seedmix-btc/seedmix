/**
 * @file platform/linux/lvgl_gray.c
 * @brief Decode JPEG/BMP image files with LVGL's bundled decoders.
 *
 * The desktop HAL reads QR codes out of files the user picks, which means
 * getting a grayscale image out of whatever the file holds.  PNG and GIF have
 * decoders of their own (png_gray.c, gif_gray.c) because LVGL's would need the
 * whole image in LVGL's fixed memory pool; JPEG and BMP are fine on LVGL, whose
 * decoders stream block by block, so they go through LVGL's image decoder API
 * here - the one place the desktop build still decodes with LVGL.
 */

#include "lvgl_gray.h"

#include "lvgl.h"
#include "src/draw/lv_image_decoder_private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Luminance of one pixel of a decoded image. */
static uint8_t pixel_luma(lv_color_format_t cf, const uint8_t* p) {
    uint32_t r, g, b;

    switch (cf) {
    case LV_COLOR_FORMAT_ARGB8888:
    case LV_COLOR_FORMAT_XRGB8888:
        /* LVGL stores 32-bit colors as blue, green, red, alpha */
        b = p[0];
        g = p[1];
        r = p[2];
        break;
    case LV_COLOR_FORMAT_RGB888:
        r = p[0];
        g = p[1];
        b = p[2];
        break;
    case LV_COLOR_FORMAT_RGB565: {
        uint16_t v;
        memcpy(&v, p, sizeof(v));
        r = ((v >> 11) & 0x1Fu) * 255u / 31u;
        g = ((v >> 5) & 0x3Fu) * 255u / 63u;
        b = (v & 0x1Fu) * 255u / 31u;
        break;
    }
    case LV_COLOR_FORMAT_L8:
    case LV_COLOR_FORMAT_A8:
        return p[0];
    default:
        return 0;
    }

    /* Channel order only shifts the result slightly, which is irrelevant for a
     * black/white QR code. */
    return (uint8_t)((r * 299u + g * 587u + b * 114u) / 1000u);
}

/* Copy one decoded block (the whole image for some decoders, one MCU or row per
 * call for JPEG/BMP) into the full-size grayscale image. */
static void gray_from_block(uint8_t* gray, uint32_t gray_w, const lv_draw_buf_t* buf,
                            const lv_area_t* area) {
    uint8_t  bpp = lv_color_format_get_size(buf->header.cf);
    uint32_t w   = (uint32_t)lv_area_get_width(area);

    for (int32_t y = area->y1; y <= area->y2; y++) {
        const uint8_t* row = buf->data + (size_t)(y - area->y1) * buf->header.stride;
        uint8_t*       dst = gray + (size_t)y * gray_w + (size_t)area->x1;
        for (uint32_t x = 0; x < w; x++) {
            dst[x] = pixel_luma(buf->header.cf, row + (size_t)x * bpp);
        }
    }
}

/* Intersect `a` and `b`; false when they don't overlap (lv_area_intersect() is
 * private to LVGL and drags in another private header). */
static bool clip_area(lv_area_t* out, const lv_area_t* a, const lv_area_t* b) {
    out->x1 = a->x1 > b->x1 ? a->x1 : b->x1;
    out->y1 = a->y1 > b->y1 ? a->y1 : b->y1;
    out->x2 = a->x2 < b->x2 ? a->x2 : b->x2;
    out->y2 = a->y2 < b->y2 ? a->y2 : b->y2;
    return out->x1 <= out->x2 && out->y1 <= out->y2;
}

/* Decode an opened image into a grayscale buffer of the full image size. */
static bool decode_to_gray(lv_image_decoder_dsc_t* dsc, uint32_t w, uint32_t h, uint8_t* gray) {
    lv_area_t image = {0, 0, (int32_t)w - 1, (int32_t)h - 1};

    /* Decoders that return the whole image in one go. */
    if (dsc->decoded) {
        gray_from_block(gray, w, dsc->decoded, &image);
        return true;
    }

    /* JPEG/BMP decoders hand out the image piece by piece.  The pattern (and
     * the LV_COORD_MIN sentinel on the first call) follows LVGL's draw layer. */
    lv_area_t block = {LV_COORD_MIN, LV_COORD_MIN, LV_COORD_MIN, LV_COORD_MIN};
    bool      any   = false;
    for (size_t guard = 0; guard <= (size_t)w * h; guard++) {
        if (lv_image_decoder_get_area(dsc, &image, &block) != LV_RESULT_OK) break;

        lv_area_t clip;
        if (clip_area(&clip, &block, &image)) {
            gray_from_block(gray, w, dsc->decoded, &clip);
            any = true;
        }
    }
    return any;
}

uint8_t* lvgl_gray_decode_file(const char* path, uint32_t* out_w, uint32_t* out_h) {
    if (!path || !out_w || !out_h) return NULL;
    *out_w = 0;
    *out_h = 0;

    char lv_path[LV_FS_MAX_PATH_LEN];
    int  n = snprintf(lv_path, sizeof(lv_path), "%c:%s", LV_FS_POSIX_LETTER, path);
    if (n <= 0 || (size_t)n >= sizeof(lv_path)) return NULL;

    lv_image_decoder_dsc_t dsc;
    /* NULL args: no image cache is configured, so the decoder frees the pixel
     * buffer again in lv_image_decoder_close(). */
    if (lv_image_decoder_open(&dsc, lv_path, NULL) != LV_RESULT_OK) return NULL;

    uint32_t w    = (uint32_t)dsc.header.w;
    uint32_t h    = (uint32_t)dsc.header.h;
    uint8_t* gray = (w && h) ? malloc((size_t)w * h) : NULL;
    bool     ok   = gray && decode_to_gray(&dsc, w, h, gray);

    lv_image_decoder_close(&dsc);

    if (!ok) {
        free(gray);
        return NULL;
    }

    *out_w = w;
    *out_h = h;
    return gray;
}
