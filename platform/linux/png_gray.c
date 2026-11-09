/**
 * @file platform/linux/png_gray.c
 * @brief Minimal PNG decoder for reading a QR code out of an image file.
 *
 * LVGL's bundled PNG decoder keeps the whole decoded image in LVGL's fixed
 * memory pool (LV_MEM_SIZE - a size meant for widget objects), which is far
 * too small for a screenshot.  So the desktop HAL decodes PNGs itself: zlib
 * for the pixel data, then one pass over the scanlines straight into the
 * grayscale image quirc wants.
 *
 * Supported: color types grayscale, RGB, palette, grayscale+alpha and RGBA;
 * bit depths 1/2/4/8/16; non-interlaced and Adam7 images.  Anything else
 * (including truncated, corrupt or absurdly large files) fails cleanly so the
 * caller can report "not an image".
 */

#include "png_gray.h"
#include "image_file.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define PNG_SIG_LEN 8
#define PNG_CHUNK_HDR 8 /* length + type */
#define PNG_CHUNK_CRC 4
#define PNG_MAX_FILE (128u * 1024u * 1024u) /* sanity limits for a picked file */
#define PNG_MAX_PIXELS (64u * 1024u * 1024u)

static const uint8_t PNG_SIG[PNG_SIG_LEN] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};

/* PNG color types. */
enum {
    PNG_COLOR_GRAY    = 0,
    PNG_COLOR_RGB     = 2,
    PNG_COLOR_PALETTE = 3,
    PNG_COLOR_GRAY_A  = 4,
    PNG_COLOR_RGBA    = 6,
};

typedef struct {
    uint32_t width;
    uint32_t height;
    uint8_t  depth;     /* bits per sample: 1, 2, 4, 8 or 16 */
    uint8_t  color;     /* one of PNG_COLOR_* */
    uint8_t  interlace; /* 0 = none, 1 = Adam7 */
    uint8_t  palette[256 * 3];
    uint8_t  palette_alpha[256];
    uint32_t palette_len;
} png_image_t;

/* Adam7 pass layout: origin and step per pass. */
static const uint8_t ADAM7_X0[7] = {0, 4, 0, 2, 0, 1, 0};
static const uint8_t ADAM7_Y0[7] = {0, 0, 4, 0, 2, 0, 1};
static const uint8_t ADAM7_DX[7] = {8, 8, 4, 4, 2, 2, 1};
static const uint8_t ADAM7_DY[7] = {8, 8, 8, 4, 4, 2, 2};

typedef struct {
    uint32_t cols; /* pixels per row of this pass */
    uint32_t rows;
    uint32_t x0;
    uint32_t y0;
    uint32_t dx;
    uint32_t dy;
} png_pass_t;

static uint32_t be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t channels_of(uint8_t color) {
    switch (color) {
    case PNG_COLOR_RGB:
        return 3;
    case PNG_COLOR_GRAY_A:
        return 2;
    case PNG_COLOR_RGBA:
        return 4;
    default: /* grayscale, or a palette index */
        return 1;
    }
}

static uint32_t bits_per_pixel(const png_image_t* img) {
    return channels_of(img->color) * img->depth;
}

static bool depth_is_valid(uint8_t color, uint8_t depth) {
    switch (color) {
    case PNG_COLOR_GRAY:
        return depth == 1 || depth == 2 || depth == 4 || depth == 8 || depth == 16;
    case PNG_COLOR_RGB:
    case PNG_COLOR_GRAY_A:
    case PNG_COLOR_RGBA:
        return depth == 8 || depth == 16;
    case PNG_COLOR_PALETTE:
        return depth == 1 || depth == 2 || depth == 4 || depth == 8;
    default:
        return false;
    }
}

static png_pass_t pass_geometry(const png_image_t* img, unsigned pass) {
    png_pass_t p;
    memset(&p, 0, sizeof(p));

    if (img->interlace) {
        p.x0 = ADAM7_X0[pass];
        p.y0 = ADAM7_Y0[pass];
        p.dx = ADAM7_DX[pass];
        p.dy = ADAM7_DY[pass];
    } else {
        p.dx = 1;
        p.dy = 1;
    }

    if (img->width > p.x0) p.cols = (img->width - p.x0 + p.dx - 1) / p.dx;
    if (img->height > p.y0) p.rows = (img->height - p.y0 + p.dy - 1) / p.dy;
    return p;
}

/** Bytes of pixel data per row of @p p (the filter byte is not included). */
static uint32_t pass_row_bytes(const png_image_t* img, const png_pass_t* p) {
    return (p->cols * bits_per_pixel(img) + 7u) / 8u;
}

/* -- Scanline decoding ------------------------------------------------- */

static uint8_t paeth(uint8_t a, uint8_t b, uint8_t c) {
    int pa = abs((int)b - (int)c);
    int pb = abs((int)a - (int)c);
    int pc = abs((int)a + (int)b - 2 * (int)c);

    if (pa <= pb && pa <= pc) return a;
    return (pb <= pc) ? b : c;
}

/* Undo the filter of one row.  @p prev is the previous *unfiltered* row of the
 * same pass (all zeros for the first row). */
static bool unfilter_row(uint8_t filter, uint8_t* row, const uint8_t* prev, uint32_t rb,
                         uint32_t bpp) {
    switch (filter) {
    case 0: /* none */
        return true;
    case 1: /* sub */
        for (uint32_t i = bpp; i < rb; i++) row[i] = (uint8_t)(row[i] + row[i - bpp]);
        return true;
    case 2: /* up */
        for (uint32_t i = 0; i < rb; i++) row[i] = (uint8_t)(row[i] + prev[i]);
        return true;
    case 3: /* average */
        for (uint32_t i = 0; i < rb; i++) {
            uint32_t a = (i >= bpp) ? row[i - bpp] : 0;
            row[i]     = (uint8_t)(row[i] + (a + prev[i]) / 2);
        }
        return true;
    case 4: /* paeth */
        for (uint32_t i = 0; i < rb; i++) {
            uint8_t a = (i >= bpp) ? row[i - bpp] : 0;
            uint8_t c = (i >= bpp) ? prev[i - bpp] : 0;
            row[i]    = (uint8_t)(row[i] + paeth(a, prev[i], c));
        }
        return true;
    default: /* invalid filter type */
        return false;
    }
}

/** Value of the @p i -th sample of a row that packs several samples per byte. */
static uint32_t sub_byte_sample(const uint8_t* row, uint32_t i, uint32_t depth) {
    uint32_t bit = i * depth;
    return (uint32_t)((row[bit >> 3] >> (8u - depth - (bit & 7u))) & ((1u << depth) - 1u));
}

/** Luminance of pixel @p i of a row, with any alpha composited over white. */
static uint8_t pixel_luma(const png_image_t* img, const uint8_t* row, uint32_t i) {
    uint32_t r, g, b, a = 255;

    switch (img->color) {
    case PNG_COLOR_GRAY:
        if (img->depth == 16) {
            r = g = b = row[i * 2]; /* high byte of the 16-bit sample */
        } else if (img->depth == 8) {
            r = g = b = row[i];
        } else {
            uint32_t max = (1u << img->depth) - 1u;
            r = g = b = sub_byte_sample(row, i, img->depth) * 255u / max;
        }
        break;
    case PNG_COLOR_GRAY_A:
        r = g = b = (img->depth == 16) ? row[i * 4] : row[i * 2];
        a         = (img->depth == 16) ? row[i * 4 + 2] : row[i * 2 + 1];
        break;
    case PNG_COLOR_RGB:
        r = (img->depth == 16) ? row[i * 6] : row[i * 3];
        g = (img->depth == 16) ? row[i * 6 + 2] : row[i * 3 + 1];
        b = (img->depth == 16) ? row[i * 6 + 4] : row[i * 3 + 2];
        break;
    case PNG_COLOR_RGBA:
        r = (img->depth == 16) ? row[i * 8] : row[i * 4];
        g = (img->depth == 16) ? row[i * 8 + 2] : row[i * 4 + 1];
        b = (img->depth == 16) ? row[i * 8 + 4] : row[i * 4 + 2];
        a = (img->depth == 16) ? row[i * 8 + 6] : row[i * 4 + 3];
        break;
    default: { /* palette index */
        uint32_t idx = (img->depth == 8) ? row[i] : sub_byte_sample(row, i, img->depth);
        if (idx >= img->palette_len) return 0;
        r = img->palette[idx * 3];
        g = img->palette[idx * 3 + 1];
        b = img->palette[idx * 3 + 2];
        a = img->palette_alpha[idx];
        break;
    }
    }

    /* Composite over white: the light modules of a QR image are often the
     * transparent ones. */
    uint32_t luma = (r * 299u + g * 587u + b * 114u) / 1000u;
    return (uint8_t)((luma * a + 255u * (255u - a)) / 255u);
}

/** Decode the inflated scanlines into @p gray (width * height bytes). */
static bool decode_passes(const png_image_t* img, const uint8_t* raw, size_t raw_len,
                          uint8_t* gray) {
    unsigned passes = img->interlace ? 7u : 1u;
    uint32_t bits   = bits_per_pixel(img);
    uint32_t bpp    = (bits / 8u) > 0 ? bits / 8u : 1u; /* filter distance in bytes */
    size_t   pos    = 0;

    for (unsigned pass = 0; pass < passes; pass++) {
        png_pass_t g = pass_geometry(img, pass);
        if (g.cols == 0 || g.rows == 0) continue;

        uint32_t rb   = pass_row_bytes(img, &g);
        uint8_t* prev = calloc(rb, 1);
        uint8_t* cur  = malloc(rb);
        bool     ok   = prev && cur;

        for (uint32_t y = 0; ok && y < g.rows; y++) {
            if (pos + 1 + rb > raw_len) { /* truncated scanline data */
                ok = false;
                break;
            }

            uint8_t filter = raw[pos++];
            memcpy(cur, raw + pos, rb);
            pos += rb;

            ok = unfilter_row(filter, cur, prev, rb, bpp);
            if (!ok) break;

            for (uint32_t i = 0; i < g.cols; i++) {
                uint32_t x                        = g.x0 + i * g.dx;
                uint32_t y_                       = g.y0 + y * g.dy;
                gray[(size_t)y_ * img->width + x] = pixel_luma(img, cur, i);
            }

            uint8_t* tmp = prev;
            prev         = cur;
            cur          = tmp;
        }

        free(prev);
        free(cur);
        if (!ok) return false;
    }

    return true;
}

/* -- File and chunk parsing -------------------------------------------- */

/** Expected size of the inflated scanline data (filter byte per row). */
static bool expected_raw_size(const png_image_t* img, size_t* out) {
    unsigned passes = img->interlace ? 7u : 1u;
    size_t   total  = 0;

    for (unsigned pass = 0; pass < passes; pass++) {
        png_pass_t g = pass_geometry(img, pass);
        if (g.cols == 0 || g.rows == 0) continue;
        total += (size_t)g.rows * (pass_row_bytes(img, &g) + 1u);
    }

    if (total == 0 || total > (size_t)PNG_MAX_PIXELS * 8u) return false;
    *out = total;
    return true;
}

uint8_t* png_decode_gray_file(const char* path, uint32_t* out_w, uint32_t* out_h) {
    if (!path || !out_w || !out_h) return NULL;
    *out_w = 0;
    *out_h = 0;

    size_t   file_len = 0;
    uint8_t* file     = image_read_file(path, &file_len, PNG_MAX_FILE);
    if (!file) return NULL;

    if (file_len < PNG_SIG_LEN || memcmp(file, PNG_SIG, PNG_SIG_LEN) != 0) {
        free(file);
        return NULL; /* not a PNG; the caller can try the other decoders */
    }

    png_image_t img;
    memset(&img, 0, sizeof(img));
    memset(img.palette_alpha, 0xFF, sizeof(img.palette_alpha));

    uint8_t* idat      = NULL;
    size_t   idat_len  = 0;
    bool     have_ihdr = false;
    bool     ok        = true;
    size_t   pos       = PNG_SIG_LEN;

    while (ok) {
        if (pos + PNG_CHUNK_HDR + PNG_CHUNK_CRC > file_len) { /* truncated */
            ok = false;
            break;
        }

        uint32_t       len  = be32(file + pos);
        const uint8_t* type = file + pos + 4;
        const uint8_t* data = file + pos + PNG_CHUNK_HDR;

        if (len > file_len - pos - PNG_CHUNK_HDR - PNG_CHUNK_CRC) {
            ok = false;
            break;
        }

        uint32_t crc = crc32(crc32(0, NULL, 0), type, 4);
        if (crc32(crc, data, len) != be32(data + len)) { /* corrupt chunk */
            ok = false;
            break;
        }

        if (memcmp(type, "IHDR", 4) == 0) {
            if (have_ihdr || len != 13) {
                ok = false;
                break;
            }
            img.width     = be32(data);
            img.height    = be32(data + 4);
            img.depth     = data[8];
            img.color     = data[9];
            img.interlace = data[12];

            have_ihdr = img.width > 0 && img.height > 0 && img.interlace <= 1 &&
                        depth_is_valid(img.color, img.depth) &&
                        (uint64_t)img.width * img.height <= (uint64_t)PNG_MAX_PIXELS;
            ok = have_ihdr;
        } else if (!have_ihdr) {
            ok = false; /* IHDR must be the first chunk */
            break;
        } else if (memcmp(type, "PLTE", 4) == 0) {
            if (len == 0 || len % 3 != 0 || len > sizeof(img.palette)) {
                ok = false;
                break;
            }
            memcpy(img.palette, data, len);
            img.palette_len = len / 3;
        } else if (memcmp(type, "tRNS", 4) == 0) {
            /* Alpha per palette entry; the other color types only get a single
             * transparent color here, which is not worth special casing. */
            if (img.color == PNG_COLOR_PALETTE && len <= img.palette_len) {
                memcpy(img.palette_alpha, data, len);
            }
        } else if (memcmp(type, "IDAT", 4) == 0) {
            uint8_t* grown = realloc(idat, idat_len + len);
            if (!grown) {
                ok = false;
                break;
            }
            idat = grown;
            memcpy(idat + idat_len, data, len);
            idat_len += len;
        } else if (memcmp(type, "IEND", 4) == 0) {
            break;
        }

        pos += PNG_CHUNK_HDR + len + PNG_CHUNK_CRC;
    }

    free(file);

    size_t expected = 0;
    if (img.color == PNG_COLOR_PALETTE && img.palette_len == 0) ok = false;
    if (ok && (!have_ihdr || !idat || !expected_raw_size(&img, &expected))) ok = false;

    uint8_t* gray = NULL;
    if (ok) {
        uint8_t* raw     = malloc(expected);
        uLongf   raw_len = (uLongf)expected;
        int      zres    = raw ? uncompress(raw, &raw_len, idat, (uLong)idat_len) : Z_MEM_ERROR;

        if (zres == Z_OK && raw_len == expected) {
            gray = malloc((size_t)img.width * img.height);
            if (gray && !decode_passes(&img, raw, expected, gray)) {
                free(gray);
                gray = NULL;
            }
        }
        free(raw);
    }

    free(idat);

    if (!gray) return NULL;

    *out_w = img.width;
    *out_h = img.height;
    return gray;
}
