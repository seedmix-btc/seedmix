/**
 * @file platform/linux/gif_gray.c
 * @brief Minimal GIF decoder for reading a QR code out of an image file.
 *
 * An animated GIF is how a fountain-encoded multi-part UR (a PSBT or wallet
 * descriptor) is normally published as a single file, so the decoder hands out
 * frames one at a time: the caller keeps asking for the next frame while the
 * multi-part UR decoder accumulates parts, exactly as it would while a camera
 * watches the animation playing on another wallet's screen.
 *
 * Frames are composited onto an RGB canvas the way a browser would (frame
 * disposal, transparent color, interlacing, local color tables) and then
 * reduced to the grayscale image quirc wants.  The canvas lives in ordinary
 * heap memory, unlike LVGL's bundled GIF support, which draws into LVGL's
 * fixed memory pool (LV_MEM_SIZE - a size meant for widget objects).
 *
 * Supported: GIF87a/GIF89a, global and local color tables, all four frame
 * disposal methods, a transparent color index, interlaced frames and any
 * number of frames.  Anything else (truncated, corrupt or absurdly large
 * files) fails cleanly so the caller can report "not an image".
 */

#include "gif_gray.h"
#include "image_file.h"

#include <stdlib.h>
#include <string.h>

#define GIF_SIG_LEN 6
#define GIF_MAX_FILE (64u * 1024u * 1024u)  /* sanity limits for a picked file */
#define GIF_MAX_PIXELS (4u * 1024u * 1024u) /* canvas: 2048 x 2048 */
#define GIF_MAX_CODES 4096                  /* 12-bit LZW code space */
#define GIF_DEFAULT_DELAY_MS 100u           /* what browsers use for "no delay" */

static const uint8_t GIF87A[GIF_SIG_LEN] = {'G', 'I', 'F', '8', '7', 'a'};
static const uint8_t GIF89A[GIF_SIG_LEN] = {'G', 'I', 'F', '8', '9', 'a'};

struct gif_gray {
    uint8_t* file;      /* whole file (owned) */
    size_t   len;       /* file length */
    size_t   pos;       /* parse cursor */
    size_t   first_pos; /* first block after the header (rewind target) */

    uint32_t sw;     /* logical screen width */
    uint32_t sh;     /* logical screen height */
    uint8_t* canvas; /* sw * sh * 3 - the frame being composited */
    uint8_t* prev;   /* canvas before the current frame (disposal 3), lazily */
    uint8_t  bg[3];  /* background color (initial canvas fill) */

    const uint8_t* gct;        /* global color table, or NULL */
    uint32_t       gct_colors; /* entries in the global color table */

    /* Graphic control extension that applies to the next image. */
    bool     have_gce;
    uint32_t delay_cs;
    int      transparent; /* palette index, or -1 */
    uint8_t  disposal;

    bool failed;  /* stopped on a malformed or truncated file */
    bool trailer; /* reached the end of the animation */
};

static uint16_t le16(const uint8_t* p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }

/** Fill a rectangle of the canvas with one color (clipped by the caller). */
static void canvas_fill(gif_gray_t* g, uint32_t left, uint32_t top, uint32_t w, uint32_t h,
                        const uint8_t rgb[3]) {
    for (uint32_t y = 0; y < h; y++) {
        uint8_t* row = g->canvas + ((size_t)(top + y) * g->sw + left) * 3;
        for (uint32_t x = 0; x < w; x++) {
            memcpy(row + (size_t)x * 3, rgb, 3);
        }
    }
}

/** Reduce the composited canvas to the grayscale image quirc wants. */
static uint8_t* canvas_to_gray(const gif_gray_t* g) {
    size_t   n    = (size_t)g->sw * g->sh;
    uint8_t* gray = malloc(n);
    if (!gray) return NULL;

    for (size_t i = 0; i < n; i++) {
        const uint8_t* p = g->canvas + i * 3;
        gray[i]          = (uint8_t)((p[0] * 299u + p[1] * 587u + p[2] * 114u) / 1000u);
    }
    return gray;
}

/* -- LZW -------------------------------------------------------------- */

/*
 * GIF's variable-width LZW.  Codes start at min_code + 1 bits, the table grows
 * by one entry per code, and the width grows with it up to 12 bits.  A clear
 * code resets the table; the code after a clear is always a literal.
 */
static bool lzw_decode(const uint8_t* in, size_t in_len, int min_code, uint8_t* out, size_t npix) {
    if (min_code < 2 || min_code > 8 || !out || npix == 0) return false;

    uint16_t prefix[GIF_MAX_CODES];
    uint8_t  suffix[GIF_MAX_CODES];
    uint8_t  first[GIF_MAX_CODES];
    uint8_t  stack[GIF_MAX_CODES + 1];

    const int clear = 1 << min_code;
    const int eoi   = clear + 1;

    int      code_size = min_code + 1;
    int      next      = eoi + 1;
    int      prev      = -1;
    uint32_t bits      = 0;
    int      nbits     = 0;
    size_t   ip        = 0;
    size_t   op        = 0;

    for (int i = 0; i < clear; i++) {
        prefix[i] = 0;
        suffix[i] = (uint8_t)i;
        first[i]  = (uint8_t)i;
    }

    while (op < npix) {
        while (nbits < code_size) {
            if (ip >= in_len) return false; /* truncated stream */
            bits |= (uint32_t)in[ip++] << nbits;
            nbits += 8;
        }

        int code = (int)(bits & (uint32_t)((1u << code_size) - 1u));
        bits >>= code_size;
        nbits -= code_size;

        if (code == clear) {
            code_size = min_code + 1;
            next      = eoi + 1;
            prev      = -1;
            continue;
        }
        if (code == eoi) break;
        if (code > next) return false; /* the encoder never defined this code */

        int stack_len = 0;
        int cur       = code;
        if (cur == next) { /* KwKwK: this code is defined by the step itself */
            if (prev < 0) return false;
            stack[stack_len++] = first[prev];
            cur                = prev;
        }
        while (cur >= clear) {
            if (stack_len >= GIF_MAX_CODES) return false;
            stack[stack_len++] = suffix[cur];
            cur                = prefix[cur];
        }
        if (stack_len >= GIF_MAX_CODES) return false;
        stack[stack_len++] = (uint8_t)cur;

        /* The strings are built back to front, so emit the stack reversed. */
        for (int i = stack_len - 1; i >= 0 && op < npix; i--) {
            out[op++] = stack[i];
        }

        if (prev >= 0 && next < GIF_MAX_CODES) {
            prefix[next] = (uint16_t)prev;
            suffix[next] = stack[stack_len - 1]; /* first character of this string */
            first[next]  = first[prev];
            next++;
            if (next == (1 << code_size) && code_size < 12) code_size++;
        }
        prev = code;
    }

    return op == npix;
}

/** Undo GIF's four-pass interlacing (rows are stored 8-8-4-2 apart). */
static void deinterlace(const uint8_t* src, uint8_t* dst, uint32_t w, uint32_t h) {
    static const uint32_t START[4] = {0, 4, 2, 1};
    static const uint32_t STEP[4]  = {8, 8, 4, 2};

    uint32_t row = 0;
    for (unsigned pass = 0; pass < 4; pass++) {
        for (uint32_t y = START[pass]; y < h; y += STEP[pass]) {
            memcpy(dst + (size_t)y * w, src + (size_t)row * w, w);
            row++;
        }
    }
}

/* -- Block parsing ---------------------------------------------------- */

/** Skip a chain of length-prefixed sub-blocks. */
static bool skip_sub_blocks(gif_gray_t* g) {
    while (g->pos < g->len) {
        uint8_t n = g->file[g->pos++];
        if (n == 0) return true;
        if (n > g->len - g->pos) break;
        g->pos += n;
    }

    g->failed = true;
    return false;
}

/** Read a graphic control extension (the cursor sits on its block size). */
static bool read_gce(gif_gray_t* g) {
    if (g->len - g->pos < 6 || g->file[g->pos] != 4) {
        g->failed = true;
        return false;
    }

    const uint8_t* p    = g->file + g->pos + 1;
    uint8_t        pack = p[0];

    g->disposal    = (uint8_t)((pack >> 2) & 0x7u);
    g->delay_cs    = le16(p + 1);
    g->transparent = (pack & 0x1u) ? (int)p[3] : -1;
    g->have_gce    = true;

    g->pos += 1 + 4 + 1; /* size + data + block terminator */
    return true;
}

/** Copy the sub-blocks holding the image's LZW data into one buffer. */
static bool gather_data(gif_gray_t* g, uint8_t** out, size_t* out_len) {
    size_t scan = g->pos, total = 0;

    for (;;) {
        if (scan >= g->len) return false;
        uint8_t n = g->file[scan++];
        if (n == 0) break;
        if (n > g->len - scan) return false;
        scan += n;
        total += n;
    }

    uint8_t* data = malloc(total ? total : 1);
    if (!data) return false;

    size_t src = g->pos, dst = 0;
    for (;;) {
        uint8_t n = g->file[src++];
        if (n == 0) break;
        memcpy(data + dst, g->file + src, n);
        src += n;
        dst += n;
    }

    g->pos   = scan; /* past the terminator */
    *out     = data;
    *out_len = total;
    return true;
}

/* -- Frame decoding --------------------------------------------------- */

/** Decode the image block the cursor sits on and composite it. */
static bool decode_frame(gif_gray_t* g, uint8_t** out_gray, uint32_t* out_delay_ms) {
    if (g->len - g->pos < 9) goto fail;

    const uint8_t* d    = g->file + g->pos;
    uint32_t       left = le16(d), top = le16(d + 2);
    uint32_t       w = le16(d + 4), h = le16(d + 6);
    uint8_t        pack = d[8];
    g->pos += 9;

    if (!w || !h) goto fail;
    if ((uint64_t)w * h > (uint64_t)GIF_MAX_PIXELS) goto fail;
    if (left >= g->sw || top >= g->sh) goto fail; /* frame entirely off-screen */

    /* Clip the frame to the logical screen: encoders do produce frames that
     * stick out, and browsers simply crop them. */
    uint32_t vis_w = w, vis_h = h;
    if (left + vis_w > g->sw) vis_w = g->sw - left;
    if (top + vis_h > g->sh) vis_h = g->sh - top;

    const uint8_t* palette = g->gct;
    uint32_t       colors  = g->gct_colors;
    if (pack & 0x80u) { /* local color table */
        uint32_t n = 2u << (pack & 0x7u);
        if (g->len - g->pos < (size_t)3u * n) goto fail;
        palette = g->file + g->pos;
        colors  = n;
        g->pos += (size_t)3u * n;
    }
    if (!palette || !colors) goto fail; /* nothing to look colors up in */

    if (g->pos >= g->len) goto fail;
    int min_code = g->file[g->pos++];

    uint8_t* data     = NULL;
    size_t   data_len = 0;
    if (!gather_data(g, &data, &data_len)) goto fail;

    uint8_t* idx = malloc((size_t)w * h);
    if (!idx) {
        free(data);
        goto fail;
    }

    bool ok = lzw_decode(data, data_len, min_code, idx, (size_t)w * h);
    free(data);
    if (!ok) {
        free(idx);
        goto fail;
    }

    uint8_t* linear = idx;
    if (pack & 0x40u) { /* interlaced */
        linear = malloc((size_t)w * h);
        if (!linear) {
            free(idx);
            goto fail;
        }
        deinterlace(idx, linear, w, h);
        free(idx);
    }

    /* The control extension applies to this frame only. */
    int      transparent = g->transparent;
    uint8_t  disposal    = g->disposal;
    uint32_t delay_ms    = g->have_gce ? g->delay_cs * 10u : GIF_DEFAULT_DELAY_MS;
    g->have_gce          = false;
    g->disposal          = 0;
    g->transparent       = -1;
    g->delay_cs          = 0;
    if (delay_ms == 0) delay_ms = GIF_DEFAULT_DELAY_MS;

    /* Disposal 3 means "put the canvas back afterwards", so the canvas has to
     * be saved before this frame is drawn on top of it. */
    if (disposal == 3 && !g->prev) {
        g->prev = malloc((size_t)g->sw * g->sh * 3);
    }
    if (disposal == 3) {
        if (!g->prev) {
            free(linear);
            goto fail;
        }
        memcpy(g->prev, g->canvas, (size_t)g->sw * g->sh * 3);
    }

    bool use_trans = transparent >= 0 && (uint32_t)transparent < colors;
    for (uint32_t y = 0; y < vis_h; y++) {
        uint8_t*       dst = g->canvas + ((size_t)(top + y) * g->sw + left) * 3;
        const uint8_t* src = linear + (size_t)y * w;
        for (uint32_t x = 0; x < vis_w; x++) {
            int v = src[x];
            if (use_trans && v == transparent) continue; /* keep what is there */
            if ((uint32_t)v >= colors) continue;         /* table too short */
            memcpy(dst + (size_t)x * 3, palette + (size_t)v * 3, 3);
        }
    }
    free(linear);

    /* The frame the caller sees is the canvas with this frame drawn on it, so
     * the disposal must only be applied afterwards - it is what the *next*
     * frame starts from. */
    uint8_t* gray = canvas_to_gray(g);
    if (!gray) goto fail;

    if (disposal == 2) {
        canvas_fill(g, left, top, vis_w, vis_h, g->bg);
    } else if (disposal == 3) {
        memcpy(g->canvas, g->prev, (size_t)g->sw * g->sh * 3);
    }

    *out_gray     = gray;
    *out_delay_ms = delay_ms;
    return true;

fail:
    g->failed = true;
    return false;
}

bool gif_gray_next(gif_gray_t* g, uint8_t** out_gray, uint32_t* out_delay_ms) {
    if (!g || !out_gray || !out_delay_ms) return false;

    *out_gray     = NULL;
    *out_delay_ms = GIF_DEFAULT_DELAY_MS;
    if (g->failed || g->trailer) return false;

    for (;;) {
        if (g->pos >= g->len) { /* the file has no trailer */
            g->failed = true;
            return false;
        }

        uint8_t block = g->file[g->pos++];

        if (block == 0x3B) { /* trailer */
            g->trailer = true;
            return false;
        }
        if (block == 0x21) { /* extension */
            if (g->pos >= g->len) break;
            uint8_t label = g->file[g->pos++];
            if (label == 0xF9) {
                if (!read_gce(g)) return false;
            } else if (!skip_sub_blocks(g)) {
                return false;
            }
            continue;
        }
        if (block == 0x2C) return decode_frame(g, out_gray, out_delay_ms); /* image */
        if (block == 0x00) continue;                                       /* padding */

        break; /* not a block GIF defines */
    }

    g->failed = true;
    return false;
}

bool gif_gray_failed(const gif_gray_t* g) { return g ? g->failed : true; }

void gif_gray_rewind(gif_gray_t* g) {
    if (!g) return;

    g->pos         = g->first_pos;
    g->have_gce    = false;
    g->delay_cs    = 0;
    g->transparent = -1;
    g->disposal    = 0;
    g->failed      = false;
    g->trailer     = false;

    canvas_fill(g, 0, 0, g->sw, g->sh, g->bg);
}

void gif_gray_close(gif_gray_t* g) {
    if (!g) return;

    free(g->file);
    free(g->canvas);
    free(g->prev);
    free(g);
}

gif_gray_t* gif_gray_open(const char* path, uint32_t* out_w, uint32_t* out_h) {
    if (!path || !out_w || !out_h) return NULL;
    *out_w = 0;
    *out_h = 0;

    size_t   len  = 0;
    uint8_t* file = image_read_file(path, &len, GIF_MAX_FILE);
    if (!file) return NULL;

    if (len < 13 ||
        (memcmp(file, GIF87A, GIF_SIG_LEN) != 0 && memcmp(file, GIF89A, GIF_SIG_LEN) != 0)) {
        free(file);
        return NULL; /* not a GIF; the caller can try the other decoders */
    }

    uint32_t sw   = le16(file + 6);
    uint32_t sh   = le16(file + 8);
    uint8_t  pack = file[10];
    uint8_t  bg_i = file[11];
    size_t   pos  = 13;

    if (!sw || !sh || (uint64_t)sw * sh > (uint64_t)GIF_MAX_PIXELS) {
        free(file);
        return NULL;
    }

    const uint8_t* gct        = NULL;
    uint32_t       gct_colors = 0;
    if (pack & 0x80u) { /* global color table */
        gct_colors = 2u << (pack & 0x7u);
        if (len - pos < (size_t)3u * gct_colors) {
            free(file);
            return NULL;
        }
        gct = file + pos;
        pos += (size_t)3u * gct_colors;
    }

    gif_gray_t* g = calloc(1, sizeof(*g));
    if (!g) {
        free(file);
        return NULL;
    }

    g->file        = file;
    g->len         = len;
    g->pos         = pos;
    g->first_pos   = pos;
    g->sw          = sw;
    g->sh          = sh;
    g->gct         = gct;
    g->gct_colors  = gct_colors;
    g->transparent = -1;

    g->canvas = malloc((size_t)sw * sh * 3);
    if (!g->canvas) {
        gif_gray_close(g);
        return NULL;
    }

    /* Start from the background color.  Unlike a browser we are not playing
     * the animation for a viewer, only looking for QR codes in it, and a
     * light background is what a QR code needs. */
    if (gct && bg_i < gct_colors) {
        memcpy(g->bg, gct + (size_t)bg_i * 3, 3);
    } else {
        g->bg[0] = 0xFF;
        g->bg[1] = 0xFF;
        g->bg[2] = 0xFF;
    }
    canvas_fill(g, 0, 0, sw, sh, g->bg);

    *out_w = sw;
    *out_h = sh;
    return g;
}
