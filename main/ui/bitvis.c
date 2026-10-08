/**
 * @file main/ui/bitvis.c
 * @brief Animated bit-level XOR view (see bitvis.h).
 *
 * The merge screen draws what the XOR does, bit by bit, below the hex text.
 * Each operand is a grid of byte blocks and every block shows its two hex
 * digits above its eight bits. A timer walks one bit per tick, so the merged
 * row fills in as the scan passes each bit.
 *
 * The grids are hand-rendered RGB565 buffers so the visual is three
 * lv_image widgets instead of hundreds of bit objects.
 */

#include "bitvis.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ui_internal.h"
#include "util/error.h"
#include "util/utils.h"

/* Hex glyphs, 3 columns x 5 rows.  In each row bit 0 is the left column. */
static const uint8_t s_xv_glyph[16][5] = {
    {7, 5, 5, 5, 7}, {2, 3, 2, 2, 7}, {7, 4, 7, 1, 7}, {7, 4, 7, 4, 7},
    {5, 5, 7, 4, 4}, {7, 1, 7, 4, 7}, {7, 1, 7, 5, 7}, {7, 4, 4, 4, 4},
    {7, 5, 7, 5, 7}, {7, 5, 7, 4, 7}, {7, 5, 7, 5, 5}, {1, 1, 7, 5, 7},
    {7, 1, 1, 1, 7}, {4, 4, 7, 5, 7}, {7, 1, 7, 1, 7}, {7, 1, 7, 1, 1},
};

#define XV_BG 0x0000u      // black
#define XV_BIT_OFF 0x2124u // dark grey: 0 bit
#define XV_BIT_ON 0xFFFFu  // white: 1 bit in an operand
#define XV_BIT_DIM 0x10A2u // nearly black: merged bit not scanned yet
#define XV_RES_ON 0x07E0u  // green: 1 bit in the result
#define XV_CUR 0xFD20u     // orange: the bit being XORed now
#define XV_HEX 0xBDF7u     // light grey: byte value
#define XV_HEX_CUR 0xFFFFu // white: value of the byte being scanned

#define XV_OPERANDS 3   // A, B and the result
#define XV_MAX_BYTES 32 // 24 words -> 32 bytes
#define XV_TICK_MS 25u
#define XV_HOLD_TICKS 24 // linger on the finished result

typedef struct {
    uint8_t  bytes[XV_OPERANDS][XV_MAX_BYTES];
    uint16_t elen;
    int32_t  cur;  // bit index being XORed, -1 before the scan starts
    int32_t  hold; // ticks left to show the finished result

    lv_obj_t*      imgs[XV_OPERANDS];
    lv_image_dsc_t dsc[XV_OPERANDS];
    uint16_t*      buf[XV_OPERANDS];
    size_t         buf_bytes;
    lv_timer_t*    timer;
    lv_obj_t*      status;
    lv_obj_t*      screen;

    lv_coord_t w, h;
    lv_coord_t block_w, row_h, cell, gap, pad;
    uint8_t    cols, rows;
    uint16_t   total_bits;
} xorview_t;

static int xv_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool xv_parse_hex(const char* hex, uint8_t* out, size_t bytes) {
    if (!hex) return false;
    for (size_t i = 0; i < bytes; i++) {
        int hi = xv_hexval(hex[2 * i]);
        int lo = xv_hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return hex[2 * bytes] == '\0';
}

static void xv_fill(uint16_t* buf, lv_coord_t w, lv_coord_t h, lv_coord_t x, lv_coord_t y,
                    lv_coord_t rw, lv_coord_t rh, uint16_t color) {
    if (x < 0) {
        rw += x;
        x = 0;
    }
    if (y < 0) {
        rh += y;
        y = 0;
    }
    if (rw <= 0 || rh <= 0) return;
    if (x + rw > w) rw = w - x;
    if (y + rh > h) rh = h - y;
    for (lv_coord_t j = 0; j < rh; j++) {
        uint16_t* row = buf + (size_t)(y + j) * (size_t)w + (size_t)x;
        for (lv_coord_t i = 0; i < rw; i++) row[i] = color;
    }
}

/* Two hex digits at (x, y), 3x5 pixels each. */
static void xv_hex(uint16_t* buf, lv_coord_t w, lv_coord_t h, lv_coord_t x, lv_coord_t y,
                   uint8_t value, uint16_t color) {
    for (int n = 0; n < 2; n++) {
        const uint8_t* g  = s_xv_glyph[n == 0 ? (value >> 4) : (value & 0xFu)];
        lv_coord_t     gx = x + n * 4; // 3 px glyph + 1 px gap
        for (int r = 0; r < 5; r++) {
            for (int c = 0; c < 3; c++) {
                if (g[r] & (1u << c)) xv_fill(buf, w, h, gx + c, y + r, 1, 1, color);
            }
        }
    }
}

static unsigned xv_bit(const xorview_t* v, int operand, uint16_t bit) {
    return (v->bytes[operand][bit >> 3] >> (7 - (bit & 7))) & 1u;
}

/* Re-derive the merged bit from A and B as the scan reaches it, so the view
 * only ever shows a result that really is A ^ B. */
static void xv_check_bit(const xorview_t* v, uint16_t bit) {
    ASSERT_OR_DIE((xv_bit(v, 0, bit) ^ xv_bit(v, 1, bit)) == xv_bit(v, 2, bit),
                  "bitvis: XOR mismatch at bit %u", (unsigned)bit);
}

/* Redraw one byte block of one operand, clearing its area first. */
static void xv_draw_block(xorview_t* v, int operand, uint16_t index) {
    uint16_t* buf = v->buf[operand];
    if (!buf || index >= v->elen) return;

    lv_coord_t bx = (lv_coord_t)(index % v->cols) * v->block_w;
    lv_coord_t by = (lv_coord_t)(index / v->cols) * v->row_h;
    xv_fill(buf, v->w, v->h, bx, by, v->block_w, v->row_h, XV_BG);

    int32_t first = (int32_t)index * 8;
    xv_hex(buf, v->w, v->h, bx + v->pad, by + 1, v->bytes[operand][index],
           (v->cur >= first && v->cur < first + 8) ? XV_HEX_CUR : XV_HEX);

    // Bits are drawn MSB first, so bit 0 of the byte is the left cell.
    lv_coord_t bit_y = by + 1 + 5 + 2;
    for (int b = 0; b < 8; b++) {
        int32_t  bit      = first + b;
        bool     revealed = (operand != 2) || (v->cur >= bit);
        uint16_t color;
        if (bit == v->cur) {
            color = XV_CUR;
        } else if (!revealed) {
            color = XV_BIT_DIM;
        } else if ((v->bytes[operand][index] >> (7 - b)) & 1u) {
            color = (operand == 2) ? XV_RES_ON : XV_BIT_ON;
        } else {
            color = XV_BIT_OFF;
        }
        xv_fill(buf, v->w, v->h, bx + v->pad + (lv_coord_t)b * (v->cell + v->gap), bit_y, v->cell,
                v->cell, color);
    }
}

static void xv_draw_operand(xorview_t* v, int operand) {
    if (!v->buf[operand]) return;
    xv_fill(v->buf[operand], v->w, v->h, 0, 0, v->w, v->h, XV_BG);
    for (uint16_t i = 0; i < v->elen; i++) xv_draw_block(v, operand, i);
}

static void xv_draw_all(xorview_t* v) {
    for (int op = 0; op < XV_OPERANDS; op++) xv_draw_operand(v, op);
}

static void xv_status(xorview_t* v) {
    if (!v->status) return;
    char text[64];
    if (v->cur < 0) {
        snprintf(text, sizeof(text), "%u bytes   A ^ B", (unsigned)v->elen);
    } else {
        uint16_t bit = (uint16_t)v->cur;
        snprintf(text, sizeof(text), "bit %u/%u:   %u ^ %u = %u", (unsigned)bit + 1,
                 (unsigned)v->total_bits, xv_bit(v, 0, bit), xv_bit(v, 1, bit), xv_bit(v, 2, bit));
    }
    lv_label_set_text(v->status, text);
}

static void xv_tick(lv_timer_t* timer) {
    xorview_t* v = lv_timer_get_user_data(timer);
    if (!v || !v->imgs[0]) return;

    int32_t prev = v->cur;

    if (v->hold > 0) {
        if (--v->hold == 0) { // pass finished: clear the highlight and restart
            v->cur = -1;
            xv_draw_all(v);
            for (int op = 0; op < XV_OPERANDS; op++) {
                if (v->imgs[op]) lv_obj_invalidate(v->imgs[op]);
            }
            xv_status(v);
        }
        return;
    }

    v->cur++;
    if (v->cur >= (int32_t)v->total_bits) {
        v->cur  = (int32_t)v->total_bits - 1; // linger on the last bit
        v->hold = XV_HOLD_TICKS;
    } else {
        xv_check_bit(v, (uint16_t)v->cur); // the bit the scan just reached
    }

    // Only the block the scan left and the one it entered change.
    for (int op = 0; op < XV_OPERANDS; op++) {
        uint16_t now = (uint16_t)(v->cur >> 3);
        if (prev >= 0) {
            uint16_t before = (uint16_t)(prev >> 3);
            xv_draw_block(v, op, before);
            if (before != now) xv_draw_block(v, op, now);
        } else {
            xv_draw_block(v, op, now);
        }
        if (v->imgs[op]) lv_obj_invalidate(v->imgs[op]);
    }
    xv_status(v);
}

static void xv_cleanup(lv_event_t* e) {
    xorview_t* v = lv_event_get_user_data(e);
    if (!v) return;
    if (lv_event_get_target_obj(e) != v->screen) return; // ignore bubbled child deletes
    if (v->timer) {
        lv_timer_delete(v->timer);
        v->timer = NULL;
    }
    for (int i = 0; i < XV_OPERANDS; i++) {
        if (v->buf[i]) {
            secure_memzero(v->buf[i], v->buf_bytes); // entropy bits are secret
            free(v->buf[i]);
            v->buf[i] = NULL;
        }
    }
    secure_memzero(v->bytes, sizeof(v->bytes));
    lv_free(v);
}

void bitvis_add_xor(lv_obj_t* parent, lv_obj_t* screen, const char* a_hex, const char* b_hex,
                    const char* r_hex) {
    ASSERT_OR_DIE(parent && screen, "bitvis: null parent/screen");
    ASSERT_OR_DIE(a_hex && b_hex && r_hex, "bitvis: null hex string");

    size_t elen = strlen(a_hex) / 2;
    ASSERT_OR_DIE(elen > 0 && elen <= XV_MAX_BYTES, "bitvis: bad entropy length (%zu)", elen);
    ASSERT_OR_DIE(strlen(b_hex) == 2 * elen && strlen(r_hex) == 2 * elen,
                  "bitvis: hex strings differ in length");

    xorview_t* v = lv_malloc(sizeof(*v));
    ASSERT_OR_DIE(v, "bitvis: out of memory");
    memset(v, 0, sizeof(*v));
    v->screen = screen;
    v->elen   = (uint16_t)elen;
    ASSERT_OR_DIE(xv_parse_hex(a_hex, v->bytes[0], elen) &&
                      xv_parse_hex(b_hex, v->bytes[1], elen) &&
                      xv_parse_hex(r_hex, v->bytes[2], elen),
                  "bitvis: invalid hex string");

    // Grid of bytes.  Keep blocks at least ~28 px wide so the bits stay
    // visible; on a narrow panel that means fewer columns and more rows.
    lv_coord_t avail = ui_scale(400);
    lv_coord_t cols  = 8;
    while (cols > 4 && avail / cols < 28) cols /= 2;
    lv_coord_t block_w = avail / cols;
    lv_coord_t inset   = ui_scale(2);
    if (inset < 1) inset = 1;
    lv_coord_t gap  = 1;
    lv_coord_t cell = (block_w - 2 * inset - 7 * gap) / 8;
    if (cell < 2) cell = 2;
    lv_coord_t bits_w = 8 * cell + 7 * gap;
    lv_coord_t pad    = (block_w - bits_w) / 2;
    if (pad < 0) pad = 0;

    v->cols       = (uint8_t)cols;
    v->rows       = (uint8_t)((elen + cols - 1) / cols);
    v->cell       = cell;
    v->gap        = gap;
    v->pad        = pad;
    v->block_w    = block_w;
    v->row_h      = 1 + 5 + 2 + cell + ui_scale(4);
    v->w          = block_w * cols;
    v->h          = v->row_h * v->rows;
    v->total_bits = (uint16_t)(elen * 8);
    v->cur        = -1;

    v->buf_bytes = (size_t)v->w * (size_t)v->h * 2u;
    for (int i = 0; i < XV_OPERANDS; i++) {
        v->buf[i] = malloc(v->buf_bytes);
        ASSERT_OR_DIE(v->buf[i], "bitvis: out of memory for %zu-byte buffer", v->buf_bytes);
    }

    lv_obj_t* vis = lv_obj_create(parent);
    lv_obj_set_width(vis, LV_PCT(100));
    lv_obj_set_height(vis, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(vis, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(vis, 0, 0);
    lv_obj_set_style_pad_all(vis, 0, 0);
    lv_obj_set_style_pad_row(vis, ui_scale(3), 0);
    lv_obj_set_flex_flow(vis, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(vis, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    static const char* const names[XV_OPERANDS] = {"Current", "New", "A ^ B"};
    for (int i = 0; i < XV_OPERANDS; i++) {
        lv_obj_t* lbl = lv_label_create(vis);
        lv_label_set_text(lbl, names[i]);
        lv_obj_set_style_text_color(lbl, lv_color_hex(0x888888), 0);
        lv_obj_set_style_text_font(lbl, ui_font(12), 0);

        memset(&v->dsc[i], 0, sizeof(v->dsc[i]));
        v->dsc[i].header.magic  = LV_IMAGE_HEADER_MAGIC;
        v->dsc[i].header.cf     = LV_COLOR_FORMAT_RGB565;
        v->dsc[i].header.w      = (uint16_t)v->w;
        v->dsc[i].header.h      = (uint16_t)v->h;
        v->dsc[i].header.stride = (uint16_t)(v->w * 2);
        v->dsc[i].data_size     = (uint32_t)v->buf_bytes;
        v->dsc[i].data          = (const uint8_t*)v->buf[i];

        lv_obj_t* img = lv_image_create(vis);
        lv_image_set_src(img, &v->dsc[i]);
        lv_obj_set_size(img, v->w, v->h); // 1:1, the buffer is already sized
        v->imgs[i] = img;
    }

    v->status = lv_label_create(vis);
    lv_obj_set_style_text_color(v->status, lv_color_hex(0xCCCCCC), 0);
    lv_obj_set_style_text_font(v->status, ui_font(12), 0);

    xv_draw_all(v);
    xv_status(v);

    lv_obj_add_event_cb(screen, xv_cleanup, LV_EVENT_DELETE, v);
    v->timer = lv_timer_create(xv_tick, XV_TICK_MS, v);
}
