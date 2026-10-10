/**
 * @file main/ui/bitvis.c
 * @brief Bit-level visualisations (see bitvis.h).
 *
 * Each value is drawn as a grid of byte blocks, every block showing its two
 * hex digits above its eight bits, and a timer walks one bit per tick. The
 * XOR view draws A, B and A ^ B; the entropy view draws a single value whose
 * bits fill in as the scan passes them.
 *
 * The grids are hand-rendered RGB565 buffers so the visual is a few lv_image
 * widgets instead of hundreds of bit objects.
 */

#include "bitvis.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ui_internal.h"
#include "util/error.h"
#include "util/utils.h"

/* Hex glyphs, 3 columns x 5 rows. In each row bit 0 is the left column. */
static const uint8_t s_xv_glyph[16][5] = {
    {7, 5, 5, 5, 7}, {2, 3, 2, 2, 7}, {7, 4, 7, 1, 7}, {7, 4, 7, 4, 7},
    {5, 5, 7, 4, 4}, {7, 1, 7, 4, 7}, {7, 1, 7, 5, 7}, {7, 4, 4, 4, 4},
    {7, 5, 7, 5, 7}, {7, 5, 7, 4, 7}, {7, 5, 7, 5, 5}, {1, 1, 7, 5, 7},
    {7, 1, 1, 1, 7}, {4, 4, 7, 5, 7}, {7, 1, 7, 1, 7}, {7, 1, 7, 1, 1},
};

/* Letters a roll label needs: H/T for a coin flip and '-' as the placeholder. */
static const uint8_t s_xv_glyph_h[5]    = {5, 5, 7, 5, 5};
static const uint8_t s_xv_glyph_t[5]    = {7, 2, 2, 2, 2};
static const uint8_t s_xv_glyph_dash[5] = {0, 0, 7, 0, 0};

static const uint8_t* xv_glyph(char c) {
    if (c >= '0' && c <= '9') return s_xv_glyph[c - '0'];
    if (c >= 'A' && c <= 'F') return s_xv_glyph[c - 'A' + 10];
    if (c >= 'a' && c <= 'f') return s_xv_glyph[c - 'a' + 10];
    if (c == 'H') return s_xv_glyph_h;
    if (c == 'T') return s_xv_glyph_t;
    if (c == '-') return s_xv_glyph_dash;
    return NULL;
}

#define XV_BG 0x0000u      // black
#define XV_BIT_OFF 0x2124u // dark grey: 0 bit
#define XV_BIT_ON 0xFFFFu  // white: 1 bit in an operand
#define XV_BIT_DIM 0x10A2u // nearly black: merged bit not scanned yet
#define XV_RES_ON 0x07E0u  // green: 1 bit in the result
#define XV_CUR 0xFD20u     // orange: the bit being XORed now
#define XV_HEX 0xBDF7u     // light grey: byte value
#define XV_HEX_CUR 0xFFFFu // white: value of the byte being scanned

#define XV_OPERANDS 3   // A, B and the result
#define XV_MAX_BYTES 64 // the widest view: a 256-bit seed, or 512 tapped bits
#define XV_TICK_MS 25u
#define XV_HOLD_TICKS 24 // linger on the finished result
#define XV_BIT_Y 8       // 1 px top margin + 5 px label + 2 px gap
#define XV_LABEL_STEP 4  // 3 px glyph + 1 px gap

typedef struct {
    uint8_t bytes[XV_OPERANDS][XV_MAX_BYTES];
    uint8_t operands;  // 1 (single entropy) or 3 (A, B, A ^ B)
    uint8_t reveal_op; // operand whose bits the scan reveals
    bool    check;     // verify each revealed bit really is A ^ B

    uint16_t elen;
    int32_t  cur;     // bit index being scanned, -1 before it starts
    int32_t  hold;    // ticks left to show the finished result
    int32_t  filled;  // caller-filled bit count, or -1 when the timer drives it
    int32_t  hl_from; // highlighted bit range [hl_from, hl_to)
    int32_t  hl_to;

    bitvis_grid_t* owner; // optional handle whose priv is cleared on delete

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

/* A string in the 3x5 font at (x, y): 3 px glyphs with a 1 px gap. */
static void xv_text(uint16_t* buf, lv_coord_t w, lv_coord_t h, lv_coord_t x, lv_coord_t y,
                    const char* text, uint16_t color) {
    for (lv_coord_t gx = x; *text; text++, gx += XV_LABEL_STEP) {
        const uint8_t* g = xv_glyph(*text);
        if (!g) continue;
        for (int r = 0; r < 5; r++) {
            for (int c = 0; c < 3; c++) {
                if (g[r] & (1u << c)) xv_fill(buf, w, h, gx + c, y + r, 1, 1, color);
            }
        }
    }
}

/* Two hex digits at (x, y), 3x5 pixels each. */
static void xv_hex(uint16_t* buf, lv_coord_t w, lv_coord_t h, lv_coord_t x, lv_coord_t y,
                   uint8_t value, uint16_t color) {
    char text[3];
    snprintf(text, sizeof(text), "%02X", value);
    xv_text(buf, w, h, x, y, text, color);
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
    bool    mark  = (v->hl_to > first && v->hl_from < first + 8);
    // With a caller-filled grid the value is shown only once the byte is whole.
    if (v->filled < 0 || first + 8 <= v->filled) {
        xv_hex(buf, v->w, v->h, bx + v->pad, by + 1, v->bytes[operand][index],
               mark ? XV_HEX_CUR : XV_HEX);
    }

    // Bits are drawn MSB first, so bit 0 of the byte is the left cell.
    lv_coord_t bit_y = by + XV_BIT_Y;
    for (int b = 0; b < 8; b++) {
        int32_t bit = first + b;
        bool    revealed =
            (v->filled >= 0) ? (bit < v->filled) : ((operand != v->reveal_op) || (v->cur >= bit));
        bool     marked = (bit >= v->hl_from && bit < v->hl_to);
        uint16_t color;
        if (!revealed) {
            color = XV_BIT_DIM;
        } else if ((v->bytes[operand][index] >> (7 - b)) & 1u) {
            color = (operand == v->reveal_op) ? XV_RES_ON : XV_BIT_ON;
        } else {
            color = XV_BIT_OFF;
        }
        lv_coord_t cx = bx + v->pad + (lv_coord_t)b * (v->cell + v->gap);
        if (marked && v->cell > 2) {
            // Hollow: an orange frame around the bit's own colour, so a marked
            // bit still reads as a 0 or a 1 rather than an ambiguous block.
            xv_fill(buf, v->w, v->h, cx, bit_y, v->cell, v->cell, XV_CUR);
            xv_fill(buf, v->w, v->h, cx + 1, bit_y + 1, v->cell - 2, v->cell - 2, color);
        } else {
            xv_fill(buf, v->w, v->h, cx, bit_y, v->cell, v->cell, marked ? XV_CUR : color);
        }
    }
}

static void xv_draw_operand(xorview_t* v, int operand) {
    if (!v->buf[operand]) return;
    xv_fill(v->buf[operand], v->w, v->h, 0, 0, v->w, v->h, XV_BG);
    for (uint16_t i = 0; i < v->elen; i++) xv_draw_block(v, operand, i);
}

static void xv_draw_all(xorview_t* v) {
    for (int op = 0; op < v->operands; op++) xv_draw_operand(v, op);
}

static void xv_status(xorview_t* v) {
    if (!v->status) return;
    char text[64];
    if (v->cur < 0) {
        snprintf(text, sizeof(text), "%u bytes   %s", (unsigned)v->elen,
                 v->check ? "A ^ B" : "entropy");
    } else if (v->check) {
        uint16_t bit = (uint16_t)v->cur;
        snprintf(text, sizeof(text), "bit %u/%u:   %u ^ %u = %u", (unsigned)bit + 1,
                 (unsigned)v->total_bits, xv_bit(v, 0, bit), xv_bit(v, 1, bit), xv_bit(v, 2, bit));
    } else {
        uint16_t bit = (uint16_t)v->cur;
        snprintf(text, sizeof(text), "bit %u/%u:   %u", (unsigned)bit + 1, (unsigned)v->total_bits,
                 xv_bit(v, 0, bit));
    }
    lv_label_set_text(v->status, text);
}

static void xv_tick(lv_timer_t* timer) {
    xorview_t* v = lv_timer_get_user_data(timer);
    if (!v || !v->imgs[0]) return;

    int32_t prev = v->cur;

    if (v->hold > 0) {
        if (--v->hold == 0) { // pass finished: clear the highlight and restart
            v->cur     = -1;
            v->hl_from = 0;
            v->hl_to   = 0;
            xv_draw_all(v);
            for (int op = 0; op < v->operands; op++) {
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
    } else if (v->check) {
        xv_check_bit(v, (uint16_t)v->cur); // the bit the scan just reached
    }
    v->hl_from = v->cur; // highlight the bit the scan just reached
    v->hl_to   = v->cur + 1;

    // Only the block the scan left and the one it entered change.
    for (int op = 0; op < v->operands; op++) {
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
    if (v->owner) v->owner->priv = NULL;
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

/* Cell/gap/block metrics, shared with the roll readout so the two line up.
 * Blocks stay at least ~28 px wide so the bits stay visible; on a narrow panel
 * that means fewer columns and more rows. */
static void xv_metrics(lv_coord_t* cols, lv_coord_t* block_w, lv_coord_t* cell, lv_coord_t* gap,
                       lv_coord_t* pad) {
    lv_coord_t avail = ui_scale(400);
    lv_coord_t n     = 8;
    while (n > 4 && avail / n < 28) n /= 2;
    lv_coord_t bw    = avail / n;
    lv_coord_t inset = ui_scale(2);
    if (inset < 1) inset = 1;
    lv_coord_t g = 1;
    lv_coord_t c = (bw - 2 * inset - 7 * g) / 8;
    if (c < 2) c = 2;
    lv_coord_t p = (bw - (8 * c + 7 * g)) / 2;
    if (p < 0) p = 0;

    *cols    = n;
    *block_w = bw;
    *cell    = c;
    *gap     = g;
    *pad     = p;
}

/* Shared builder: @p n_ops grids of @p elen bytes, labelled by @p names (NULL
 * for none). The bits of operand @p reveal_op are revealed by the scan when
 * @p animate is set; otherwise the caller pushes them with bitvis_grid_set().
 * When @p check is set every revealed bit must be the XOR of the first two
 * operands.  @p owner (optional) is cleared when the screen goes away. */
static xorview_t* xv_build(lv_obj_t* parent, lv_obj_t* screen, uint8_t elen, uint8_t n_ops,
                           const char* const* names, uint8_t reveal_op, bool check, bool animate,
                           bitvis_grid_t* owner) {
    ASSERT_OR_DIE(parent && screen, "bitvis: null parent/screen");
    ASSERT_OR_DIE(elen > 0 && elen <= XV_MAX_BYTES, "bitvis: bad entropy length");

    xorview_t* v = lv_malloc(sizeof(*v));
    ASSERT_OR_DIE(v, "bitvis: out of memory");
    memset(v, 0, sizeof(*v));
    v->screen    = screen;
    v->operands  = n_ops;
    v->reveal_op = reveal_op;
    v->check     = check;
    v->elen      = elen;
    v->filled    = -1;
    v->cur       = -1;
    v->owner     = owner;
    if (owner) owner->priv = v;

    // Grid of bytes, sized by the metrics the roll readout also uses.
    lv_coord_t cols = 0, block_w = 0, cell = 0, gap = 0, pad = 0;
    xv_metrics(&cols, &block_w, &cell, &gap, &pad);

    v->cols       = (uint8_t)cols;
    v->rows       = (uint8_t)((elen + cols - 1) / cols);
    v->cell       = cell;
    v->gap        = gap;
    v->pad        = pad;
    v->block_w    = block_w;
    v->row_h      = XV_BIT_Y + cell + ui_scale(4);
    v->w          = block_w * cols;
    v->h          = v->row_h * v->rows;
    v->total_bits = (uint16_t)(elen * 8);

    v->buf_bytes = (size_t)v->w * (size_t)v->h * 2u;
    for (uint8_t i = 0; i < v->operands; i++) {
        v->buf[i] = malloc(v->buf_bytes);
        ASSERT_OR_DIE(v->buf[i], "bitvis: out of memory for %zu-byte buffer", v->buf_bytes);
    }

    lv_obj_t* vis = lv_obj_create(parent);
    ui_clickthrough(vis); // a bit view never takes a tap, its box included
    lv_obj_set_width(vis, LV_PCT(100));
    lv_obj_set_height(vis, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(vis, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(vis, 0, 0);
    lv_obj_set_style_pad_all(vis, 0, 0);
    lv_obj_set_style_pad_row(vis, ui_scale(3), 0);
    lv_obj_set_flex_flow(vis, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(vis, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    for (uint8_t i = 0; i < v->operands; i++) {
        if (names) {
            lv_obj_t* lbl = lv_label_create(vis);
            lv_label_set_text(lbl, names[i]);
            lv_obj_set_style_text_color(lbl, lv_color_hex(0x888888), 0);
            lv_obj_set_style_text_font(lbl, ui_font(12), 0);
        }

        memset(&v->dsc[i], 0, sizeof(v->dsc[i]));
        v->dsc[i].header.magic  = LV_IMAGE_HEADER_MAGIC;
        v->dsc[i].header.cf     = LV_COLOR_FORMAT_RGB565;
        v->dsc[i].header.w      = (uint16_t)v->w;
        v->dsc[i].header.h      = (uint16_t)v->h;
        v->dsc[i].header.stride = (uint16_t)(v->w * 2);
        v->dsc[i].data_size     = (uint32_t)v->buf_bytes;
        v->dsc[i].data          = (const uint8_t*)v->buf[i];

        lv_obj_t* img = lv_image_create(vis);
        ui_clickthrough(img); // a bit view never takes a tap
        lv_image_set_src(img, &v->dsc[i]);
        lv_obj_set_size(img, v->w, v->h); // 1:1, the buffer is already sized
        v->imgs[i] = img;
    }

    if (animate) {
        v->status = lv_label_create(vis);
        lv_obj_set_style_text_color(v->status, lv_color_hex(0xCCCCCC), 0);
        lv_obj_set_style_text_font(v->status, ui_font(12), 0);
    }

    lv_obj_add_event_cb(screen, xv_cleanup, LV_EVENT_DELETE, v);
    if (animate) v->timer = lv_timer_create(xv_tick, XV_TICK_MS, v);
    return v;
}

void bitvis_add_xor(lv_obj_t* parent, lv_obj_t* screen, const char* a_hex, const char* b_hex,
                    const char* r_hex) {
    ASSERT_OR_DIE(a_hex && b_hex && r_hex, "bitvis: null hex string");

    size_t elen = strlen(a_hex) / 2;
    ASSERT_OR_DIE(elen > 0 && elen <= XV_MAX_BYTES, "bitvis: bad entropy length (%zu)", elen);
    ASSERT_OR_DIE(strlen(b_hex) == 2 * elen && strlen(r_hex) == 2 * elen,
                  "bitvis: hex strings differ in length");

    static const char* const names[3] = {"Current", "New", "A ^ B"};
    const char*              hexs[3]  = {a_hex, b_hex, r_hex};
    xorview_t* v = xv_build(parent, screen, (uint8_t)elen, 3, names, 2, true, true, NULL);
    for (int i = 0; i < 3; i++) {
        ASSERT_OR_DIE(xv_parse_hex(hexs[i], v->bytes[i], elen), "bitvis: invalid hex string");
    }
    xv_draw_all(v);
    xv_status(v);
}

void bitvis_add_entropy(lv_obj_t* parent, lv_obj_t* screen, const char* hex) {
    ASSERT_OR_DIE(hex, "bitvis: null hex string");

    size_t elen = strlen(hex) / 2;
    ASSERT_OR_DIE(elen > 0 && elen <= XV_MAX_BYTES, "bitvis: bad entropy length (%zu)", elen);

    xorview_t* v = xv_build(parent, screen, (uint8_t)elen, 1, NULL, 0, false, true, NULL);
    ASSERT_OR_DIE(xv_parse_hex(hex, v->bytes[0], elen), "bitvis: invalid hex string");
    xv_draw_all(v);
    xv_status(v);
}

void bitvis_grid_create(bitvis_grid_t* g, lv_obj_t* parent, lv_obj_t* screen, uint32_t total_bits) {
    ASSERT_OR_DIE(g && parent && screen, "bitvis: null argument");
    ASSERT_OR_DIE(total_bits > 0 && total_bits % 8 == 0 && total_bits / 8 <= XV_MAX_BYTES,
                  "bitvis: bad bit count (%u)", (unsigned)total_bits);

    g->priv      = NULL;
    xorview_t* v = xv_build(parent, screen, (uint8_t)(total_bits / 8), 1, NULL, 0, false, false, g);
    xv_draw_all(v);
}

void bitvis_grid_set(bitvis_grid_t* g, const uint8_t* bytes, uint32_t filled_bits,
                     uint32_t highlight_from) {
    if (!g || !g->priv) return; // the screen is gone
    xorview_t* v = g->priv;
    ASSERT_OR_DIE(bytes, "bitvis: null bytes");
    ASSERT_OR_DIE(filled_bits <= v->total_bits, "bitvis: too many filled bits");
    ASSERT_OR_DIE(highlight_from <= filled_bits, "bitvis: bad highlight range");

    memcpy(v->bytes[0], bytes, (filled_bits + 7u) / 8u);
    v->filled  = (int32_t)filled_bits;
    v->hl_from = (int32_t)highlight_from;
    v->hl_to   = (int32_t)filled_bits;
    xv_draw_all(v);
    if (v->imgs[0]) lv_obj_invalidate(v->imgs[0]);
}

/* -- Last-roll readout ------------------------------------------------- */

/* One grid block's worth of chrome for the newest roll: a label where a byte
 * block shows its hex, and the bits the roll produced below it. Same metrics,
 * colours and font as the grid, so it reads as a block of the same visual. */
typedef struct {
    bitvis_roll_t* owner;
    lv_obj_t*      img;
    lv_image_dsc_t dsc;
    uint16_t*      buf;
    size_t         buf_bytes;
    lv_coord_t     w, h, cell, gap, pad;
    unsigned       cells;
    char           label[8];
    lv_obj_t*      screen;
} rollview_t;

/* Wipe the block and draw the label centred over the bit cells. */
static void xrv_chrome(rollview_t* r) {
    xv_fill(r->buf, r->w, r->h, 0, 0, r->w, r->h, XV_BG);

    size_t n = strlen(r->label);
    if (!n) return;
    lv_coord_t lw = (lv_coord_t)n * XV_LABEL_STEP - 1;
    xv_text(r->buf, r->w, r->h, (r->w - lw) / 2, 1, r->label, XV_HEX);
}

static void xrv_cleanup(lv_event_t* e) {
    rollview_t* r = lv_event_get_user_data(e);
    if (!r) return;
    if (lv_event_get_target_obj(e) != r->screen) return; // ignore bubbled child deletes
    if (r->owner) r->owner->priv = NULL;
    if (r->buf) {
        secure_memzero(r->buf, r->buf_bytes); // entropy bits are secret
        free(r->buf);
        r->buf = NULL;
    }
    lv_free(r);
}

void bitvis_roll_create(bitvis_roll_t* h, lv_obj_t* parent, lv_obj_t* screen, unsigned cells) {
    ASSERT_OR_DIE(h && parent && screen, "bitvis: null argument");
    ASSERT_OR_DIE(cells >= 1 && cells <= 8, "bitvis: bad roll cell count (%u)", cells);

    h->priv       = NULL;
    rollview_t* r = lv_malloc(sizeof(*r));
    ASSERT_OR_DIE(r, "bitvis: out of memory");
    memset(r, 0, sizeof(*r));
    r->owner  = h;
    r->screen = screen;
    r->cells  = cells;

    lv_coord_t cols = 0, block_w = 0;
    xv_metrics(&cols, &block_w, &r->cell, &r->gap, &r->pad);
    // Snug around the cells, and as tall as one grid row so the bit rows line up.
    r->w         = (lv_coord_t)cells * r->cell + (lv_coord_t)(cells - 1) * r->gap + 2 * r->pad;
    r->h         = XV_BIT_Y + r->cell + ui_scale(4);
    r->buf_bytes = (size_t)r->w * (size_t)r->h * 2u;
    r->buf       = malloc(r->buf_bytes);
    ASSERT_OR_DIE(r->buf, "bitvis: out of memory for %zu-byte buffer", r->buf_bytes);

    memset(&r->dsc, 0, sizeof(r->dsc));
    r->dsc.header.magic  = LV_IMAGE_HEADER_MAGIC;
    r->dsc.header.cf     = LV_COLOR_FORMAT_RGB565;
    r->dsc.header.w      = (uint16_t)r->w;
    r->dsc.header.h      = (uint16_t)r->h;
    r->dsc.header.stride = (uint16_t)(r->w * 2);
    r->dsc.data_size     = (uint32_t)r->buf_bytes;
    r->dsc.data          = (const uint8_t*)r->buf;

    snprintf(r->label, sizeof(r->label), "--");
    xrv_chrome(r);

    r->img = lv_image_create(parent);
    ui_clickthrough(r->img); // a bit view never takes a tap
    lv_image_set_src(r->img, &r->dsc);
    lv_obj_set_size(r->img, r->w, r->h); // 1:1, the buffer is already sized

    h->priv = r;
    lv_obj_add_event_cb(screen, xrv_cleanup, LV_EVENT_DELETE, r);
}

void bitvis_roll_set(bitvis_roll_t* h, const char* label, const uint8_t* bytes,
                     uint32_t filled_bits, uint32_t nbits) {
    if (!h || !h->priv) return; // the screen is gone
    rollview_t* r = h->priv;
    ASSERT_OR_DIE(label, "bitvis: null roll label");
    ASSERT_OR_DIE(nbits <= filled_bits, "bitvis: bad roll bit count");

    snprintf(r->label, sizeof(r->label), "%s", label);
    xrv_chrome(r);

    // The roll's bits, most significant first; cells past it stay unknown.
    lv_coord_t strip_w = (lv_coord_t)r->cells * r->cell + (lv_coord_t)(r->cells - 1) * r->gap;
    lv_coord_t x       = (r->w - strip_w) / 2;
    lv_coord_t bit_y   = XV_BIT_Y;
    for (unsigned b = 0; b < r->cells; b++) {
        uint16_t color = XV_BIT_DIM;
        if (b < nbits) {
            uint32_t bit = filled_bits - nbits + b;
            color        = ((bytes[bit >> 3] >> (7 - (bit & 7u))) & 1u) ? XV_BIT_ON : XV_BIT_OFF;
        }
        xv_fill(r->buf, r->w, r->h, x + (lv_coord_t)b * (r->cell + r->gap), bit_y, r->cell, r->cell,
                color);
    }
    if (r->img) lv_obj_invalidate(r->img);
}
