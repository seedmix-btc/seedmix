/**
 * @file main/ui/mnemonic_view.c
 * @brief Reusable numbered-grid view for displaying a BIP39 mnemonic.
 */

#include "mnemonic_view.h"
#include "bitvis.h"
#include "ui_internal.h"
#include "util/error.h"
#include "util/utils.h"
#include <stdio.h>
#include <string.h>

#define MNEMONIC_VIEW_MAX_WORDS 24
#define MNEMONIC_VIEW_COLS_LARGE 4
#define MNEMONIC_VIEW_COLS_SMALL 2
#define MNEMONIC_VIEW_ROW_H 30
#define MNEMONIC_VIEW_ROW_H_BITS 46 // a word line and a row of source bits

// One block per word box, for the mnemonics that carry their bits. Static: the
// blocks have to outlive the screen the grid is placed on.
static bitvis_roll_t view_roll[MNEMONIC_VIEW_MAX_WORDS];

// A transparent row to lay labels out in.
static lv_obj_t* mnemonic_view_row(lv_obj_t* parent) {
    lv_obj_t* row = lv_obj_create(parent);
    lv_obj_set_size(row, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_set_style_pad_all(row, 0, 0);
    lv_obj_set_style_pad_column(row, ui_scale(3), 0);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    return row;
}

typedef struct {
    int32_t* col_dsc;
    int32_t* row_dsc;
} mnemonic_view_dscs_t;

static void mnemonic_view_dscs_free(lv_obj_t* view) {
    mnemonic_view_dscs_t* d = (mnemonic_view_dscs_t*)lv_obj_get_user_data(view);
    if (!d) return;
    if (d->col_dsc) lv_free(d->col_dsc);
    if (d->row_dsc) lv_free(d->row_dsc);
    lv_free(d);
    lv_obj_set_user_data(view, NULL);
}

static void mnemonic_view_delete_cb(lv_event_t* e) {
    mnemonic_view_dscs_free(lv_event_get_target(e));
}

/* -- Public API ------------------------------------------------------- */
lv_obj_t* ui_mnemonic_view_create(lv_obj_t* parent) {
    ASSERT_OR_DIE(parent, "null parent");

    lv_obj_t* view = lv_obj_create(parent);
    lv_obj_set_size(view, ui_scale(460), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_color(view, lv_color_hex(0x111111), 0);
    lv_obj_set_style_border_width(view, 0, 0);
    lv_obj_set_style_pad_all(view, 4, 0);
    lv_obj_set_style_pad_row(view, 2, 0);
    lv_obj_set_style_pad_column(view, 2, 0);
    lv_obj_clear_flag(view, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_event_cb(view, mnemonic_view_delete_cb, LV_EVENT_DELETE, NULL);
    return view;
}

void ui_mnemonic_view_set_words(lv_obj_t* view, const char* words, const mnemonic_bits_t* bits) {
    ASSERT_OR_DIE(view, "null view");
    ASSERT_OR_DIE(words, "null words");

    lv_obj_clean(view);

    // The source bits are optional; without them a box is just a numbered word.
    const bool with_bits = bits && bits->entropy && bits->indices &&
                           (bits->entropy_len == 16 || bits->entropy_len == 32);

    /* Tokenize into a local array.  lv_label_set_text() copies the text, so
     * pointers into this buffer are only needed while building the cells. */
    char buf[512];
    strncpy(buf, words, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    const char* word[MNEMONIC_VIEW_MAX_WORDS];
    size_t      count   = 0;
    char*       saveptr = NULL;
    for (char* tok = strtok_r(buf, " \t\n", &saveptr); tok && count < MNEMONIC_VIEW_MAX_WORDS;
         tok       = strtok_r(NULL, " \t\n", &saveptr)) {
        word[count++] = tok;
    }

    if (count == 0) return;

    unsigned cols = ui_small_screen() ? MNEMONIC_VIEW_COLS_SMALL : MNEMONIC_VIEW_COLS_LARGE;
    unsigned rows = (unsigned)((count + cols - 1) / cols);

    /* Grid template: equal-width columns, fixed-height rows. */
    mnemonic_view_dscs_t* d = (mnemonic_view_dscs_t*)lv_obj_get_user_data(view);
    if (!d) {
        d = lv_malloc(sizeof(*d));
        ASSERT_OR_DIE(d, "mnemonic grid descriptor ctx alloc");
        d->col_dsc = NULL;
        d->row_dsc = NULL;
        lv_obj_set_user_data(view, d);
    }
    if (d->col_dsc) lv_free(d->col_dsc);
    if (d->row_dsc) lv_free(d->row_dsc);

    d->col_dsc = lv_malloc(sizeof(int32_t) * (cols + 1));
    d->row_dsc = lv_malloc(sizeof(int32_t) * (rows + 1));
    ASSERT_OR_DIE(d->col_dsc && d->row_dsc, "mnemonic grid descriptor alloc");

    for (unsigned c = 0; c < cols; c++) d->col_dsc[c] = LV_GRID_FR(1);
    d->col_dsc[cols] = LV_GRID_TEMPLATE_LAST;
    for (unsigned r = 0; r < rows; r++)
        d->row_dsc[r] = ui_scale(with_bits ? MNEMONIC_VIEW_ROW_H_BITS : MNEMONIC_VIEW_ROW_H);
    d->row_dsc[rows] = LV_GRID_TEMPLATE_LAST;

    lv_obj_set_grid_dsc_array(view, d->col_dsc, d->row_dsc);

    for (size_t i = 0; i < count; i++) {
        unsigned col = (unsigned)(i % cols);
        unsigned row = (unsigned)(i / cols);

        lv_obj_t* cell = lv_obj_create(view);
        lv_obj_clear_flag(cell, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_set_style_bg_color(cell, lv_color_hex(0x1c1c1c), 0);
        lv_obj_set_style_border_width(cell, 0, 0);
        lv_obj_set_style_radius(cell, 2, 0);
        lv_obj_set_style_pad_hor(cell, 3, 0);
        lv_obj_set_style_pad_ver(cell, 1, 0);
        lv_obj_set_style_pad_column(cell, 3, 0);
        if (with_bits) {
            // Two lines: the numbered word, then the bits it was cut from.
            lv_obj_set_style_pad_row(cell, ui_scale(2), 0);
            lv_obj_set_flex_flow(cell, LV_FLEX_FLOW_COLUMN);
            lv_obj_set_flex_align(cell, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START,
                                  LV_FLEX_ALIGN_CENTER);
        } else {
            lv_obj_set_flex_flow(cell, LV_FLEX_FLOW_ROW);
            lv_obj_set_flex_align(cell, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                                  LV_FLEX_ALIGN_CENTER);
        }
        lv_obj_set_grid_cell(cell, LV_GRID_ALIGN_STRETCH, (int32_t)col, 1, LV_GRID_ALIGN_STRETCH,
                             (int32_t)row, 1);

        lv_obj_t* head = with_bits ? mnemonic_view_row(cell) : cell;

        char num[12];
        int  res = snprintf(num, sizeof(num), "%u.", (unsigned)(i + 1));
        ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(num), "number too long");
        lv_obj_t* num_lbl = lv_label_create(head);
        lv_label_set_text(num_lbl, num);
        lv_obj_set_style_text_color(num_lbl, lv_color_hex(0x888888), 0);
        lv_obj_set_style_text_font(num_lbl, ui_font(14), 0);
        lv_obj_set_style_min_width(num_lbl, ui_scale(20), 0);

        lv_obj_t* word_lbl = lv_label_create(head);
        lv_label_set_text(word_lbl, word[i]);
        lv_obj_set_style_text_color(word_lbl, lv_color_white(), 0);
        lv_obj_set_style_text_font(word_lbl, ui_font(14), 0);
        lv_label_set_long_mode(word_lbl, LV_LABEL_LONG_DOT);

        if (with_bits) {
            // The eleven bits that pick this word, with the number they make: the
            // last word takes fewer, because the checksum starts in it.
            const bool     last = (i + 1 == count);
            const unsigned n    = last ? 11u - (unsigned)(bits->entropy_len / 4u) : 11u;

            uint8_t win[2];
            utils_bit_window(bits->entropy, 11u * i, n, win);

            lv_obj_t* bit_row = mnemonic_view_row(cell);
            bitvis_roll_create(&view_roll[i], bit_row, lv_obj_get_screen(view), 11);
            bitvis_roll_set(&view_roll[i], "", win, n, n);

            char idx[8];
            res = snprintf(idx, sizeof(idx), "%u", (unsigned)bits->indices[i]);
            ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(idx), "index too long");
            lv_obj_t* idx_lbl = lv_label_create(bit_row);
            lv_label_set_text(idx_lbl, idx);
            lv_obj_set_style_text_font(idx_lbl, ui_font(12), 0);

            // The last word is not all entropy - the checksum shares its bits - so
            // its number and bits are drawn in the seed colour, not the grey.
            lv_obj_set_style_text_color(idx_lbl,
                                        lv_color_hex(last ? UI_COLOR_SEED_GREEN : 0x888888), 0);
            if (last) {
                bitvis_roll_set_colors(&view_roll[i],
                                       lv_color_to_u16(lv_color_hex(UI_COLOR_SEED_GREEN)), 0);
            }
        }
    }

    secure_memzero(buf, sizeof(buf));
}
