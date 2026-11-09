/**
 * @file main/ui/log.c
 * @brief Action log ring buffer and state screen.
 */

#include "log.h"
#include "bitvis.h"
#include "hal.h"
#include "ui_internal.h"
#include "util/error.h"
#include "util/utils.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* -- Action log ring buffer ------------------------------------------- */
#define LOG_MAX 32
#define LOG_LEN 96
static char log_buf[LOG_MAX][LOG_LEN];
static int  log_head  = 0; // next write position
static int  log_count = 0; // total entries (capped at LOG_MAX)

void ui_log_add(const char* fmt, ...) {
    // Prefix an elapsed-time stamp (uptime HH:MM:SS) to each entry.
    uint32_t t = lv_tick_get();
    unsigned h = (unsigned)(t / 3600000u);
    unsigned m = (unsigned)((t / 60000u) % 60u);
    unsigned s = (unsigned)((t / 1000u) % 60u);

    int prefix = snprintf(log_buf[log_head], LOG_LEN, "[%02u:%02u:%02u] ", h, m, s);

    va_list args;
    va_start(args, fmt);
    vsnprintf(log_buf[log_head] + prefix, LOG_LEN - prefix, fmt, args);
    va_end(args);

    log_head = (log_head + 1) % LOG_MAX;
    if (log_count < LOG_MAX) log_count++;
}

/* -- State screen ----------------------------------------------------- */
// The grid the entropy is drawn in; static because it has to outlive the screen.
static bitvis_grid_t state_grid;

void ui_show_state(ui_cb_t on_back, const char* entropy_hex) {
    ASSERT_OR_DIE(on_back, "null on_back");

    lv_obj_t* s = ui_make_screen();
    ui_add_title(s, "State & Log");

    // Current entropy: the hex, and the same bits drawn as a grid.
    lv_obj_t* ent_area = lv_obj_create(s);
    lv_obj_set_size(ent_area, ui_scale(440), LV_SIZE_CONTENT);
    lv_obj_align(ent_area, LV_ALIGN_TOP_MID, 0, ui_scale(48));
    // Black, because the bit grid is an opaque RGB565 image with a black
    // background, so anything lighter would show it as a box.
    lv_obj_set_style_bg_color(ent_area, lv_color_black(), 0);
    lv_obj_set_style_border_width(ent_area, 0, 0);
    lv_obj_set_style_pad_all(ent_area, ui_scale(4), 0);
    lv_obj_set_style_pad_row(ent_area, ui_scale(4), 0);
    lv_obj_set_flex_flow(ent_area, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(ent_area, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);

    // 16 or 32 bytes, as hex. Anything else is treated as "no entropy yet".
    uint8_t entropy[32];
    size_t  entropy_len = 0;
    if (entropy_hex && entropy_hex[0]) {
        const size_t hex_len = strlen(entropy_hex);
        if ((hex_len == 32 || hex_len == 64) &&
            hex_to_bytes(entropy_hex, hex_len, entropy, sizeof(entropy))) {
            entropy_len = hex_len / 2;
        }
    }

    if (entropy_len) {
        lv_obj_t* lbl = lv_label_create(ent_area);
        lv_label_set_text(lbl, "Current entropy:");
        lv_obj_set_style_text_color(lbl, lv_color_hex(0x888888), 0);
        lv_obj_set_style_text_font(lbl, ui_font(12), 0);

        lv_obj_t* val = lv_label_create(ent_area);
        lv_label_set_text(val, entropy_hex);
        lv_obj_set_style_text_color(val, lv_color_white(), 0);
        lv_obj_set_style_text_font(val, ui_font(12), 0);
        lv_obj_set_width(val, ui_scale(424));
        lv_label_set_long_mode(val, LV_LABEL_LONG_WRAP);

        const uint32_t bits = (uint32_t)entropy_len * 8u;
        bitvis_grid_create(&state_grid, ent_area, s, bits);
        bitvis_grid_set(&state_grid, entropy, bits, bits);
    } else {
        lv_obj_t* lbl = lv_label_create(ent_area);
        lv_label_set_text(lbl, "(no entropy yet)");
        lv_obj_set_style_text_color(lbl, lv_color_hex(0x888888), 0);
        lv_obj_set_style_text_font(lbl, ui_font(18), 0);
    }
    secure_memzero(entropy, sizeof(entropy));
    lv_obj_update_layout(ent_area);

    // log entries (oldest first, top to bottom)
    lv_obj_t* log_cont = lv_obj_create(s);
    lv_obj_set_style_bg_color(log_cont, lv_color_hex(0x111111), 0);
    lv_obj_set_style_border_width(log_cont, 0, 0);
    lv_obj_set_flex_flow(log_cont, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(log_cont, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
    lv_obj_set_scroll_dir(log_cont, LV_DIR_VER);

    int start = (log_count < LOG_MAX) ? 0 : log_head;
    for (int i = 0; i < log_count; i++) {
        int idx = (start + i) % LOG_MAX;
        if (!log_buf[idx][0]) continue;
        lv_obj_t* entry = lv_label_create(log_cont);
        lv_label_set_text(entry, log_buf[idx]);
        lv_obj_set_style_text_color(entry, lv_color_hex(0xAAAAAA), 0);
        lv_obj_set_style_text_font(entry, ui_font(14), 0);
        lv_label_set_long_mode(entry, LV_LABEL_LONG_WRAP);
        lv_obj_set_width(entry, ui_scale(420));
    }

    // Fit the log between the entropy area and the back button.
    lv_coord_t mn_bottom = lv_obj_get_y(ent_area) + lv_obj_get_height(ent_area);
    lv_coord_t log_top   = mn_bottom + ui_scale(8);
    lv_coord_t log_h =
        (LV_VER_RES - ui_scale(10) - ui_scale(44)) - ui_scale(8) - log_top; /* above back button */
    if (log_h < 40) log_h = 40;
    lv_obj_set_size(log_cont, ui_scale(440), log_h);
    lv_obj_align(log_cont, LV_ALIGN_TOP_MID, 0, log_top);

    if (!hal_touch_available()) {
        lv_obj_t* arrows = ui_add_scroll_arrows(s, log_cont, ui_scale(24));
        lv_obj_align_to(arrows, log_cont, LV_ALIGN_OUT_RIGHT_MID, ui_scale(4), 0);
    }

    // back button
    ui_add_btn(s, "Back", on_back, UI_BTN_SIZE_MED, LV_ALIGN_BOTTOM_MID, 0, -10);

    ui_swap_screen(s);
}
