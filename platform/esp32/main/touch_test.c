/**
 * @file touch_test.c
 * @brief Touchscreen test screen: crosshair plus raw/LVGL coordinate readout.
 *
 * Shows both coordinate pairs: `ctrl` is what the controller reported, `lvgl`
 * what the pointer device receives after the SWAP_XY / INVERT_X / INVERT_Y
 * flags. If the crosshair follows the finger the flags are right; if it moves
 * along the wrong axis the printed numbers say which one.
 */

#include "touch_test.h"

#include "display.h"
#include "lvgl.h"
#include "touchscreen.h"

#include <stdio.h>

#define CROSS_ARM 20 /* half-length of the crosshair arms, in pixels */
#define CROSS_DOT 8

static lv_obj_t* s_scr   = NULL;
static lv_obj_t* s_bar_h = NULL;
static lv_obj_t* s_bar_v = NULL;
static lv_obj_t* s_dot   = NULL;
static lv_obj_t* s_ctrl  = NULL;
static lv_obj_t* s_lvgl  = NULL;

static lv_obj_t* make_block(lv_obj_t* parent, lv_coord_t w, lv_coord_t h, uint32_t color) {
    lv_obj_t* obj = lv_obj_create(parent);
    lv_obj_set_size(obj, w, h);
    lv_obj_set_style_bg_color(obj, lv_color_hex(color), 0);
    lv_obj_set_style_border_width(obj, 0, 0);
    lv_obj_set_style_radius(obj, 0, 0);
    lv_obj_set_style_pad_all(obj, 0, 0);
    lv_obj_clear_flag(obj, LV_OBJ_FLAG_SCROLLABLE);
    return obj;
}

lv_obj_t* touch_test_create(void) {
    s_scr = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(s_scr, lv_color_hex(0x101418), 0);
    lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* title = lv_label_create(s_scr);
    lv_label_set_text(title, "TOUCH TEST");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_white(), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 2);

    s_ctrl = lv_label_create(s_scr);
    lv_obj_set_style_text_font(s_ctrl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_ctrl, lv_color_hex(0x888888), 0);
    lv_obj_align(s_ctrl, LV_ALIGN_TOP_LEFT, 4, 20);

    s_lvgl = lv_label_create(s_scr);
    lv_obj_set_style_text_font(s_lvgl, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_lvgl, lv_color_hex(0xA6CF5E), 0);
    lv_obj_align(s_lvgl, LV_ALIGN_TOP_LEFT, 4, 38);

    // Crosshair last so it draws over the labels.
    s_bar_h = make_block(s_scr, CROSS_ARM * 2, 2, 0xA6CF5E);
    s_bar_v = make_block(s_scr, 2, CROSS_ARM * 2, 0xA6CF5E);
    s_dot   = make_block(s_scr, CROSS_DOT, CROSS_DOT, 0x555555);
    lv_obj_set_style_radius(s_dot, LV_RADIUS_CIRCLE, 0);

    return s_scr;
}

void touch_test_update(void) {
    // Skip unless this screen is active.
    if (!s_scr || lv_screen_active() != s_scr) {
        return;
    }

    touchscreen_debug_t st;
    touchscreen_debug_get(&st);

    if (!st.present) {
        lv_label_set_text(s_ctrl, "no touchscreen");
        lv_label_set_text(s_lvgl, "");
        lv_obj_add_flag(s_bar_h, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(s_bar_v, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(s_dot, LV_OBJ_FLAG_HIDDEN);
        return;
    }

    lv_obj_clear_flag(s_bar_h, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(s_bar_v, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(s_dot, LV_OBJ_FLAG_HIDDEN);

    char buf[48];
    snprintf(buf, sizeof(buf), "ctrl  x=%3u y=%3u n=%u", (unsigned)st.raw_x, (unsigned)st.raw_y,
             (unsigned)st.points);
    lv_label_set_text(s_ctrl, buf);

    snprintf(buf, sizeof(buf), "lvgl  x=%3u y=%3u %s", (unsigned)st.x, (unsigned)st.y,
             st.pressed ? "DOWN" : "up");
    lv_label_set_text(s_lvgl, buf);

    // Keep the whole crosshair on screen: at x=0 half of it would be off view.
    lv_coord_t x = (lv_coord_t)st.x;
    lv_coord_t y = (lv_coord_t)st.y;
    if (x < CROSS_ARM) {
        x = CROSS_ARM;
    }
    if (x > DISPLAY_WIDTH - CROSS_ARM) {
        x = DISPLAY_WIDTH - CROSS_ARM;
    }
    if (y < CROSS_ARM) {
        y = CROSS_ARM;
    }
    if (y > DISPLAY_HEIGHT - CROSS_ARM) {
        y = DISPLAY_HEIGHT - CROSS_ARM;
    }

    lv_obj_set_pos(s_bar_h, x - CROSS_ARM, y - 1);
    lv_obj_set_pos(s_bar_v, x - 1, y - CROSS_ARM);
    lv_obj_set_pos(s_dot, x - CROSS_DOT / 2, y - CROSS_DOT / 2);
    lv_obj_set_style_bg_color(s_dot, lv_color_hex(st.pressed ? 0xFF4444 : 0x555555), 0);
}
