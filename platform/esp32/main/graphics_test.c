/**
 * @file graphics_test.c
 * @brief Graphics test screen - exercises LVGL rendering on the panel.
 */

#include "graphics_test.h"

#include "display.h"
#include "lvgl.h"

static lv_obj_t* make_swatch(lv_obj_t* parent, uint32_t color, lv_coord_t size) {
    lv_obj_t* sw = lv_obj_create(parent);
    lv_obj_set_size(sw, size, size);
    lv_obj_set_style_bg_color(sw, lv_color_hex(color), 0);
    lv_obj_set_style_border_width(sw, 0, 0);
    lv_obj_set_style_radius(sw, 0, 0);
    return sw;
}

lv_obj_t* graphics_test_create(void) {
    lv_obj_t* scr = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x101418), 0);

    // Title
    lv_obj_t* title = lv_label_create(scr);
    lv_label_set_text(title, "GRAPHICS TEST");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_white(), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 2);

    // Color swatches - each solid block verifies RGB565 color ordering
    static const uint32_t colors[] = {
        0xFF0000, 0x00FF00, 0x0000FF, 0xFFFFFF, 0x000000, 0xFFFF00, 0x00FFFF, 0xFF00FF,
    };
    enum { N = sizeof(colors) / sizeof(colors[0]), SW = 26, GAP = 2 };
    lv_coord_t total = N * SW + (N - 1) * GAP;
    lv_coord_t x0    = (DISPLAY_WIDTH - total) / 2;
    for (int i = 0; i < (int)N; i++) {
        lv_obj_t* s = make_swatch(scr, colors[i], SW);
        lv_obj_set_pos(s, x0 + i * (SW + GAP), 30);
    }

    // Arc
    lv_obj_t* arc = lv_arc_create(scr);
    lv_obj_set_size(arc, 72, 72);
    lv_arc_set_value(arc, 68);
    lv_obj_set_style_arc_color(arc, lv_color_hex(0xA6CF5E), LV_PART_INDICATOR);
    lv_obj_align(arc, LV_ALIGN_BOTTOM_LEFT, 4, -24);

    // Rounded rectangle
    lv_obj_t* rect = lv_obj_create(scr);
    lv_obj_set_size(rect, 64, 44);
    lv_obj_set_style_bg_color(rect, lv_color_hex(0x305C2B), 0);
    lv_obj_set_style_radius(rect, 12, 0);
    lv_obj_align(rect, LV_ALIGN_BOTTOM_MID, 0, -26);

    // Exit hint (bottom-left, clear of the Back button the debug screen
    // adds to this screen)
    lv_obj_t* hint = lv_label_create(scr);
    lv_label_set_text(hint, "ENTER / Back to exit");
    lv_obj_set_style_text_color(hint, lv_color_hex(0x888888), 0);
    lv_obj_align(hint, LV_ALIGN_BOTTOM_LEFT, 4, -4);

    return scr;
}
