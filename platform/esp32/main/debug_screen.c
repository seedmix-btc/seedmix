/**
 * @file debug_screen.c
 * @brief Hardware debug screen: config summary + live button and touch tests.
 *
 * Hold a button while the board boots to get here (see main_esp32.c).  The
 * summary screen lists the sub-tests; each row is tappable, which matters on
 * boards whose button mapping cannot produce ENTER (the Waveshare board has
 * one GPIO button, but a touchscreen).  Every sub-test also has a Back
 * button, and ENTER returns to the summary where it is reachable.
 *
 * Outside a sub-test, pressing a physical button switches to a full-screen
 * "pressed" indicator for as long as the button is held, then returns to the
 * summary screen.
 */

#include "debug_screen.h"

#include "buttons.h"
#include "camera_test.h"
#include "display.h"
#include "graphics_test.h"
#include "keymap.h"
#include "lvgl.h"
#include "sdkconfig.h"
#include "touch_test.h"
#include "touchscreen.h"

#include <stdio.h>

/* Full-screen sub-test currently on display (SUB_NONE = summary screen). */
typedef enum {
    SUB_NONE = 0,
    SUB_GFX,
    SUB_TOUCH,
    SUB_CAMERA,
} sub_screen_t;

static lv_obj_t*    s_debug_scr      = NULL;
static lv_obj_t*    s_pressed_scr    = NULL;
static lv_obj_t*    s_pressed_label  = NULL;
static lv_obj_t*    s_gfx_scr        = NULL;
static lv_obj_t*    s_touch_scr      = NULL;
static lv_obj_t*    s_camera_scr     = NULL;
static sub_screen_t s_sub            = SUB_NONE;
static bool         s_pressed_active = false;
static uint32_t     s_last_enter_ms  = 0;
static lv_key_t     s_prev_key       = 0;

static const char* lv_key_name(uint32_t key) {
    switch (key) {
    case LV_KEY_ENTER:
        return "ENTER";
    case LV_KEY_NEXT:
        return "NEXT";
    case LV_KEY_PREV:
        return "PREV";
    case LV_KEY_ESC:
        return "ESC";
    case LV_KEY_UP:
        return "UP";
    case LV_KEY_DOWN:
        return "DOWN";
    case LV_KEY_LEFT:
        return "LEFT";
    case LV_KEY_RIGHT:
        return "RIGHT";
    case LV_KEY_HOME:
        return "HOME";
    case LV_KEY_END:
        return "END";
    default:
        return "?";
    }
}

/* -- Sub-screen plumbing ----------------------------------------------- */
static void leave_sub_screen(void) {
    s_sub           = SUB_NONE;
    s_last_enter_ms = 0;
    lv_screen_load(s_debug_scr);
}

static void enter_sub_screen(sub_screen_t sub) {
    s_sub = sub;
    switch (sub) {
    case SUB_TOUCH:
        lv_screen_load(s_touch_scr);
        break;
    case SUB_CAMERA:
        lv_screen_load(s_camera_scr);
        break;
    default:
        lv_screen_load(s_gfx_scr);
        break;
    }
}

static void back_btn_cb(lv_event_t* e) {
    (void)e;
    leave_sub_screen();
}

/* Every sub-test gets one: on the Waveshare board ENTER is unreachable from
 * the single GPIO button, so the touchscreen is the only way back. */
static void add_back_button(lv_obj_t* scr) {
    lv_obj_t* btn = lv_button_create(scr);
    lv_obj_set_size(btn, 76, 30);
    lv_obj_align(btn, LV_ALIGN_BOTTOM_RIGHT, -4, -4);
    lv_obj_add_event_cb(btn, back_btn_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t* label = lv_label_create(btn);
    lv_label_set_text(label, "Back");
    lv_obj_center(label);
}

static void test_btn_cb(lv_event_t* e) {
    enter_sub_screen((sub_screen_t)(intptr_t)lv_event_get_user_data(e));
}

static void add_test_button(lv_obj_t* parent, const char* text, sub_screen_t sub) {
    lv_obj_t* btn = lv_button_create(parent);
    lv_obj_set_size(btn, 86, 30);
    lv_obj_add_event_cb(btn, test_btn_cb, LV_EVENT_CLICKED, (void*)(intptr_t)sub);

    lv_obj_t* label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_obj_center(label);
}

/* Switch screens based on the current logical key (debounced). */
static void debug_poll_cb(lv_timer_t* t) {
    (void)t;

    lv_key_t key = keymap_current_key();

    if (s_sub != SUB_NONE) {
        /* Inside a sub-test: keep it live and let ENTER (or the Back
         * button) return to the summary. */
        if (s_sub == SUB_TOUCH) {
            touch_test_update();
        } else if (s_sub == SUB_CAMERA) {
            camera_test_update();
        }
        if (key == LV_KEY_ENTER && s_prev_key != LV_KEY_ENTER) {
            leave_sub_screen();
        }
        s_prev_key = key;
        return;
    }

    /* ENTER twice in quick succession activates the graphics test. */
    if (key == LV_KEY_ENTER && s_prev_key != LV_KEY_ENTER) {
        uint32_t now = lv_tick_get();
        if (now - s_last_enter_ms <= 800) {
            s_last_enter_ms = 0;
            s_prev_key      = key;
            enter_sub_screen(SUB_GFX);
            return;
        }
        s_last_enter_ms = now;
    }
    s_prev_key = key;

    if (key != 0) {
        if (!s_pressed_active) {
            s_pressed_active = true;
            lv_screen_load(s_pressed_scr);
        }
        // Keep the label live so it reflects the current combination
        lv_label_set_text_fmt(s_pressed_label, "PRESSED: %s", lv_key_name(key));
    } else if (s_pressed_active) {
        s_pressed_active = false;
        lv_screen_load(s_debug_scr);
    }
}

void debug_screen_init(void) {
    const char* touch   = touchscreen_is_present() ? "enabled" : "none";
    const char* buttons = "none";
    const char* camera  = "none";
    const char* trng    = "none";
#if CONFIG_SEEDMIX_BUTTONS_ENABLE
    char buttons_buf[16];
    snprintf(buttons_buf, sizeof(buttons_buf), "enabled (%d)", CONFIG_SEEDMIX_BUTTONS_COUNT);
    buttons = buttons_buf;
#endif
#if CONFIG_SEEDMIX_CAMERA_ENABLE
    camera = "enabled";
#endif
#if CONFIG_SEEDMIX_TRNG_SOURCE_HARDWARE
    trng = "HW RNG";
#endif

    /* -- Debug (summary) screen -------------------------------------- */
    s_debug_scr = lv_obj_create(NULL);

    lv_obj_t* info = lv_label_create(s_debug_scr);
    lv_obj_set_style_text_font(info, &lv_font_montserrat_14, 0);
#if CONFIG_SEEDMIX_DISPLAY_DRIVER_NONE
    lv_label_set_text(info, "seedmix ESP32\nheadless (no display)");
#else
    lv_label_set_text_fmt(info,
                          "seedmix ESP32\n"
                          "display %dx%d\n"
                          "touch %s\n"
                          "camera %s\n"
                          "buttons %s\n"
                          "trng %s",
                          DISPLAY_WIDTH, DISPLAY_HEIGHT, touch, camera, buttons, trng);
#endif
    lv_obj_align(info, LV_ALIGN_TOP_LEFT, 4, 4);

    /* -- Sub-test rows ------------------------------------------------ */
    lv_obj_t* row = lv_obj_create(s_debug_scr);
    lv_obj_set_size(row, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_align(row, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(row, 2, 0);
    lv_obj_set_style_pad_column(row, 4, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);

    add_test_button(row, "Graphics", SUB_GFX);
    add_test_button(row, "Touch", SUB_TOUCH);
#if CONFIG_SEEDMIX_CAMERA_ENABLE
    add_test_button(row, "Camera", SUB_CAMERA);
#endif

    /* -- Pressed (hold indicator) screen ------------------------------ */
    s_pressed_scr   = lv_obj_create(NULL);
    s_pressed_label = lv_label_create(s_pressed_scr);
    lv_obj_set_style_text_font(s_pressed_label, &lv_font_montserrat_14, 0);
    lv_label_set_text(s_pressed_label, "PRESSED");
    lv_obj_center(s_pressed_label);

    /* -- Graphics test screen ---------------------------------------- */
    s_gfx_scr = graphics_test_create();
    add_back_button(s_gfx_scr);

    /* -- Touch test screen -------------------------------------------- */
    s_touch_scr = touch_test_create();
    add_back_button(s_touch_scr);

    /* -- Camera test screen ------------------------------------------- */
#if CONFIG_SEEDMIX_CAMERA_ENABLE
    s_camera_scr = camera_test_create();
    add_back_button(s_camera_scr);
#endif

    lv_screen_load(s_debug_scr);

    /* Poll the raw button state to switch screens on press/release. */
    lv_timer_create(debug_poll_cb, 20, NULL);
}
