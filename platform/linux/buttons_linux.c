/**
 * @file platform/linux/buttons_linux.c
 * @brief Button input emulation for the Linux/SDL2 build.
 *
 * Emulates the ESP32 two-button keypad with a keyboard:
 *   Left arrow            -> LV_KEY_LEFT   (button 0)
 *   Right arrow           -> LV_KEY_RIGHT  (button 1)
 *   Enter / keypad enter / space -> LV_KEY_ENTER (both buttons)
 */

#include "buttons_linux.h"

#include "lvgl.h"
#include <SDL2/SDL.h>

static lv_indev_t* s_indev    = NULL;
static lv_key_t    s_last_key = 0;

static void buttons_read_cb(lv_indev_t* indev, lv_indev_data_t* data) {
    (void)indev;

    const Uint8* keys = SDL_GetKeyboardState(NULL);

    bool left  = keys[SDL_SCANCODE_LEFT] != 0;
    bool right = keys[SDL_SCANCODE_RIGHT] != 0;
    bool enter = keys[SDL_SCANCODE_RETURN] != 0 || keys[SDL_SCANCODE_KP_ENTER] != 0 ||
                 keys[SDL_SCANCODE_SPACE] != 0;

    lv_key_t cur = 0;
    if (enter) {
        cur = LV_KEY_ENTER;
    } else if (left) {
        cur = LV_KEY_LEFT;
    } else if (right) {
        cur = LV_KEY_RIGHT;
    }

    // Mirror the ESP32 keymap
    if (cur != 0) {
        s_last_key  = cur;
        data->state = LV_INDEV_STATE_PRESSED;
    } else {
        data->state = LV_INDEV_STATE_RELEASED;
    }
    data->key = s_last_key;
}

void buttons_linux_init(void) {
    s_indev = lv_indev_create();
    lv_indev_set_type(s_indev, LV_INDEV_TYPE_ENCODER);
    lv_indev_set_read_cb(s_indev, buttons_read_cb);
}

lv_indev_t* buttons_linux_get_indev(void) { return s_indev; }
