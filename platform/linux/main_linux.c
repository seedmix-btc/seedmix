/**
 * @file platform/linux/main_linux.c
 * @brief Linux SDL2 entry point - initializes LVGL with SDL backend and
 *        runs the shared application main loop.
 */

#include "app.h"
#include "lv_sdl_mouse.h"
#include "lv_sdl_mousewheel.h"
#include "lv_sdl_window.h"
#include "lvgl.h"
#include "ui.h"
#include <SDL2/SDL.h>

#ifdef ENABLE_BUTTONS
#include "buttons_linux.h"
#else
#include "lv_sdl_keyboard.h"
#endif

/* -- Display configuration -------------------------------------------- */
#ifdef ENABLE_TDISPLAY
#define DISPLAY_WIDTH 240
#define DISPLAY_HEIGHT 135
#else
#define DISPLAY_WIDTH 480
#define DISPLAY_HEIGHT 320
#endif

/* -- SDL tick callback ------------------------------------------------ */
static uint32_t sdl_tick_cb(void) { return SDL_GetTicks(); }

/* -- Entry point ------------------------------------------------------ */
int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    lv_init();

    /* Use SDL_GetTicks as the LVGL tick source */
    lv_tick_set_cb(sdl_tick_cb);

    /* Create SDL window + display (LVGL v9 built-in) */
    lv_display_t* disp = lv_sdl_window_create(DISPLAY_WIDTH, DISPLAY_HEIGHT);
    lv_sdl_window_set_title(disp, "Entropy");

    /* Register input devices */
    lv_sdl_mouse_create();
#ifdef ENABLE_BUTTONS
    buttons_linux_init();
    ui_nav_set_indev(buttons_linux_get_indev());
#else
    lv_sdl_keyboard_create();
#endif
    lv_sdl_mousewheel_create();

    /* Run the application */
    app_init();

    while (1) {
        lv_timer_handler();
        SDL_Delay(5);
    }

    return 0;
}
