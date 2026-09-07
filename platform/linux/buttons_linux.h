/**
 * @file platform/linux/buttons_linux.h
 * @brief Button input emulation for the Linux/SDL2 build.
 */

#ifndef SEEDMIX_BUTTONS_LINUX_H
#define SEEDMIX_BUTTONS_LINUX_H

#include "lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Create the encoder input device emulating the ESP32 buttons. */
void buttons_linux_init(void);

/** Get the emulated button input device (NULL before init). */
lv_indev_t* buttons_linux_get_indev(void);

#ifdef __cplusplus
}
#endif

#endif /* SEEDMIX_BUTTONS_LINUX_H */
