/**
 * @file main/ui/log.h
 * @brief Action log ring buffer and state screen.
 */

#ifndef UI_LOG_H
#define UI_LOG_H

#include "lvgl.h"
#include "ui.h"
#include "util/compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

void ui_log_add(const char* fmt, ...) PRINTF_LIKE(1, 2);
/** @brief Show the log with the current entropy above it (@p entropy_hex may be NULL). */
void ui_show_state(ui_cb_t on_back, const char* entropy_hex);

#ifdef __cplusplus
}
#endif

#endif /* UI_LOG_H */
