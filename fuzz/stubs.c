/**
 * @file fuzz/stubs.c
 * @brief Minimal fatal/hal/log stubs so fuzz targets can link crypto sources.
 *
 * A FATAL during fuzzing aborts, which libFuzzer reports as a crash (a real
 * bug worth investigating).  The HAL random functions are unused by the
 * current fuzz targets but are required to satisfy the linker.
 */

#include "hal.h"
#include "util/error.h"
#include "util/log.h"

#include <stdint.h>
#include <stdlib.h>

NORETURN void fatal_handler(const char* file, int line, const char* fmt, ...) {
    (void)file;
    (void)line;
    (void)fmt;
    abort();
}

void log_msg(const char* level, const char* file, int line, const char* fmt, ...) {
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

const char* hal_get_random_source(void) { return "fuzz"; }

void hal_get_random(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)i;
}
