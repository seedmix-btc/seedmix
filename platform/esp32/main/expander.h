/**
 * @file expander.h
 * @brief Ownership of the board's TCA9554 IO expander.
 *
 * This is a thin ownership wrapper, not a driver: the panel reset pulse and
 * the Waveshare PWR button both live on the same chip, and the official
 * `espressif/esp_io_expander_tca9554` driver wants one handle for both.  It
 * is created on first use and kept, instead of being created and deleted per
 * operation.
 */

#ifndef SEEDMIX_ESP32_EXPANDER_H
#define SEEDMIX_ESP32_EXPANDER_H

#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create the IO expander handle if it does not exist yet.
 *
 * Idempotent and safe to call from anywhere after i2c_bus_init().  A failed
 * probe is remembered: the chip is either there at boot or it never will be,
 * so later calls do not hammer a dead I2C address.
 */
esp_err_t expander_init(void);

/** @brief True when the IO expander answered and is usable. */
bool expander_available(void);

/**
 * @brief Configure `pin` as an output and drive it.
 *
 * @param pin   Expander pin index (0-7).
 * @param level true for high, false for low.
 */
esp_err_t expander_set_output(int pin, bool level);

/**
 * @brief Configure `pin` as an input and read its level.
 *
 * @param pin Expander pin index (0-7).
 * @param out Receives the level; untouched when the read fails.
 * @return true when the level was read.
 */
bool expander_read(int pin, bool* out);

#ifdef __cplusplus
}
#endif

#endif /* SEEDMIX_ESP32_EXPANDER_H */
