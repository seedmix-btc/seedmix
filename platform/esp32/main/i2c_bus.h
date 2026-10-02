/**
 * @file i2c_bus.h
 * @brief Shared I2C master bus for the ESP32 board peripherals.
 *
 * The I2C bus is shared between the capacitive touchscreen, the TCA9554 IO
 * expander (panel reset / power button), the camera SCCB interface and any
 * onboard IMU/RTC/PMIC.  It is brought up once, from the Kconfig pin
 * assignment, and handed to each peripheral driver.
 */

#ifndef SEEDMIX_ESP32_I2C_BUS_H
#define SEEDMIX_ESP32_I2C_BUS_H

#include <stdbool.h>

#include "driver/i2c_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the shared I2C master bus.
 *
 * Idempotent: calling it twice returns ESP_OK and keeps the existing bus.
 * When the bus is disabled in Kconfig this is a no-op returning ESP_OK and
 * i2c_bus_get() stays NULL.
 */
esp_err_t i2c_bus_init(void);

/**
 * @brief Handle of the shared bus, or NULL when not initialized/disabled.
 */
i2c_master_bus_handle_t i2c_bus_get(void);

#ifdef __cplusplus
}
#endif

#endif /* SEEDMIX_ESP32_I2C_BUS_H */
