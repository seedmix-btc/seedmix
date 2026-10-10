/**
 * @file i2c_bus.c
 * @brief Shared I2C master bus bring-up (see i2c_bus.h).
 */

#include "i2c_bus.h"

#include "esp_log.h"
#include "sdkconfig.h"

static const char* TAG = "i2c_bus";

static i2c_master_bus_handle_t s_bus = NULL;

#if CONFIG_SEEDMIX_I2C_ENABLE
static bool s_init_done = false;
#endif

esp_err_t i2c_bus_init(void) {
#if !CONFIG_SEEDMIX_I2C_ENABLE
    ESP_LOGI(TAG, "shared I2C bus disabled in Kconfig");
    return ESP_OK;
#else
    if (s_init_done) {
        return ESP_OK;
    }

    const i2c_master_bus_config_t cfg = {
        .i2c_port                     = (i2c_port_num_t)CONFIG_SEEDMIX_I2C_PORT,
        .sda_io_num                   = CONFIG_SEEDMIX_I2C_SDA_GPIO,
        .scl_io_num                   = CONFIG_SEEDMIX_I2C_SCL_GPIO,
        .clk_source                   = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt            = 7,
        .flags.enable_internal_pullup = true,
    };

    const esp_err_t err = i2c_new_master_bus(&cfg, &s_bus);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c_new_master_bus failed: %s", esp_err_to_name(err));
        return err;
    }

    s_init_done = true;
    ESP_LOGI(TAG, "I2C%d ready (SDA %d, SCL %d)", CONFIG_SEEDMIX_I2C_PORT,
             CONFIG_SEEDMIX_I2C_SDA_GPIO, CONFIG_SEEDMIX_I2C_SCL_GPIO);
    return ESP_OK;
#endif
}

i2c_master_bus_handle_t i2c_bus_get(void) { return s_bus; }
