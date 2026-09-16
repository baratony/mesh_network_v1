#ifndef ETHERNET_SETUP_H
#define ETHERNET_SETUP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "hardware/spi.h"

typedef struct {
	spi_inst_t *spi;
	uint miso_pin;
	uint cs_pin;
	uint sck_pin;
	uint mosi_pin;
	uint reset_pin;
} ethernet_w5500_config_t;

/**
 * Initialize the W5500 Ethernet controller and configure its network settings.
 *
 * This function initializes the configured Pico SPI peripheral, resets the
 * W5500, installs the WIZnet SPI callbacks, and applies the static network
 * configuration.
 */
void init_w5500(const ethernet_w5500_config_t *config);

#ifdef __cplusplus
}
#endif

#endif
