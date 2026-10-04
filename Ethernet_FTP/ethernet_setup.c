#include "ethernet_setup.h"
#include "wizchip_conf.h"
#include "socket.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "hardware/gpio.h"

static ethernet_w5500_config_t w5500_config;

#define HTTP_SOCKET 2
#define HTTP_PORT 80

static void ftp_data_cb(uint8_t *data, uint16_t len)
{
    for (uint16_t i = 0; i < len; ++i) {
        putchar(data[i]);
    }
}

static const char http_response[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<!doctype html><html><head><title>Pico Server</title></head>"
    "<body><h1>Hello World!</h1><p>Served from a W5500</p></body></html>";

static void wizchip_select(void)
{
    gpio_put(w5500_config.cs_pin, 0);
}

static void wizchip_deselect(void)
{
    gpio_put(w5500_config.cs_pin, 1);
}

static uint8_t wizchip_read_byte(void)
{
    uint8_t value = 0;
    spi_read_blocking(w5500_config.spi, 0x00, &value, 1);
    return value;
}

static void wizchip_write_byte(uint8_t value)
{
    spi_write_blocking(w5500_config.spi, &value, 1);
}

static void wizchip_read_burst(uint8_t *buf, uint16_t len)
{
    spi_read_blocking(w5500_config.spi, 0x00, buf, len);
}

static void wizchip_write_burst(uint8_t *buf, uint16_t len)
{
    spi_write_blocking(w5500_config.spi, buf, len);
}

void init_w5500(const ethernet_w5500_config_t *config)
{
    if (config == NULL || config->spi == NULL) {
        printf("Invalid W5500 configuration\n");
        return;
    }

    w5500_config = *config;

    stdio_init_all();
    sleep_ms(1000);

    spi_init(config->spi, 20 * 1000 * 1000);
    gpio_set_function(config->miso_pin, GPIO_FUNC_SPI);
    gpio_set_function(config->sck_pin, GPIO_FUNC_SPI);
    gpio_set_function(config->mosi_pin, GPIO_FUNC_SPI);

    gpio_init(config->cs_pin);
    gpio_set_dir(config->cs_pin, GPIO_OUT);
    gpio_put(config->cs_pin, 1);

    gpio_init(config->reset_pin);
    gpio_set_dir(config->reset_pin, GPIO_OUT);
    gpio_put(config->reset_pin, 0);
    sleep_ms(100);
    gpio_put(config->reset_pin, 1);
    sleep_ms(100);

    reg_wizchip_cs_cbfunc(wizchip_select, wizchip_deselect);
    reg_wizchip_spi_cbfunc(wizchip_read_byte, wizchip_write_byte);
    reg_wizchip_spiburst_cbfunc(wizchip_read_burst, wizchip_write_burst);

    uint8_t txsize[8] = {2, 2, 2, 2, 2, 2, 2, 2};
    uint8_t rxsize[8] = {2, 2, 2, 2, 2, 2, 2, 2};

    if (wizchip_init(txsize, rxsize) != 0) {
        printf("W5500 init failed\n");
        while (1) tight_loop_contents();
    }

    wiz_NetInfo netinfo = {
        .mac = {0x00, 0x08, 0xDC, 0x11, 0x22, 0x33},
        .ip = {192, 168, 12, 200},
        .sn = {255, 255, 255, 0},
        .gw = {192, 168, 12, 1},
        .dns = {8, 8, 8, 8},
        .dhcp = NETINFO_STATIC
    };

    ctlnetwork(CN_SET_NETINFO, &netinfo);
    printf("W5500 ready\n");

    http_server_init();
}

void http_server_init(void)
{
    int8_t result = socket(HTTP_SOCKET, Sn_MR_TCP, HTTP_PORT, 0);
    if (result < 0) {
        printf("HTTP socket open failed: %d\n", result);
        return;
    }

    if (listen(HTTP_SOCKET) != SOCK_OK) {
        printf("HTTP socket listen failed\n");
        return;
    }

    printf("HTTP server listening on port %u\n", HTTP_PORT);
}

void http_server_poll(void)
{
    switch (getSn_SR(HTTP_SOCKET)) {
    case SOCK_ESTABLISHED:
        if (getSn_RX_RSR(HTTP_SOCKET) > 0) {
            uint8_t buffer[512];
            int32_t received = recv(HTTP_SOCKET, buffer, sizeof(buffer));
            if (received > 0) {
                printf("HTTP request: %.*s\n", (int)received, (char *)buffer);
                int32_t sent = send(HTTP_SOCKET, (uint8_t *)http_response,
                                   sizeof(http_response) - 1);
                if (sent <= 0) {
                    printf("HTTP response send failed: %ld\n", (long)sent);
                }
                disconnect(HTTP_SOCKET);
            }
        }
        break;

    case SOCK_CLOSE_WAIT:
        disconnect(HTTP_SOCKET);
        break;

    case SOCK_CLOSED:
        http_server_init();
        break;

    default:
        break;
    }
}
