#ifndef EBYTE_E32_H
#define EBYTE_E32_H


#include <stdint.h>
#include "hardware/uart.h"


typedef enum
{
    E32_MODE_NORMAL = 0,
    E32_MODE_WAKEUP,
    E32_MODE_POWER_SAVE,
    E32_MODE_SLEEP

} e32_mode_t;



typedef struct
{

    uart_inst_t *uart;

    uint m0_pin;
    uint m1_pin;
    uint aux_pin;


} e32_t;



void e32_init(
    e32_t *dev,
    uart_inst_t *uart,
    uint tx,
    uint rx,
    uint m0,
    uint m1s
);



void e32_set_mode(
    e32_t *dev,
    e32_mode_t mode
);



void e32_send(
    e32_t *dev,
    uint8_t *data,
    uint16_t length
);



int e32_receive(
    e32_t *dev,
    uint8_t *buffer,
    uint16_t length
);



void e32_send_fixed(
    e32_t *dev,
    uint16_t address,
    uint8_t channel,
    uint8_t *data,
    uint16_t length
);



void e32_send_broadcast(
    e32_t *dev,
    uint8_t *data,
    uint16_t length
);



void e32_read_config(
    e32_t *dev,
    uint8_t *config
);



void e32_write_config(
    e32_t *dev,
    uint16_t address,
    uint8_t channel
);



#endif