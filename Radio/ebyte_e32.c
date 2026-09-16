#include "ebyte_e32.h"

#include "hardware/gpio.h"
#include "pico/stdlib.h"



#define CMD_READ   0xC1
#define CMD_WRITE  0xC0



void e32_init(
    e32_t *dev,
    uart_inst_t *uart,
    uint tx,
    uint rx,
    uint m0,
    uint m1
)
{

    dev->uart = uart;

    dev->m0_pin=m0;
    dev->m1_pin=m1;


    uart_init(uart,9600);


    gpio_set_function(tx,GPIO_FUNC_UART);
    gpio_set_function(rx,GPIO_FUNC_UART);



    gpio_init(m0);
    gpio_init(m1);

    gpio_set_dir(m0,GPIO_OUT);
    gpio_set_dir(m1,GPIO_OUT);



    e32_set_mode(dev,E32_MODE_NORMAL);

}




void e32_set_mode(
    e32_t *dev,
    e32_mode_t mode
)
{

    switch(mode)
    {


    case E32_MODE_NORMAL:

        gpio_put(dev->m0_pin,0);
        gpio_put(dev->m1_pin,0);

        break;



    case E32_MODE_WAKEUP:

        gpio_put(dev->m0_pin,1);
        gpio_put(dev->m1_pin,0);

        break;



    case E32_MODE_POWER_SAVE:

        gpio_put(dev->m0_pin,0);
        gpio_put(dev->m1_pin,1);

        break;



    case E32_MODE_SLEEP:

        gpio_put(dev->m0_pin,1);
        gpio_put(dev->m1_pin,1);

        break;

    }


    sleep_ms(20);

}







void e32_send(
    e32_t *dev,
    uint8_t *data,
    uint16_t length
)
{

    uart_write_blocking(
        dev->uart,
        data,
        length
    );

}






int e32_receive(
    e32_t *dev,
    uint8_t *buffer,
    uint16_t length
)
{

    int count=0;


    while(uart_is_readable(dev->uart)
          && count<length)
    {

        buffer[count++]=uart_getc(dev->uart);

    }


    return count;

}








void e32_send_fixed(
    e32_t *dev,
    uint16_t address,
    uint8_t channel,
    uint8_t *data,
    uint16_t length
)
{

    uint8_t packet[512];


    packet[0]=address>>8;
    packet[1]=address&0xFF;

    packet[2]=channel;


    for(int i=0;i<length;i++)
    {
        packet[i+3]=data[i];
    }


    uart_write_blocking(
        dev->uart,
        packet,
        length+3
    );

}







void e32_send_broadcast(
    e32_t *dev,
    uint8_t *data,
    uint16_t length
)
{


    e32_send_fixed(
        dev,
        0xFFFF,
        0,
        data,
        length
    );


}







void e32_read_config(
    e32_t *dev,
    uint8_t *config
)
{


    e32_set_mode(
        dev,
        E32_MODE_SLEEP
    );


    uint8_t cmd[3];


    cmd[0]=CMD_READ;
    cmd[1]=0;
    cmd[2]=6;



    uart_write_blocking(
        dev->uart,
        cmd,
        3
    );


    sleep_ms(50);



    uart_read_blocking(
        dev->uart,
        config,
        6
    );


}








void e32_write_config(
    e32_t *dev,
    uint16_t address,
    uint8_t channel
)
{


    e32_set_mode(
        dev,
        E32_MODE_SLEEP
    );


    uint8_t cfg[6];


    cfg[0]=CMD_WRITE;


    cfg[1]=address>>8;
    cfg[2]=address&0xFF;


    cfg[3]=0x44;   // default UART/air settings


    cfg[4]=channel;


    cfg[5]=0x00;



    uart_write_blocking(
        dev->uart,
        cfg,
        6
    );


    sleep_ms(100);


    e32_set_mode(
        dev,
        E32_MODE_NORMAL
    );

}