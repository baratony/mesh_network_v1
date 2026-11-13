#include "ebyte_e32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/uart.h"


e32_t radio;



int main()
{

    stdio_init_all();


    gpio_init(6);
    gpio_init(7);

    // 2. Set the direction of both pins to output
    gpio_set_dir(6, GPIO_OUT);
    gpio_set_dir(7, GPIO_OUT);

    // 3. Drive both pins low (GND / 0V)
    gpio_put(6, 0);
    gpio_put(7, 0);


    e32_init(
        &radio,
        uart0,
        0,   // TX
        1,
        6,
        7   // RX
    );


    uint8_t read_config[6] = {0};
    printf("Reading radio config before write.\n");
    if (e32_read_config(&radio, read_config)) {
        printf("Radio config before write [C0 ADDH ADDL SPED CHAN OPTION]: "
               "%02X %02X %02X %02X %02X %02X\n",
               (unsigned int)read_config[0],
               (unsigned int)read_config[1],
               (unsigned int)read_config[2],
               (unsigned int)read_config[3],
               (unsigned int)read_config[4],
               (unsigned int)read_config[5]);
    } else {
        printf("Radio config read timed out before write; continuing with config write.\n");
    }


    e32_write_config(&radio);


    printf("Reading radio config after write.\n");
    if (e32_read_config(&radio, read_config)) {
        printf("Radio config before write [C0 ADDH ADDL SPED CHAN OPTION]: "
               "%02X %02X %02X %02X %02X %02X\n",
               (unsigned int)read_config[0],
               (unsigned int)read_config[1],
               (unsigned int)read_config[2],
               (unsigned int)read_config[3],
               (unsigned int)read_config[4],
               (unsigned int)read_config[5]);
    } else {
        printf("Radio config read timed out before write; continuing with config write.\n");
    }

    char msg[]="Hello";


    absolute_time_t next_send = get_absolute_time();
    while(1)
    {
        if (time_reached(next_send))
        {
            printf("Sent\n");
            e32_send(&radio, (const uint8_t *)msg, sizeof(msg) - 1);
            next_send = make_timeout_time_ms(1000);
        }

        uint8_t buffer[64];
        int len = e32_receive(
            &radio,
            buffer,
            sizeof(buffer)
        );


        if(len > 0)
        {
            printf("HEX: ");

            for(int i=0;i<len;i++)
            {
                printf("%02X ", buffer[i]);
            }


            printf(" | ASCII: ");


            for(int i=0;i<len;i++)
            {
                if(buffer[i] >= 32 && buffer[i] <= 126)
                    printf("%c", buffer[i]);
                else
                    printf(".");
            }

            printf("\n");
        }

        tight_loop_contents();
    }

}
