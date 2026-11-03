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
        1   // RX
    );



    char msg[]="Hello";


    for (int i = 0; i < 10; i++)
    {
        sleep_ms(1000);
        printf("Sent\n");
        e32_send(
            &radio,
            (uint8_t*)msg,
            5
        );
    }




    while(1)
    {

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
            tight_loop_contents();
        }

        tight_loop_contents();
    }

}
