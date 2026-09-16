#include <stdio.h>
#include "pico/stdlib.h"
#include "Ethernet_FTP/ethernet_setup.h"
#include "Radio/radio.c"


int main()
{
    stdio_init_all();

    while (true) {
        printf("Hello, world!\n");
        sleep_ms(1000);
    }
}