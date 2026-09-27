#include <stdio.h>
#include "pico/stdlib.h"
#include "Ethernet_FTP/ethernet_setup.h"
#include "Radio/radio.c"
#include "Cryptographic_Functions/Cryptographic_Functions.h"


int main()
{
    stdio_init_all();

    while (true) {
        printf("Hello, world!\n");
        sleep_ms(1000);
    }
}