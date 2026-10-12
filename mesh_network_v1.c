#include <stdio.h>
#include <unistd.h>
#include "pico/stdlib.h"
#include "Ethernet_FTP/ethernet_setup.h"
#include "Radio/radio.c"
#include "Cryptographic_Functions/Cryptographic_Functions.h"
#include "pico/multicore.h"
#include "Radio/ebyte_e32.h"


// Have the Seocnd Core handle all radio operations and communcication
void second_core_code() {

    Intilize radio and wake it up
    struct e32_t e32_t_main = {/*Uart Struct*/, 0, 1, 2};


    e32_init(e32_t_main, /*Uart Instance*/, 3, 4, 5, /*?*/);
    e32_set_mode(e32_t_main, E32_MODE_WAKEUP);
    printf("[CORE1] Radio being woken up.");
    sleep(2);
    printf("[CORE1] Radio has been awoken.");
    e32_set_mode(e32_t_main, E32_MODE_NORMAL);

    Check to see if this node has a pre-existing global address or if this is the first time activating the node.

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        goto new_node_setup:
    }

    else
    {
        continue
    }

    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("[CORE1] No valid neighbors in local_neighbors.txt\n");
        printf("[CORE1] New node detected, going to generate global address.\n");
        goto new_node_setup;
    }

    else
    {
        goto normal_operations
    }
    
    
    new_node_setup:
    uint32 GlobalAddress = radio_generate_global_address(2026, 9, 6);
    unint16 LocalAddress = /*Local Address*/;

    normal_operations:
    
}

// Have Core one handle all of the ethernet requests and webiste hosting.
int main()
{
  //  multicore_launch_core1(second_core_code);
    stdio_init_all();

    while (true) {
        printf("Hello, world!\n");
        sleep_ms(1000);
    }
}