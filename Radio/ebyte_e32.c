/* ==========================================================================
 * ebyte_e32.c -- implementation of the PHYSICAL layer.
 *
 * Everything here is either GPIO/UART plumbing or the tiny wire format the
 * E32 itself understands:
 *
 *   on the wire:  [dest_address_hi][dest_address_lo][channel][payload...]
 *
 * That 3-byte prefix is the whole of the radio's addressing capability, and
 * it is the reason the project needs a second, 32-bit addressing layer above
 * it (see radio_packet_protocol.h). Nothing in this file knows about nodes,
 * packets, commands or CRCs.
 * ==========================================================================*/
#include "ebyte_e32.h"

#include "hardware/gpio.h"
#include "pico/stdlib.h"



/* The device's own control opcodes, used only by read/write_config. They are
 * sent over the same UART as the radio traffic, which is why both functions
 * park the radio in SLEEP first: a running radio would answer with traffic of
 * its own and the reply could not be told apart. */
#define CMD_READ   0xC1
#define CMD_WRITE  0xC0



/* Boot-time wiring, called once from second_core_code().
 *
 * The order matters: the UART must exist before its pins are pointed at it,
 * and the mode pins must be writable before e32_set_mode() touches them. */
void e32_init(
    e32_t *dev,
    uart_inst_t *uart,
    uint tx,
    uint rx,
    uint m0,
    uint m1
)
{

    /* Remember which UART and which mode pins this handle owns. Everything
     * else in this file works through dev->uart and these two pin numbers. */
    dev->uart = uart;

    dev->m0_pin=m0;
    dev->m1_pin=m1;


    /* Open the Pico's UART at the rate the radio is about to be configured
     * for. E32_UART_BAUD and E32_TRANSPORT_SETTINGS are one setting seen
     * from both sides; see ebyte_e32.h for why they must agree. */
    uart_init(uart,E32_UART_BAUD);

    /* Make the two Pico GPIOs act as that UART's data lines, so the radio's
     * wires plug straight into them. */
    gpio_set_function(tx,GPIO_FUNC_UART);
    gpio_set_function(rx,GPIO_FUNC_UART);

    /* M0/M1 are plain outputs, not part of the UART: they are the 2-bit
     * mode selector. */
    gpio_init(m0);
    gpio_init(m1);

    gpio_set_dir(m0,GPIO_OUT);
    gpio_set_dir(m1,GPIO_OUT);

    /* Leave the device in its running state; second_core_code() then does
     * the WAKEUP -> NORMAL sequence, which is what actually powers it up. */
    e32_set_mode(dev,E32_MODE_NORMAL);

}




/* The 2-bit mode selector. Each enum value maps to one combination of the
 * two control pins - this table IS the device's hardware interface. */
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








/* THE ONE SEND PRIMITIVE THAT THE WHOLE PROGRAM USES.
 *
 * radio_send_packet() in radio_packet_protocol.c ends here: it hands us the
 * already-encoded packet bytes plus the 16-bit address of the hop to dial.
 * The 3-byte prefix is the entire physical addressing capability of the radio:
 *   [address_hi][address_lo][channel][payload...]
 * which is why the mesh layer above has to carry its own 32-bit destination
 * inside the payload.
 *
 * WARNING: packet[] is a fixed 512-byte buffer and length is not checked, so
 * a caller passing more than 509 bytes overflows it. RADIO_MAX_PACKET_SIZE is
 * chosen to stay under that limit. */
void e32_send_fixed(
    e32_t *dev,
    uint16_t address,
    uint8_t channel,
    uint8_t *data,
    uint16_t length
)
{

    uint8_t packet[512];

    /* Split the 16-bit destination into two bytes, big-endian, matching the
     * convention used by every other format in this project. */
    packet[0]=address>>8;
    packet[1]=address&0xFF;

    packet[2]=channel;

    /* Copy the payload after the header. */
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







/* 'Reach every radio in range'. This is the only addressing mode that needs
 * no prior knowledge, so it is what the discovery PING uses. Everywhere else
 * the program deliberately addresses one specific neighbour, to avoid
 * paying for traffic it cannot use. */
void e32_send_broadcast(
    e32_t *dev,
    uint8_t *data,
    uint16_t length
)
{


    e32_send_fixed(
        dev,
        0xFFFF,   /* the device's own 'broadcast' address */
        0,
        data,
        length
    );


}







/* Debug helper: ask the device what address and channel it currently holds.
 * Not called anywhere in the mesh protocol - it exists so you can verify on a
 * bench that a radio was configured as intended. */
void e32_read_config(
    e32_t *dev,
    uint8_t *config
)
{


    /* Park the radio first: while it is running, its own traffic would be
     * mixed into the reply we are about to read. */
    e32_set_mode(
        dev,
        E32_MODE_SLEEP
    );


    /* A 3-byte control request: opcode, first index, count of bytes wanted. */
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








/* Give the radio its 16-bit address and channel. Called once at boot from
 * second_core_code() with E32_BROADCAST (0xFFFF): this node deliberately
 * claims no address of its own, because the addresses it uses are the per-
 * neighbour local addresses recorded in local_neighbors.txt. */
void e32_write_config(
    e32_t *dev,
    uint16_t address,
    uint8_t channel
)
{


    /* Same reason as e32_read_config: stop the radio before talking to it. */
    e32_set_mode(
        dev,
        E32_MODE_SLEEP
    );


    /* The device's control block: opcode, the new address, transport settings,
     * the channel, and a trailing reserved byte. */
    uint8_t cfg[6];


    cfg[0]=CMD_WRITE;


    cfg[1]=address>>8;
    cfg[2]=address&0xFF;


    cfg[3]=E32_TRANSPORT_SETTINGS;   /* the connector at E32_UART_BAUD */


    cfg[4]=channel;


    cfg[5]=0x00;



    uart_write_blocking(
        dev->uart,
        cfg,
        6
    );


    /* Give the device time to apply the new configuration, then put it back
     * into service - the caller (second_core_code) follows with WAKEUP. */
    sleep_ms(100);


    e32_set_mode(
        dev,
        E32_MODE_NORMAL
    );

}