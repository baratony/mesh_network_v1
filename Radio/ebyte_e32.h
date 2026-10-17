/* ==========================================================================
 * ebyte_e32.h -- the PHYSICAL layer: an eByte E32.02 "radio".
 *
 * This is the bottom of the three-layer stack:
 *   ebyte_e32.h/.c          raw bytes to a node in physical range (16-bit)
 *   radio_packet_protocol.h message framing + 32-bit global addresses
 *   radio.h/.c              the mesh protocol itself
 *
 * WHAT THE DEVICE IS
 * ------------------
 * The E32 is not a network: it is a broadcast radio. Every E32 within a few
 * hundred metres of another one can exchange short messages. Each unit has
 * exactly ONE 16-bit address and can be told "send this to address X" or
 * "send this to everyone in range". That single 16-bit number is why the
 * whole project needs a second, 32-bit addressing layer on top: the radio
 * cannot identify more than one node per address, and it has no idea what a
 * mesh is.
 *
 * HOW IT IS WIRED ON THE PICO
 * ---------------------------
 * The device talks to the Pico over a UART (9600 baud) on two GPIO pins, and
 * its power/mode state is controlled by two more GPIO pins, M0 and M1. The
 * two-bit combination of M0/M1 selects one of four hardware modes, which is
 * what the enum below encodes.
 *
 * Everything in this file is byte plumbing. Nothing here knows about packets,
 * commands, CRCs or nodes.
 * ==========================================================================*/
#ifndef EBYTE_E32_H
#define EBYTE_E32_H


#include <stdint.h>
#include "hardware/uart.h"


/* The four hardware states of the E32, encoded as the two GPIO control pins
 * M0/M1. Waking the device is required at boot: a sleeping radio receives
 * nothing, which is why second_core_code() does WAKEUP -> NORMAL with a
 * sleep between the two. POWER_SAVE/SLEEP are used when the radio is not
 * needed (e32_write_config() parks it in SLEEP while it reconfigures itself). */
typedef enum
{
    E32_MODE_NORMAL = 0,   /* M0=0 M1=0 : fully operational */
    E32_MODE_WAKEUP,       /* M0=1 M1=0 : bring the device to life */
    E32_MODE_POWER_SAVE,   /* M0=0 M1=1 : idle, low power */
    E32_MODE_SLEEP         /* M0=1 M1=1 : dormant */

} e32_mode_t;



/* Minimal handle for one radio. Only the UART instance and the two control
 * pins are needed; the device keeps its own address internally, which is why
 * the address is not stored here (it is read back with e32_read_config).
 * aux_pin is declared but never used by e32_init(). */
typedef struct
{

    uart_inst_t *uart;

    uint m0_pin;
    uint m1_pin;
    uint aux_pin;


} e32_t;



/* Bind the C struct to the physical hardware: remember the UART and control
 * pins, open the UART at 9600 baud, point its two data pins at the radio's
 * connectors, make M0/M1 writable, and leave the device in NORMAL. */
void e32_init(
    e32_t *dev,
    uart_inst_t *uart,
    uint tx,          /* Pico GPIO carrying the radio's transmit wire */
    uint rx,          /* Pico GPIO carrying the radio's receive wire */
    uint m0,          /* mode control bit 0 */
    uint m1           /* mode control bit 1 (was mis-typed 'm1s' here) */
);



/* Set the hardware mode by writing the M0/M1 pair. Always followed by a short
 * sleep inside the implementation, because the device needs time to apply it. */
void e32_set_mode(
    e32_t *dev,
    e32_mode_t mode
);



/* Raw, unframed write. Not used by the mesh protocol, which always goes
 * through e32_send_fixed(); kept for direct/debug use. */
void e32_send(
    e32_t *dev,
    uint8_t *data,
    uint16_t length
);



/* Raw, non-blocking read: drain whatever is already in the UART buffer, up to
 * length bytes, and report how many were taken. radio_receive_packet() does NOT
 * use this - it reads one byte at a time with uart_getc() so it can run its
 * own framing state machine. */
int e32_receive(
    e32_t *dev,
    uint8_t *buffer,
    uint16_t length
);



/* THE SEND PRIMITIVE OF THE WHOLE PROGRAM.
 *
 * Prefixes the payload with the 16-bit destination address and a channel byte,
 * then hands the whole thing to the radio. This is the only place a 32-bit
 * mesh destination is turned into a 16-bit radio address, and it is the
 * function every handler in radio.c ultimately calls (via radio_send_packet).
 *
 * Note the fixed 512-byte scratch buffer in the implementation: it caps the
 * payload at 509 bytes, which is why RADIO_MAX_PACKET_SIZE in
 * radio_packet_protocol.h is sized the way it is. */
void e32_send_fixed(
    e32_t *dev,
    uint16_t address,   /* the radio to dial, or 0xFFFF for every one in range */
    uint8_t channel,
    uint8_t *data,
    uint16_t length
);



/* Convenience wrapper for 'everyone in range': address 0xFFFF, channel 0.
 * Used by Find_Neighbors for the initial PING, where the node has no idea
 * yet who is there and must reach every radio. */
void e32_send_broadcast(
    e32_t *dev,
    uint8_t *data,
    uint16_t length
);



/* Ask the device for its own configuration (address + channel). Debug only:
 * nothing in the mesh protocol calls it, but it is how you can verify on a
 * bench what address a radio actually holds. Parks the device in SLEEP first,
 * because a running radio would answer with traffic of its own. */
void e32_read_config(
    e32_t *dev,
    uint8_t *config
);



/* Assign this radio its 16-bit address and channel. Called once at boot from
 * second_core_code() with E32_BROADCAST (0xFFFF), i.e. the node deliberately
 * has no fixed radio address of its own: it only ever addresses other nodes
 * through the local addresses recorded in local_neighbors.txt. */
void e32_write_config(
    e32_t *dev,
    uint16_t address,
    uint8_t channel
);



#endif