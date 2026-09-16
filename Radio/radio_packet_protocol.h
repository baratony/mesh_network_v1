#ifndef RADIO_PACKET_PROTOCOL_H
#define RADIO_PACKET_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

#include "ebyte_e32.h"
#include "pico/stdlib.h"
#include "hardware/rtc.h"

/*
 * GLOBAL NODE ADDRESSING
 *
 * A global address is the number of seconds elapsed since:
 *
 *     2020-01-01 00:00:00 UTC
 *
 * It is deliberately independent of the E32's 16-bit address. The
 * global address identifies the node at the protocol/mesh layer, while
 * the E32 address identifies the next radio hop.
 */
#define RADIO_EPOCH_YEAR  2020
#define RADIO_EPOCH_MONTH 1
#define RADIO_EPOCH_DAY   1

#define RADIO_BROADCAST_ADDRESS 0xFFFFFFFFu

/*
 * Packet format on the wire:
 *
 *   Byte 0       : START (0xAA)
 *   Bytes 1-4    : Destination global address, big-endian
 *   Bytes 5-8    : Source global address, big-endian
 *   Bytes 9-10   : Command, big-endian
 *   Byte 11      : Flags
 *   Bytes 12-13  : Sequence number, big-endian
 *   Bytes 14-15  : Data length, big-endian
 *   Bytes 16..   : Data
 *   Final 2      : CRC-16-CCITT, big-endian
 */
#define RADIO_PACKET_START       0xAA
#define RADIO_PACKET_HEADER_SIZE 16
#define RADIO_PACKET_CRC_SIZE    2
#define RADIO_PACKET_OVERHEAD    (RADIO_PACKET_HEADER_SIZE + RADIO_PACKET_CRC_SIZE)

/* e32_send_fixed() currently has a 512-byte temporary buffer. */
#define RADIO_MAX_DATA        256
#define RADIO_MAX_PACKET_SIZE (RADIO_PACKET_OVERHEAD + RADIO_MAX_DATA)

/* Commands */
typedef enum
{
    RADIO_CMD_PING        = 0x01,
    RADIO_CMD_PONG        = 0x02,
    RADIO_CMD_DATA        = 0x03,
    RADIO_CMD_ACK         = 0x04,
    RADIO_CMD_SEND_CONNECTIONS = 0x05,
    RADIO_CMD_SET_OUTPUT  = 0x06,
    RADIO_CMD_GET_STATUS  = 0x07,
    RADIO_CMD_SEND_LOCAL_ADRESS = 0x08
    
} radio_command_t;

/* Packet flags */
#define RADIO_FLAG_ACK_REQUEST (1u << 0)
#define RADIO_FLAG_ACK         (1u << 1)
#define RADIO_FLAG_BROADCAST   (1u << 2)
#define RADIO_FLAG_FRAGMENT    (1u << 3)
#define RADIO_FLAG_ENCRYPTED   (1u << 4)
#define RADIO_FLAG_ROUTED      (1u << 5)

typedef struct
{
    uint32_t destination;
    uint32_t source;

    uint16_t command;
    uint8_t flags;

    uint16_t sequence;
    uint16_t length;

    uint8_t data[RADIO_MAX_DATA];

    uint16_t crc;
} radio_packet_t;

/* --------------------------------------------------------------------------
 * Global address functions
 * -------------------------------------------------------------------------- */

/* Return true if year is a Gregorian leap year. */
bool radio_is_leap_year(uint16_t year);

/*
 * Convert a complete Pico SDK datetime_t to a global address.
 * The datetime is interpreted as UTC.
 * Returns 0 on invalid input. Note that 2020-01-01 00:00:00 itself is
 * address 0, so callers should use radio_datetime_valid() if they need to
 * distinguish an invalid date from the epoch itself.
 */
uint32_t radio_datetime_to_global_address(const datetime_t *dt);

/*
 * Generate a node address using the supplied creation date and the current
 * RTC hour/minute/second.
 *
 * Example:
 *     uint32_t my_address = radio_generate_global_address(2026, 9, 6);
 *
 * The Pico RTC must already be set to the correct UTC time.
 */
uint32_t radio_generate_global_address(uint16_t year,
                                       uint8_t month,
                                       uint8_t day);

/* --------------------------------------------------------------------------
 * Packet functions
 * -------------------------------------------------------------------------- */

bool radio_packet_create(
    radio_packet_t *packet,
    uint32_t source,
    uint32_t destination,
    uint16_t command,
    uint8_t flags,
    uint16_t sequence
);

bool radio_packet_set_data(
    radio_packet_t *packet,
    const uint8_t *data,
    uint16_t length
);

uint16_t radio_crc16(
    const uint8_t *data,
    uint16_t length
);

uint16_t radio_packet_encode(
    radio_packet_t *packet,
    uint8_t *buffer,
    uint16_t buffer_size
);

bool radio_packet_decode(
    const uint8_t *buffer,
    uint16_t buffer_length,
    radio_packet_t *packet
);

/*
 * Send a protocol packet through an E32.
 *
 * IMPORTANT:
 *   e32_destination is the 16-bit address of the NEXT radio hop.
 *   packet->destination is the 32-bit FINAL/global destination.
 *
 * For a global broadcast destination, e32_destination should normally be
 * 0xFFFF (the E32 broadcast address).
 */
bool radio_send_packet(
    e32_t *dev,
    radio_packet_t *packet,
    uint16_t e32_destination,
    uint8_t channel
);

bool radio_receive_packet(
    e32_t *dev,
    radio_packet_t *packet
);

void radio_receive_reset(
    e32_t *dev
);

bool radio_is_broadcast(
    uint32_t address
);

#endif
