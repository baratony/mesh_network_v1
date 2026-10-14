/* ==========================================================================
 * radio_packet_protocol.h  --  the "wire" layer of the mesh network
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The project is a swarm of Raspberry Pi Picos ("nodes") that must talk to
 * each other.  There are TWO INDEPENDENT ADDRESSING LAYERS and this file owns
 * the lower one:
 *
 *   1. PHYSICAL LAYER - the E32.02 "radio" (an eByte broadcast radio with a
 *      16-bit address, wired to the Pico through uart1 + pins M0/M1).
 *      It can only carry a 16-bit address and only reaches nodes in physical
 *      range.  Those 16-bit numbers are the "local addresses".
 *
 *   2. MESH/PROTOCOL LAYER - a 32-bit "global address" per node, defined as
 *      the number of seconds since 2020-01-01T00:00:00 UTC.  A node's
 *      creation timestamp is unique, so this ID is unique, collision-free and
 *      self-describing: it needs no coordination with any other node and it
 *      survives power loss, reboot and re-flashing.
 *
 * Everything here is only about (a) the date maths that produces a global
 * address and (b) turning protocol messages (radio_packet_t) into bytes and
 * back again.  The actual mesh behaviour (neighbour discovery, graph
 * propagation, RSA signatures, Diffie-Hellman key exchange, ...) lives in
 * Radio/radio.c and is documented there.
 *
 * Included by: mesh_network_v1.c (the packet dispatcher), Radio/radio.c (the
 * protocol handlers) and Radio/ebyte_e32.h (the raw radio device).
 * ==========================================================================*/
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
/* The epoch is hard-coded and NEVER changes: it is baked into every global
 * address that has ever been handed out, so changing it would invalidate all
 * existing nodes. Keep it fixed forever. */
#define RADIO_EPOCH_YEAR  2020
#define RADIO_EPOCH_MONTH 1
#define RADIO_EPOCH_DAY   1

/* Reserved "global address" meaning "any node / everyone in radio range".
 * Used by PING, broadcast announcements and by packet_is_for_us() in main. */
#define RADIO_BROADCAST_ADDRESS 0xFFFFFFFFu

/*
 * Packet format on the wire:
 *
 *   Byte 0       : START (0xAA)
 *   Byte 1       : Number of jumps in the route
 *   Bytes 2..    : Route addresses, big-endian; one source address plus
 *                  one address for each jump
 *   Next 2       : Command, big-endian
 *   Next 1       : Flags
 *   Next 2       : Sequence number, big-endian
 *   Next 2       : Data length, big-endian
 *   Next bytes   : Data
 *   Final 2      : CRC-16-CCITT, big-endian
 */
/* --- Wire format constants -----------------------------------------------
 * These numbers are the single source of truth for the byte layout described
 * in the comment above. radio_packet_encode()/radio_packet_decode() and the
 * byte-at-a-time stream parser in radio_packet_protocol.c all derive their
 * offsets from these, so changing one changes all three consistently.
 * ----------------------------------------------------------------------- */
#define RADIO_PACKET_START       0xAA   /* resync byte that starts every packet */
#define RADIO_MAX_ROUTE_ADDRESSES 16   /* hard cap on the route list          */
#define RADIO_MAX_ROUTE_JUMPS    (RADIO_MAX_ROUTE_ADDRESSES - 1)
#define RADIO_PACKET_FIXED_HEADER_SIZE 9 /* START + jump count + cmd + flags + seq + len */
#define RADIO_PACKET_CRC_SIZE    2
#define RADIO_MAX_DATA           256   /* payload cap = one E32 "fixed" frame */
#define RADIO_PACKET_MAX_HEADER_SIZE \
    (RADIO_PACKET_FIXED_HEADER_SIZE + \
     (RADIO_MAX_ROUTE_ADDRESSES * sizeof(uint32_t)))
#define RADIO_MAX_PACKET_SIZE \
    (RADIO_PACKET_MAX_HEADER_SIZE + RADIO_MAX_DATA + RADIO_PACKET_CRC_SIZE)

/* e32_send_fixed() currently has a 512-byte temporary buffer. */
/* The command byte is the "verb" of the mesh protocol. Every one of these is
 * routed by dispatch_packet() in mesh_network_v1.c to a handler in this file
 * or in radio.c. Grouped by protocol: */
typedef enum
{
    /* --- discovery / keep-alive: find who is physically in radio range --- */
    RADIO_CMD_PING        = 0x01,   /* broadcast "who is there?" from a node */
    RADIO_CMD_PONG        = 0x02,   /* reply carrying the sender's 16-bit local address */
    RADIO_CMD_DATA        = 0x03,   /* generic payload (neighbour list, encrypted text) */
    RADIO_CMD_ACK         = 0x04,   /* "I received packet #N" confirmation */

    /* --- local (16-bit) address negotiation, avoids radio address clashes --- */
    RADIO_CMD_SEND_CONNECTIONS = 0x05,   /* "give me your neighbour list" */
    RADIO_CMD_SEND_LOCAL_ADRESS = 0x08,  /* "my radio address is X" */
    RADIO_CMD_REMOVE_LOCAL_ADDRESS = 0xA9,/* "drop me from your neighbour list" */

    /* --- control-panel / demo commands, handled in mesh_network_v1.c --- */
    RADIO_CMD_SET_OUTPUT  = 0x06,   /* turn a GPIO output of this node on/off */
    RADIO_CMD_GET_STATUS  = 0x07,   /* report own addresses + neighbour count */

    /* --- the global connection graph (adjacency list on the FTP server) --- */
    RADIO_CMD_RECEIVE_GLOBAL_CONNECTIONS = 0x09, /* request the whole graph */
    RADIO_CMD_SEND_GLOBAL_CONNECTIONS = 0xA,     /* reply, in chunks */
    RADIO_CMD_RELAY_NEW_NODE = 0xA1,             /* propagate "node X joined" */
    RADIO_CMD_RELAY_REMOVE_NODE = 0xAA,          /* propagate "node X left" */

    /* --- the global RSA public-key ledger (for signature verification) --- */
    RADIO_CMD_RECEIVE_GLOBAL_RSA_KEYS = 0xA2,
    RADIO_CMD_SEND_GLOBAL_RSA_KEYS = 0xA3,
    RADIO_CMD_RELAY_RSA_KEYS = 0xA4,

    /* --- multi-hop Diffie-Hellman: derives the AEAD key for DATA packets --- */
    RADIO_CMD_SEND_ENCRYPTION_REQUEST = 0xA5,      /* send g^a mod p */
    RADIO_CMD_SEND_ENCRYPTION_RESPONSE = 0xA6,     /* send g^b mod p + hash */
    RADIO_CMD_DH_EXCHANGE_CONFIRMED = 0xA7,        /* handshake OK */
    RADIO_CMD_DH_EXCHANGE_FAILED = 0xA8,           /* handshake broken */

    /* (the duplicated tail of the original enum has been folded into the
     * groups above - the numeric values are unchanged) */
} radio_command_t;

/* --- Packet flags: a 1-byte bitmask of "how to treat this packet" ---------
 * These are the only metadata the protocol needs beyond the command byte;
 * they tell a receiver whether to answer, whether more parts follow, and
 * whether the payload must be decrypted before use.
 * ------------------------------------------------------------------------- */
#define RADIO_FLAG_ACK_REQUEST (1u << 0)  /* sender wants an ACK back        */
#define RADIO_FLAG_ACK         (1u << 1)  /* this packet IS an acknowledgement */
#define RADIO_FLAG_BROADCAST   (1u << 2)  /* destination is "everyone", auto-set from the address */
#define RADIO_FLAG_FRAGMENT    (1u << 3)  /* part of a larger reassembled payload */
#define RADIO_FLAG_ENCRYPTED   (1u << 4)  /* payload is nonce||ciphertext||tag */
#define RADIO_FLAG_ROUTED      (1u << 5)  /* follow path[] instead of broadcasting */

/* The in-memory form of one message. This is what every handler in radio.c
 * and mesh_network_v1.c actually manipulates; radio_packet_encode()/decode()
 * move it to/from bytes. Note that the route is stored explicitly, which is
 * what lets a packet hop across several nodes and be sent straight back along
 * the same route (see the reverse-path loops in radio.c). */
typedef struct
{
    uint32_t path[RADIO_MAX_ROUTE_ADDRESSES]; /* full route: path[0]=origin ... path[n-1]=final target */
    uint8_t path_length;                      /* how many entries of path[] are valid */

    /* Convenience aliases kept in sync by create/set_path/encode so handlers
     * can just test "is this for me?" without touching path[]. */
    uint32_t destination;   /* == path[path_length-1] */
    uint32_t source;        /* == path[0] : the ORIGINAL sender, never the last hop */

    uint16_t command;       /* one of radio_command_t */
    uint8_t flags;          /* RADIO_FLAG_* bitmask */

    uint16_t sequence;      /* anti-desynchronisation counter; also the dedup key */
    uint16_t length;        /* valid bytes in data[] */

    uint8_t data[RADIO_MAX_DATA];   /* payload, format depends on command */

    uint16_t crc;           /* CRC-16-CCITT over header+data, filled by encode() */
} radio_packet_t;

/* -------------------------------------------------------------------------
 * GLOBAL ADDRESS FUNCTIONS  (identity layer)
 *
 * These are used exactly once per node, at boot: main() sets the Pico RTC to
 * the node's creation date, then second_core_code() calls
 * radio_generate_global_address() to mint the node's permanent 32-bit ID.
 * Every other part of the program only ever compares or copies that number.
 * ------------------------------------------------------------------------- */

/* Calendar helper used by the day-counting loop below. */
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

/* The core identity function: date -> seconds-since-epoch. This is the ONLY
 * place where a global address is computed, so it must be byte-for-byte
 * identical on every node for the IDs to be comparable. */
uint32_t radio_datetime_to_global_address(const datetime_t *dt);

/* Thin wrapper: takes the creation date from the caller and reads the current
 * clock from the RTC, so two nodes created on the same day still get
 * different addresses (they differ by their creation second). */
uint32_t radio_generate_global_address(uint16_t year,
                                       uint8_t month,
                                       uint8_t day);

/* -------------------------------------------------------------------------
 * PACKET FUNCTIONS  (transport layer)
 *
 * Everything in radio.c builds a radio_packet_t with create/set_path/set_data,
 * then hands it to radio_send_packet(), which encodes it and pushes the bytes
 * into the E32. On the way in, radio_receive_packet() reassembles the byte
 * stream and calls radio_packet_decode(). Nothing else touches the wire.
 * ------------------------------------------------------------------------- */

/* Start a new message. Sets path[0]=source and, for a real (non-self) target,
 * path[1]=destination, i.e. a one-hop route by default. Handlers that route
 * over several nodes call radio_packet_set_path() afterwards. */
bool radio_packet_create(
    radio_packet_t *packet,
    uint32_t source,        /* who really sent it (our own global address) */
    uint32_t destination,   /* final target, or RADIO_BROADCAST_ADDRESS */
    uint16_t command,
    uint8_t flags,
    uint16_t sequence       /* must match the request when replying */
);

/* Attach a payload. Fails if it would not fit in one E32 frame. */
bool radio_packet_set_data(
    radio_packet_t *packet,
    const uint8_t *data,
    uint16_t length
);

/* Replace the default one-hop route with a multi-hop one (used by the DH
 * exchange and by the chunked file transfers). Re-derives source/destination. */
bool radio_packet_set_path(
    radio_packet_t *packet,
    const uint32_t *path,
    uint8_t path_length
);

/* Integrity check over header+payload; appended by encode(), verified by decode(). */
uint16_t radio_crc16(
    const uint8_t *data,
    uint16_t length
);

/* Struct -> bytes. Returns the number of bytes written, 0 = rejected. */
uint16_t radio_packet_encode(
    radio_packet_t *packet,
    uint8_t *buffer,
    uint16_t buffer_size
);

/* Bytes -> struct, with full validation (start byte, length, CRC). */
bool radio_packet_decode(
    const uint8_t *buffer,
    uint16_t buffer_length,
    radio_packet_t *packet
);

/* The single send primitive used by every handler in radio.c.
 *
 * The two-address trick is the heart of the design:
 *   e32_destination = WHICH physical radio to hand the packet to (16-bit,
 *                     must be one of our neighbours, or 0xFFFF = all of them)
 *   packet->destination = WHICH node in the mesh we ultimately want (32-bit).
 * A node that is not the final target simply forwards it on again. */
bool radio_send_packet(
    e32_t *dev,
    radio_packet_t *packet,
    uint16_t e32_destination,
    uint8_t channel
);

/* Non-blocking: drains whatever is currently in the UART RX buffer, feeds it
 * to the state machine, and returns true only when one whole valid packet
 * has been reassembled. The main loop in second_core_code() calls this every
 * millisecond, so it must never block. */
bool radio_receive_packet(
    e32_t *dev,
    radio_packet_t *packet
);

/* Throw away any half-received packet (e.g. after a reboot or a bad CRC run). */
void radio_receive_reset(
    e32_t *dev
);

/* True if an address means "everyone in range" rather than a specific node. */
bool radio_is_broadcast(
    uint32_t address
);

#endif
