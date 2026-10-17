/* ==========================================================================
 * radio_packet_protocol.c -- implementation of the transport layer.
 *
 * It provides three things to the rest of the program:
 *   1. Global-address arithmetic (date <-> seconds since 2020-01-01).
 *   2. Packet codec (struct <-> bytes) with a CRC-16 guard.
 *   3. A byte-at-a-time state machine that turns the E32's UART stream back
 *      into whole packets, because the radio gives us no message framing.
 *
 * It knows nothing about the mesh itself: no command is interpreted here. All
 * interpretation happens in radio.c / mesh_network_v1.c.
 * ==========================================================================*/
#include "radio_packet_protocol.h"

#include <string.h>
#include <limits.h>

/* One reassembly buffer per E32 device. The program only ever has one radio
 * (`e32_t radio`), but keeping a table means the same code would work if a
 * node ever grew a second radio. */
#define RADIO_RX_STATE_SLOTS 8

typedef struct
{
    e32_t *dev;                            /* which radio this slot belongs to (NULL = free) */
    uint8_t buffer[RADIO_MAX_PACKET_SIZE]; /* raw bytes collected so far */
    uint16_t position;                     /* write cursor into buffer */
    uint16_t expected_length;              /* where the current packet must end; 0 = unknown yet */
    bool active;                           /* we are inside a packet (past the START byte) */
} radio_rx_state_t;

static radio_rx_state_t rx_states[RADIO_RX_STATE_SLOTS];

/* --- Big-endian helpers ---------------------------------------------------
 * The wire format is big-endian everywhere. That is deliberate: it makes the
 * bytes human-readable in a hex dump and identical on every node regardless
 * of the host's word order. These four functions are the only place where
 * numbers cross the boundary between "integer" and "bytes". */

/* Write a 16-bit value into the next two bytes of `buffer`. */
static void write_u16_be(uint8_t *buffer, uint16_t value)
{
    buffer[0] = (uint8_t)(value >> 8);
    buffer[1] = (uint8_t)value;
}

/* Read a 16-bit value back out of two bytes. */
static uint16_t read_u16_be(const uint8_t *buffer)
{
    return (uint16_t)(((uint16_t)buffer[0] << 8) | buffer[1]);
}

/* Write a 32-bit value (a global address, a length, an offset...) as 4 bytes. */
static void write_u32_be(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (uint8_t)(value >> 24);
    buffer[1] = (uint8_t)(value >> 16);
    buffer[2] = (uint8_t)(value >> 8);
    buffer[3] = (uint8_t)value;
}

/* Read a global address back out of 4 bytes. */
static uint32_t read_u32_be(const uint8_t *buffer)
{
    return ((uint32_t)buffer[0] << 24) |
           ((uint32_t)buffer[1] << 16) |
           ((uint32_t)buffer[2] << 8) |
           (uint32_t)buffer[3];
}

/* --------------------------------------------------------------------------
 * Date/time and global address generation
 * -------------------------------------------------------------------------- */

bool radio_is_leap_year(uint16_t year)
{
    return ((year % 4u == 0u && year % 100u != 0u) ||
            (year % 400u == 0u));
}

static uint8_t days_in_month(uint16_t year, uint8_t month)
{
    static const uint8_t days[12] =
        {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    if (month == 2 && radio_is_leap_year(year))
        return 29;

    return days[month - 1];
}

static bool radio_datetime_valid(const datetime_t *dt)
{
    if (dt == NULL)
        return false;

    if (dt->year < RADIO_EPOCH_YEAR)
        return false;

    if (dt->month < 1 || dt->month > 12)
        return false;

    if (dt->day < 1 || dt->day > days_in_month((uint16_t)dt->year,
                                               (uint8_t)dt->month))
        return false;

    if (dt->hour < 0 || dt->hour > 23)
        return false;

    if (dt->min < 0 || dt->min > 59)
        return false;

    if (dt->sec < 0 || dt->sec > 59)
        return false;

    return true;
}

/* THE IDENTITY FUNCTION OF THE WHOLE PROJECT.
 *
 * It walks forward from the fixed epoch, one whole year at a time, then one
 * whole month, then the remaining days, and converts the total to seconds.
 * Doing it this way (rather than a closed formula) keeps it obviously correct
 * and identical on every node, which is what makes the addresses comparable.
 *
 * uint64_t is used for the running total so the intermediate days*86400 cannot
 * overflow before the final 32-bit range check rejects it. */
uint32_t radio_datetime_to_global_address(const datetime_t *dt)
{
    if (!radio_datetime_valid(dt))
        return 0;

    /*
     * Count complete days from the epoch to the supplied date.
     * uint64_t is used for the calculation so there is no intermediate
     * overflow before the final 32-bit range check.
     */
    uint64_t days = 0;

    /* Step 1: add every whole year strictly before the target year.
     * This is the dominant cost (~6 years x 365) but it only runs at boot. */
    for (uint16_t year = RADIO_EPOCH_YEAR;
         year < (uint16_t)dt->year;
         ++year)
    {
        days += radio_is_leap_year(year) ? 366u : 365u;
    }

    /* Step 2: add the whole months already elapsed inside the target year. */
    for (uint8_t month = 1;
         month < (uint8_t)dt->month;
         ++month)
    {
        days += days_in_month((uint16_t)dt->year, month);
    }

    /* Step 3: the day-of-month part. -1 because the 1st contributes 0 days. */
    days += (uint64_t)((uint8_t)dt->day - 1u);

    /* Step 4: days -> seconds, plus the time-of-day read straight from the RTC.
     * The seconds field is what makes two nodes created on the same day unique. */
    uint64_t seconds =
        days * 86400ull +
        (uint64_t)(uint8_t)dt->hour * 3600ull +
        (uint64_t)(uint8_t)dt->min * 60ull +
        (uint64_t)(uint8_t)dt->sec;

    /* Guard: a 32-bit address covers ~136 years from 2020. Beyond that the
     * node cannot be identified, so we report failure rather than wrap. */
    if (seconds > UINT32_MAX)
        return 0;

    return (uint32_t)seconds;
}

/* Wrapper used by mesh_network_v1.c: it reads the LIVE clock from the Pico RTC
 * and overwrites only the date part with the node's creation date. The hour/
 * minute/second therefore come from rtc_init()/rtc_set_datetime() in main(),
 * which is why main() must set the clock before Core 1 starts. */
uint32_t radio_generate_global_address(uint16_t year,
                                       uint8_t month,
                                       uint8_t day)
{
    datetime_t now;

    /* Pico SDK rtc_get_datetime() fills the structure; it is not bool. */
    rtc_get_datetime(&now);

    /* Creation date is supplied by the node/application. */
    now.year = (int16_t)year;
    now.month = (int8_t)month;
    now.day = (int8_t)day;

    return radio_datetime_to_global_address(&now);
}

/* -------------------------------------------------------------------------
 * RECEIVE-STATE MANAGEMENT
 *
 * The E32 delivers raw bytes over a UART with no message boundaries, so the
 * parser below needs somewhere to keep "the packet I am in the middle of".
 * That state lives in this static table, keyed by device pointer.
 * ------------------------------------------------------------------------- */

/* Find (or lazily create) the reassembly slot for one radio.
 * Returns NULL only if all slots are taken by other devices. */
static radio_rx_state_t *get_rx_state(e32_t *dev)
{
    radio_rx_state_t *free_state = NULL;

    /* Single pass: return immediately on a device match, otherwise remember
     * the first empty slot we could claim. */
    for (uint8_t i = 0; i < RADIO_RX_STATE_SLOTS; ++i)
    {
        if (rx_states[i].dev == dev)
            return &rx_states[i];

        if (rx_states[i].dev == NULL && free_state == NULL)
            free_state = &rx_states[i];
    }

    /* Nothing matched: claim the first free slot and wipe it so a stale
     * half-packet from a previous owner can never leak into a new one. */
    if (free_state != NULL)
    {
        memset(free_state, 0, sizeof(*free_state));
        free_state->dev = dev;
        return free_state;
    }

    return NULL;
}

/* Discard any partial packet. Not called by the main loop today, but it is
 * the correct thing to do after a reboot or after a run of bad CRCs. */
void radio_receive_reset(e32_t *dev)
{
    radio_rx_state_t *state = get_rx_state(dev);

    if (state == NULL)
        return;

    state->position = 0;
    state->expected_length = 0;
    state->active = false;
}

/* -------------------------------------------------------------------------
 * CRC-16-CCITT
 *
 * Purpose in the grand scheme: the E32 radio is a noisy physical channel. A
 * corrupted packet must never be mistaken for a valid one, because handlers
 * such as Respond_To_New_Node immediately write the payload into the global
 * graph. The CRC is the gate that protects that.
 *
 * Polynomial: 0x1021, initial 0xFFFF, no reflection, no final XOR.
 * Bit-by-bit (no table) on purpose: it costs a few microseconds but keeps
 * ~256 bytes of RAM free, which matters on a Pico.
 * ------------------------------------------------------------------------- */

uint16_t radio_crc16(const uint8_t *data, uint16_t length)
{
    uint16_t crc = 0xFFFF;

    /* Feed every byte into the register... */
    for (uint16_t i = 0; i < length; ++i)
    {
        crc ^= (uint16_t)data[i] << 8;

        /* ...then shift it through the polynomial, one bit at a time. */
        for (uint8_t bit = 0; bit < 8; ++bit)
        {
            if (crc & 0x8000)
                crc = (uint16_t)((crc << 1) ^ 0x1021);
            else
                crc <<= 1;
        }
    }

    return crc;
}

/* -------------------------------------------------------------------------
 * PACKET CONSTRUCTION
 *
 * Every sender in the program uses this trio: create -> (optional set_path)
 * -> (optional set_data) -> radio_send_packet. Keeping construction in three
 * small steps is what guarantees source/destination/path stay consistent.
 * ------------------------------------------------------------------------- */

/* Start a message. Also pre-fills a one-hop route (source -> destination)
 * so that simple neighbour-to-neighbour traffic needs no extra call. */
bool radio_packet_create(radio_packet_t *packet,
                         uint32_t source,
                         uint32_t destination,
                         uint16_t command,
                         uint8_t flags,
                         uint16_t sequence)
{
    if (packet == NULL)
        return false;

    /* Zero everything first: unused path slots and unused data must be
     * deterministic, otherwise two identical messages would differ on the
     * wire and the CRC/dedup logic would be confused. */
    memset(packet, 0, sizeof(*packet));

    packet->source = source;
    packet->destination = destination;
    packet->path[0] = source;
    /* A self-directed packet needs only one route entry; anything else is
     * a single jump, so two. path_length is what encode() writes as "jumps". */
    packet->path_length = source == destination ? 1 : 2;
    if (packet->path_length == 2)
        packet->path[1] = destination;
    packet->command = command;
    packet->flags = flags;
    packet->sequence = sequence;

    if (destination == RADIO_BROADCAST_ADDRESS)
        packet->flags |= RADIO_FLAG_BROADCAST;

    return true;
}

/* Attach a payload. The length checks here are the reason every caller can
 * assume packet->data is always big enough and always NUL-free binary safe. */
bool radio_packet_set_data(radio_packet_t *packet,
                           const uint8_t *data,
                           uint16_t length)
{
    if (packet == NULL)
        return false;

    if (length > RADIO_MAX_DATA)
        return false;

    if (length > 0 && data == NULL)
        return false;

    if (length > 0)
        memcpy(packet->data, data, length);

    packet->length = length;
    return true;
}

/* Overwrite the default one-hop route with a multi-hop one. Used by the
 * Diffie-Hellman exchange and by the chunked file transfers, where the packet
 * must travel through intermediate nodes that are NOT the final target.
 * Re-deriving source/destination here is what keeps packet_is_for_us() in
 * mesh_network_v1.c correct for every hop. */
bool radio_packet_set_path(radio_packet_t *packet,
                           const uint32_t *path,
                           uint8_t path_length)
{
    if (packet == NULL || path == NULL ||
        path_length == 0 || path_length > RADIO_MAX_ROUTE_ADDRESSES)
        return false;

    memcpy(packet->path, path, (size_t)path_length * sizeof(uint32_t));
    packet->path_length = path_length;
    packet->source = path[0];
    packet->destination = path[path_length - 1];

    /* The broadcast flag must agree with the address, never contradict it,
     * because the flag is what a receiver checks first (it is cheaper than
     * comparing a 32-bit address). */
    if (packet->destination == RADIO_BROADCAST_ADDRESS)
        packet->flags |= RADIO_FLAG_BROADCAST;
    else
        packet->flags &= (uint8_t)~RADIO_FLAG_BROADCAST;

    return true;
}

/* -------------------------------------------------------------------------
 * ENCODING: struct -> bytes
 *
 * The exact inverse of radio_packet_decode(). All offsets are written as
 * `header_size - N` counted from the END of the header, which makes the code
 * independent of how many route addresses a packet happens to carry.
 * ------------------------------------------------------------------------- */

/* Returns the byte count written, or 0 if the packet was rejected. */
uint16_t radio_packet_encode(radio_packet_t *packet,
                             uint8_t *buffer,
                             uint16_t buffer_size)
{
    if (packet == NULL || buffer == NULL)
        return 0;

    if (packet->length > RADIO_MAX_DATA ||
        packet->path_length == 0 ||
        packet->path_length > RADIO_MAX_ROUTE_ADDRESSES)
        return 0;

    /* Fix the flag BEFORE the CRC is computed, so the CRC covers the flag
     * value that will actually be transmitted. */
    if (packet->destination == RADIO_BROADCAST_ADDRESS)
        packet->flags |= RADIO_FLAG_BROADCAST;

    /* The header length is variable because the route list is variable.
     * Everything after the route is addressed backwards from header_size. */
    uint16_t header_size = RADIO_PACKET_FIXED_HEADER_SIZE +
                           (uint16_t)(packet->path_length * sizeof(uint32_t));
    uint16_t total_length = header_size + RADIO_PACKET_CRC_SIZE +
                            packet->length;

    if (buffer_size < total_length)
        return 0;

    /* --- the fixed 2-byte preamble --- */
    buffer[0] = RADIO_PACKET_START;
    /* We transmit the number of JUMPS, not the number of addresses, so the
     * decoder can recover path_length as jumps+1 from a single byte. */
    buffer[1] = (uint8_t)(packet->path_length - 1u);

    /* --- the route list: this is what makes multi-hop routing possible --- */
    for (uint8_t i = 0; i < packet->path_length; ++i)
        write_u32_be(&buffer[2u + (i * sizeof(uint32_t))], packet->path[i]);

    /* --- the rest of the header, counted back from its end --- */
    write_u16_be(&buffer[header_size - 7], packet->command);
    buffer[header_size - 5] = packet->flags;

    write_u16_be(&buffer[header_size - 4], packet->sequence);
    write_u16_be(&buffer[header_size - 2], packet->length);

    /* --- payload, then the CRC over everything above it --- */
    if (packet->length > 0)
    {
        memcpy(&buffer[header_size],
               packet->data,
               packet->length);
    }

    /* The CRC is computed over the bytes we just produced, i.e. header + data
     * but NOT the CRC field itself. decode() recomputes the same range. */
    packet->crc = radio_crc16(
        buffer,
        header_size + packet->length);

    write_u16_be(&buffer[header_size + packet->length],
                 packet->crc);

    return total_length;
}

/* -------------------------------------------------------------------------
 * DECODING: bytes -> struct, with validation
 *
 * This is the trust boundary of the whole program: anything that arrives from
 * another node has been through here. Every check below exists to stop a
 * corrupted or hostile packet from reaching a handler that would otherwise
 * index arrays with values taken straight from the wire.
 * ------------------------------------------------------------------------- */

bool radio_packet_decode(const uint8_t *buffer,
                         uint16_t buffer_length,
                         radio_packet_t *packet)
{
    if (buffer == NULL || packet == NULL)
        return false;

    /* Smallest legal packet = fixed header + one route address + CRC. */
    if (buffer_length < RADIO_PACKET_FIXED_HEADER_SIZE +
                       sizeof(uint32_t) + RADIO_PACKET_CRC_SIZE)
        return false;

    /* Resync marker: without it we cannot trust any other offset. */
    if (buffer[0] != RADIO_PACKET_START)
        return false;

    /* Rebuild the header geometry from the wire. Each step depends on the
     * previous one, so each step also re-validates before the next is done. */
    uint8_t route_jumps = buffer[1];
    uint16_t path_length = (uint16_t)route_jumps + 1u;
    if (path_length > RADIO_MAX_ROUTE_ADDRESSES)
        return false;

    uint16_t header_size = RADIO_PACKET_FIXED_HEADER_SIZE +
                           (uint16_t)(path_length * sizeof(uint32_t));
    if (buffer_length < header_size + RADIO_PACKET_CRC_SIZE)
        return false;

    /* Now that header_size is known, the length field sits at header_size-2. */
    uint16_t data_length = read_u16_be(&buffer[header_size - 2]);

    /* Bounds the memcpy into packet->data[], which is exactly RADIO_MAX_DATA. */
    if (data_length > RADIO_MAX_DATA)
        return false;

    /* The declared length must match the amount of bytes we were handed;
     * any mismatch means the stream desynchronised, so drop the packet. */
    uint16_t expected_length = header_size + RADIO_PACKET_CRC_SIZE +
                               data_length;

    if (buffer_length != expected_length)
        return false;

    uint16_t received_crc =
        read_u16_be(&buffer[header_size + data_length]);

    uint16_t calculated_crc = radio_crc16(
        buffer,
        header_size + data_length);

    /* Last line of defence against radio-wave corruption. */
    if (received_crc != calculated_crc)
        return false;

    /* Only now do we fill the struct: the buffer is known to be whole,
     * in-range and CRC-correct, so every read below is safe. */
    memset(packet, 0, sizeof(*packet));

    /* Mirror of encode(): same offsets, read instead of written. */
    packet->path_length = (uint8_t)path_length;
    for (uint8_t i = 0; i < packet->path_length; ++i)
        packet->path[i] = read_u32_be(&buffer[2u + (i * sizeof(uint32_t))]);
    packet->source = packet->path[0];
    packet->destination = packet->path[packet->path_length - 1];
    packet->command = read_u16_be(&buffer[header_size - 7]);
    packet->flags = buffer[header_size - 5];
    packet->sequence = read_u16_be(&buffer[header_size - 4]);
    packet->length = data_length;

    if (data_length > 0)
    {
        memcpy(packet->data,
             &buffer[header_size],
               data_length);
    }

    packet->crc = received_crc;

    return true;
}

/* -------------------------------------------------------------------------
 * BROADCAST HELPER
 * Used by radio_send_packet() to decide whether a packet may be handed to
 * every radio in range instead of one specific neighbour.
 * ------------------------------------------------------------------------- */

bool radio_is_broadcast(uint32_t address)
{
    return address == RADIO_BROADCAST_ADDRESS;
}

/* -------------------------------------------------------------------------
 * SEND: the single exit point of a node towards the physical world.
 *
 * Every handler in radio.c and every reply helper in mesh_network_v1.c ends
 * by calling this. It is the only place where the two addressing layers meet:
 * the 32-bit mesh destination stays inside the packet, while the 16-bit
 * e32_destination chooses which physical radio receives it.
 * ------------------------------------------------------------------------- */

bool radio_send_packet(e32_t *dev,
                       radio_packet_t *packet,
                       uint16_t e32_destination,
                       uint8_t channel)
{
    if (dev == NULL || packet == NULL)
        return false;

    if (packet->length > RADIO_MAX_DATA)
        return false;

    /* A global broadcast is also an E32 broadcast unless the caller is
       deliberately routing it through a particular next-hop radio.
       Note the flag is only *recorded* here: the caller still decides the
       actual 16-bit address, which is how a node can send a 'broadcast to
       everyone' message through one specific neighbour. */
    if (radio_is_broadcast(packet->destination))
        packet->flags |= RADIO_FLAG_BROADCAST;

    uint8_t encoded[RADIO_MAX_PACKET_SIZE];

    uint16_t encoded_length = radio_packet_encode(
        packet,
        encoded,
        sizeof(encoded));

    if (encoded_length == 0)
        return false;

    e32_send_fixed(dev,
                   e32_destination,
                   channel,
                   encoded,
                   encoded_length);

    return true;
}

/* -------------------------------------------------------------------------
 * STREAM PARSER: bytes -> packets
 *
 * This is the input side of Core 1. second_core_code() calls it in a tight
 * loop; it must never block, so it consumes only what is already in the
 * UART buffer and returns false when nothing complete was found.
 *
 * The machine has three phases, driven by expected_length:
 *   unknown  -> waiting for the 0xAA resync byte
 *   header   -> once byte 1 is known we know where the header ends
 *   whole    -> once the length field is read we know where the packet ends
 * Any inconsistency resets it, so a single bad byte cannot derail the mesh.
 * ------------------------------------------------------------------------- */

bool radio_receive_packet(e32_t *dev,
                          radio_packet_t *packet)
{
    if (dev == NULL || packet == NULL)
        return false;

    radio_rx_state_t *state = get_rx_state(dev);

    if (state == NULL)
        return false;

    /* Drain only what is already buffered - this is what keeps the caller's
     * 1 ms loop non-blocking. */
    while (uart_is_readable(dev->uart))
    {
        uint8_t byte = uart_getc(dev->uart);

        /* PHASE 1 - hunting for the start byte. Garbage between packets
         * (radio noise, a truncated tail) is simply skipped here. */
        if (!state->active)
        {
            if (byte != RADIO_PACKET_START)
                continue;

            state->active = true;
            state->position = 0;
            state->expected_length = 0;
            state->buffer[state->position++] = byte;
            continue;
        }

        /* Overflow guard: a packet longer than the buffer can never be valid,
         * so we throw the run away and re-seek. The current byte is re-tested
         * as a possible new START so we never lose a packet boundary. */
        if (state->position >= RADIO_MAX_PACKET_SIZE)
        {
            state->position = 0;
            state->expected_length = 0;
            state->active = false;

            /* Treat this byte as a possible new START. */
            if (byte == RADIO_PACKET_START)
            {
                state->active = true;
                state->buffer[state->position++] = byte;
            }

            continue;
        }

        state->buffer[state->position++] = byte;

        /* PHASE 2 - we have just collected byte #1, the jump count.
         * That single byte tells us exactly where the header ends, so we can
         * set the first stop condition. */
        if (state->position == 2)
        {
            uint8_t route_jumps = state->buffer[1];
            uint16_t path_length = (uint16_t)route_jumps + 1u;
            if (path_length > RADIO_MAX_ROUTE_ADDRESSES)
            {
                state->position = 0;
                state->expected_length = 0;
                state->active = false;
                continue;
            }

            state->expected_length = RADIO_PACKET_FIXED_HEADER_SIZE +
                                     (uint16_t)(path_length * sizeof(uint32_t));
        }

        /* PHASE 3 - the header is complete, so the payload length field at
         * header_size-2 is now readable. Set the final stop condition. */
        if (state->expected_length != 0 &&
            state->position == state->expected_length)
        {
            uint16_t header_size = state->expected_length;
            uint16_t data_length = read_u16_be(
                &state->buffer[header_size - 2]);

            if (data_length > RADIO_MAX_DATA)
            {
                state->position = 0;
                state->expected_length = 0;
                state->active = false;
                continue;
            }

            state->expected_length = header_size + RADIO_PACKET_CRC_SIZE +
                                     data_length;
        }

        /* PHASE 4 - the whole packet (header + payload + CRC) is in hand.
         * decode() does the real validation; a false return means "drop it",
         * and the state has already been cleared so we resync immediately. */
        if (state->expected_length > 0 &&
            state->position == state->expected_length)
        {
            bool valid = radio_packet_decode(state->buffer,
                                              state->expected_length,
                                              packet);

            state->position = 0;
            state->expected_length = 0;
            state->active = false;

            if (valid)
                return true;
        }
    }

    return false;
}
