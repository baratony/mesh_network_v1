#include "radio_packet_protocol.h"

#include <string.h>
#include <limits.h>

#define RADIO_RX_STATE_SLOTS 8

typedef struct
{
    e32_t *dev;
    uint8_t buffer[RADIO_MAX_PACKET_SIZE];
    uint16_t position;
    uint16_t expected_length;
    bool active;
} radio_rx_state_t;

static radio_rx_state_t rx_states[RADIO_RX_STATE_SLOTS];

/* --------------------------------------------------------------------------
 * Big-endian helpers
 * -------------------------------------------------------------------------- */

static void write_u16_be(uint8_t *buffer, uint16_t value)
{
    buffer[0] = (uint8_t)(value >> 8);
    buffer[1] = (uint8_t)value;
}

static uint16_t read_u16_be(const uint8_t *buffer)
{
    return (uint16_t)(((uint16_t)buffer[0] << 8) | buffer[1]);
}

static void write_u32_be(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (uint8_t)(value >> 24);
    buffer[1] = (uint8_t)(value >> 16);
    buffer[2] = (uint8_t)(value >> 8);
    buffer[3] = (uint8_t)value;
}

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

    for (uint16_t year = RADIO_EPOCH_YEAR;
         year < (uint16_t)dt->year;
         ++year)
    {
        days += radio_is_leap_year(year) ? 366u : 365u;
    }

    for (uint8_t month = 1;
         month < (uint8_t)dt->month;
         ++month)
    {
        days += days_in_month((uint16_t)dt->year, month);
    }

    days += (uint64_t)((uint8_t)dt->day - 1u);

    uint64_t seconds =
        days * 86400ull +
        (uint64_t)(uint8_t)dt->hour * 3600ull +
        (uint64_t)(uint8_t)dt->min * 60ull +
        (uint64_t)(uint8_t)dt->sec;

    if (seconds > UINT32_MAX)
        return 0;

    return (uint32_t)seconds;
}

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

/* --------------------------------------------------------------------------
 * Receive-state management
 * -------------------------------------------------------------------------- */

static radio_rx_state_t *get_rx_state(e32_t *dev)
{
    radio_rx_state_t *free_state = NULL;

    for (uint8_t i = 0; i < RADIO_RX_STATE_SLOTS; ++i)
    {
        if (rx_states[i].dev == dev)
            return &rx_states[i];

        if (rx_states[i].dev == NULL && free_state == NULL)
            free_state = &rx_states[i];
    }

    if (free_state != NULL)
    {
        memset(free_state, 0, sizeof(*free_state));
        free_state->dev = dev;
        return free_state;
    }

    return NULL;
}

void radio_receive_reset(e32_t *dev)
{
    radio_rx_state_t *state = get_rx_state(dev);

    if (state == NULL)
        return;

    state->position = 0;
    state->expected_length = 0;
    state->active = false;
}

/* --------------------------------------------------------------------------
 * CRC-16-CCITT
 * Polynomial: 0x1021, initial 0xFFFF, no reflection, no final XOR.
 * -------------------------------------------------------------------------- */

uint16_t radio_crc16(const uint8_t *data, uint16_t length)
{
    uint16_t crc = 0xFFFF;

    for (uint16_t i = 0; i < length; ++i)
    {
        crc ^= (uint16_t)data[i] << 8;

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

/* --------------------------------------------------------------------------
 * Packet creation
 * -------------------------------------------------------------------------- */

bool radio_packet_create(radio_packet_t *packet,
                         uint32_t source,
                         uint32_t destination,
                         uint16_t command,
                         uint8_t flags,
                         uint16_t sequence)
{
    if (packet == NULL)
        return false;

    memset(packet, 0, sizeof(*packet));

    packet->source = source;
    packet->destination = destination;
    packet->path[0] = source;
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

    if (packet->destination == RADIO_BROADCAST_ADDRESS)
        packet->flags |= RADIO_FLAG_BROADCAST;
    else
        packet->flags &= (uint8_t)~RADIO_FLAG_BROADCAST;

    return true;
}

/* --------------------------------------------------------------------------
 * Encoding
 * -------------------------------------------------------------------------- */

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

    /* Keep broadcast flag synchronized before CRC is calculated. */
    if (packet->destination == RADIO_BROADCAST_ADDRESS)
        packet->flags |= RADIO_FLAG_BROADCAST;

    uint16_t header_size = RADIO_PACKET_FIXED_HEADER_SIZE +
                           (uint16_t)(packet->path_length * sizeof(uint32_t));
    uint16_t total_length = header_size + RADIO_PACKET_CRC_SIZE +
                            packet->length;

    if (buffer_size < total_length)
        return 0;

    buffer[0] = RADIO_PACKET_START;
    buffer[1] = (uint8_t)(packet->path_length - 1u);

    for (uint8_t i = 0; i < packet->path_length; ++i)
        write_u32_be(&buffer[2u + (i * sizeof(uint32_t))], packet->path[i]);

    write_u16_be(&buffer[header_size - 7], packet->command);
    buffer[header_size - 5] = packet->flags;

    write_u16_be(&buffer[header_size - 4], packet->sequence);
    write_u16_be(&buffer[header_size - 2], packet->length);

    if (packet->length > 0)
    {
        memcpy(&buffer[header_size],
               packet->data,
               packet->length);
    }

    packet->crc = radio_crc16(
        buffer,
        header_size + packet->length);

    write_u16_be(&buffer[header_size + packet->length],
                 packet->crc);

    return total_length;
}

/* --------------------------------------------------------------------------
 * Decoding
 * -------------------------------------------------------------------------- */

bool radio_packet_decode(const uint8_t *buffer,
                         uint16_t buffer_length,
                         radio_packet_t *packet)
{
    if (buffer == NULL || packet == NULL)
        return false;

    if (buffer_length < RADIO_PACKET_FIXED_HEADER_SIZE +
                       sizeof(uint32_t) + RADIO_PACKET_CRC_SIZE)
        return false;

    if (buffer[0] != RADIO_PACKET_START)
        return false;

    uint8_t route_jumps = buffer[1];
    uint16_t path_length = (uint16_t)route_jumps + 1u;
    if (path_length > RADIO_MAX_ROUTE_ADDRESSES)
        return false;

    uint16_t header_size = RADIO_PACKET_FIXED_HEADER_SIZE +
                           (uint16_t)(path_length * sizeof(uint32_t));
    if (buffer_length < header_size + RADIO_PACKET_CRC_SIZE)
        return false;

    uint16_t data_length = read_u16_be(&buffer[header_size - 2]);

    if (data_length > RADIO_MAX_DATA)
        return false;

    uint16_t expected_length = header_size + RADIO_PACKET_CRC_SIZE +
                               data_length;

    if (buffer_length != expected_length)
        return false;

    uint16_t received_crc =
        read_u16_be(&buffer[header_size + data_length]);

    uint16_t calculated_crc = radio_crc16(
        buffer,
        header_size + data_length);

    if (received_crc != calculated_crc)
        return false;

    memset(packet, 0, sizeof(*packet));

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

/* --------------------------------------------------------------------------
 * Broadcast helper
 * -------------------------------------------------------------------------- */

bool radio_is_broadcast(uint32_t address)
{
    return address == RADIO_BROADCAST_ADDRESS;
}

/* --------------------------------------------------------------------------
 * Send packet
 * -------------------------------------------------------------------------- */

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
       deliberately routing it through a particular next-hop radio. */
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

/* --------------------------------------------------------------------------
 * Stream parser
 * -------------------------------------------------------------------------- */

bool radio_receive_packet(e32_t *dev,
                          radio_packet_t *packet)
{
    if (dev == NULL || packet == NULL)
        return false;

    radio_rx_state_t *state = get_rx_state(dev);

    if (state == NULL)
        return false;

    while (uart_is_readable(dev->uart))
    {
        uint8_t byte = uart_getc(dev->uart);

        /* Search for synchronization byte. */
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

        /* The jump count determines where the rest of the header ends. */
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
