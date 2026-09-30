#include "ebyte_e32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include "pico/stdlib.h"
#include "pico/rand.h"
#include "hardware/uart.h"
#include "hardware/spi.h"
#include "radio_packet_protocol.h"
#include "Ethernet_FTP/ethernet_setup.h"
#include "Ethernet_FTP/ftp_client.h"
#include "Cryptographic_Functions/Cryptographic_Functions.h"
#include "Cryptographic_Functions/Cryptographic_Functions.c"



#define RADIO_NEIGHBOR_FILE_MAX_SIZE 1024
#define RADIO_NEIGHBOR_COUNT_MAX 8
#define RADIO_CONNECTION_RECORD_SIZE 6
#define RADIO_CONNECTIONS_PER_PACKET 8
#define RADIO_CONNECTION_RESPONSE_TIMEOUT_MS 5000
#define RADIO_GLOBAL_CONNECTIONS_FILE "global_connections.bin"
#define RADIO_GLOBAL_CONNECTIONS_ROW_SIZE (9u * sizeof(uint32_t))
#define RADIO_NEW_NODE_RECORD_SIZE (9u * sizeof(uint32_t))
#define RADIO_GLOBAL_CONNECTIONS_FILE_MAX_SIZE 4096
#define RADIO_GLOBAL_CONNECTIONS_CHUNK_HEADER_SIZE 8
#define RADIO_GLOBAL_CONNECTIONS_CHUNK_SIZE \
    (RADIO_MAX_DATA - RADIO_GLOBAL_CONNECTIONS_CHUNK_HEADER_SIZE)
#define RADIO_GLOBAL_CONNECTIONS_RESPONSE_TIMEOUT_MS 10000
#define RADIO_GLOBAL_ROUTE_MAX_JUMPS 14
#define RADIO_GLOBAL_ROUTE_MAX_ADDRESSES 16
#define RADIO_GLOBAL_CONNECTIONS_MAX_NODES \
    (RADIO_GLOBAL_CONNECTIONS_FILE_MAX_SIZE / sizeof(uint32_t))
#define RADIO_GLOBAL_RSA_KEYS_FILE "global_rsa_key_list"
#define RADIO_GLOBAL_RSA_KEYS_FILE_MAX_SIZE 16384
#define RADIO_GLOBAL_RSA_KEYS_CHUNK_HEADER_SIZE 12
#define RADIO_GLOBAL_RSA_KEYS_CHUNK_SIZE \
    (RADIO_MAX_DATA - RADIO_GLOBAL_RSA_KEYS_CHUNK_HEADER_SIZE)
#define RADIO_GLOBAL_RSA_KEYS_RESPONSE_TIMEOUT_MS 10000
#define RADIO_GLOBAL_RSA_KEYS_ATTEMPTS_PER_NEIGHBOR 2
#define RADIO_RSA_PUBLIC_MODULUS_BITS 2048
#define RADIO_RSA_PUBLIC_MODULUS_SIZE (RADIO_RSA_PUBLIC_MODULUS_BITS / 8)
#define RADIO_RSA_KEY_ROW_SIZE (sizeof(uint32_t) + RADIO_RSA_PUBLIC_MODULUS_SIZE)
#define RADIO_DH_MODULUS_BITS 1028u
#define RADIO_DH_RSA_FRAGMENT_HEADER_SIZE 4u
#define RADIO_DH_RSA_FRAGMENT_DATA_SIZE \
    (RADIO_MAX_DATA - RADIO_DH_RSA_FRAGMENT_HEADER_SIZE)
#define RADIO_DH_RSA_CIPHERTEXT_MAX_SIZE 512u


typedef struct
{
    uint32_t global_address;
    uint16_t local_address;
} radio_neighbor_t;


static uint8_t neighbor_file[RADIO_NEIGHBOR_FILE_MAX_SIZE + 1];
static size_t neighbor_file_length;
static bool neighbor_file_overflow;
static uint8_t global_connections_file[RADIO_GLOBAL_CONNECTIONS_FILE_MAX_SIZE];
static size_t global_connections_file_length;
static bool global_connections_file_overflow;
static uint8_t global_rsa_keys_file[RADIO_GLOBAL_RSA_KEYS_FILE_MAX_SIZE];
static size_t global_rsa_keys_file_length;
static bool global_rsa_keys_file_overflow;

static uint32_t radio_read_u32_be(const uint8_t *data);


static void radio_neighbor_file_cb(uint8_t *data, uint16_t length)
{
    size_t available = sizeof(neighbor_file) - neighbor_file_length - 1;

    if (length > available)
    {
        length = (uint16_t)available;
        neighbor_file_overflow = true;
    }

    memcpy(&neighbor_file[neighbor_file_length], data, length);
    neighbor_file_length += length;
    neighbor_file[neighbor_file_length] = '\0';
}


static void radio_global_connections_file_cb(uint8_t *data, uint16_t length)
{
    size_t available = sizeof(global_connections_file) -
                       global_connections_file_length;

    if (length > available)
    {
        length = (uint16_t)available;
        global_connections_file_overflow = true;
    }

    memcpy(&global_connections_file[global_connections_file_length],
           data,
           length);
    global_connections_file_length += length;
}


static void radio_global_rsa_keys_file_cb(uint8_t *data, uint16_t length)
{
    size_t available = sizeof(global_rsa_keys_file) -
                       global_rsa_keys_file_length;

    if (length > available)
    {
        length = (uint16_t)available;
        global_rsa_keys_file_overflow = true;
    }

    memcpy(&global_rsa_keys_file[global_rsa_keys_file_length], data, length);
    global_rsa_keys_file_length += length;
}


static uint32_t radio_crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xFFFFFFFFu;

    for (size_t i = 0; i < length; ++i)
    {
        crc ^= data[i];
        for (uint8_t bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int32_t)(crc & 1u));
    }

    return ~crc;
}


static bool radio_rsa_key_address_saved(uint32_t global_address)
{
    if (global_rsa_keys_file_length % RADIO_RSA_KEY_ROW_SIZE != 0)
        return false;

    for (size_t offset = 0;
         offset < global_rsa_keys_file_length;
         offset += RADIO_RSA_KEY_ROW_SIZE)
    {
        if (radio_read_u32_be(&global_rsa_keys_file[offset]) == global_address)
            return true;
    }

    return false;
}


static bool radio_encode_rsa_public_modulus(mpz_t public_modulo,
                                            uint8_t output[RADIO_RSA_PUBLIC_MODULUS_SIZE])
{
    if (mpz_sgn(public_modulo) <= 0 ||
        mpz_sizeinbase(public_modulo, 2) != RADIO_RSA_PUBLIC_MODULUS_BITS)
        return false;

    size_t exported_length = 0;
    memset(output, 0, RADIO_RSA_PUBLIC_MODULUS_SIZE);
    mpz_export(output,
               &exported_length,
               1,
               1,
               1,
               0,
               public_modulo);

    if (exported_length > RADIO_RSA_PUBLIC_MODULUS_SIZE)
        return false;

    if (exported_length < RADIO_RSA_PUBLIC_MODULUS_SIZE)
    {
        memmove(&output[RADIO_RSA_PUBLIC_MODULUS_SIZE - exported_length],
                output,
                exported_length);
        memset(output, 0, RADIO_RSA_PUBLIC_MODULUS_SIZE - exported_length);
    }

    return true;
}


static bool radio_valid_rsa_public_modulus(const uint8_t *modulus)
{
    return modulus != NULL &&
           (modulus[0] & 0x80u) != 0 &&
           (modulus[RADIO_RSA_PUBLIC_MODULUS_SIZE - 1] & 1u) != 0;
}


static uint32_t radio_read_u32_be(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}


static uint32_t radio_read_global_connection_word(size_t offset)
{
    uint32_t value;
    memcpy(&value, &global_connections_file[offset], sizeof(value));
    return value;
}


static void radio_write_global_connection_word(size_t offset, uint32_t value)
{
    memcpy(&global_connections_file[offset], &value, sizeof(value));
}


static bool radio_download_global_connections(ftp_client_t *ftp)
{
    global_connections_file_length = 0;
    global_connections_file_overflow = false;

    if (ftp == NULL ||
        !ftp_download(ftp, RADIO_GLOBAL_CONNECTIONS_FILE,
                      radio_global_connections_file_cb))
        return false;

    return !global_connections_file_overflow &&
           global_connections_file_length % RADIO_GLOBAL_CONNECTIONS_ROW_SIZE == 0;
}


static bool radio_find_global_connection_row(uint32_t address,
                                             size_t *row_index)
{
    size_t row_count = global_connections_file_length /
                       RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;

    for (size_t row = 0; row < row_count; ++row)
    {
        size_t offset = row * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;
        if (radio_read_global_connection_word(offset) == address)
        {
            *row_index = row;
            return true;
        }
    }

    return false;
}


static bool radio_global_connection_saved(uint32_t global_address)
{
    for (size_t offset = 0;
         offset < global_connections_file_length;
         offset += sizeof(uint32_t))
    {
        if (radio_read_global_connection_word(offset) == global_address)
            return true;
    }

    return false;
}


static bool radio_ensure_global_connection_row(uint32_t address,
                                               size_t *row_index,
                                               bool *changed)
{
    if (radio_find_global_connection_row(address, row_index))
        return true;

    if (global_connections_file_length + RADIO_GLOBAL_CONNECTIONS_ROW_SIZE >
        sizeof(global_connections_file))
        return false;

    *row_index = global_connections_file_length /
                 RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;
    memset(&global_connections_file[global_connections_file_length],
           0,
           RADIO_GLOBAL_CONNECTIONS_ROW_SIZE);
    radio_write_global_connection_word(global_connections_file_length,
                                       address);
    global_connections_file_length += RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;
    *changed = true;
    return true;
}


static bool radio_add_connection_to_row(size_t row_index,
                                        uint32_t neighbor_address,
                                        bool *changed)
{
    size_t row_offset = row_index * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;
    size_t empty_offset = RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;

    for (uint8_t column = 1; column < 9; ++column)
    {
        size_t offset = row_offset + column * sizeof(uint32_t);
        uint32_t existing = radio_read_global_connection_word(offset);
        if (existing == neighbor_address)
            return true;
        if (existing == 0 && empty_offset == RADIO_GLOBAL_CONNECTIONS_ROW_SIZE)
            empty_offset = offset - row_offset;
    }

    if (empty_offset == RADIO_GLOBAL_CONNECTIONS_ROW_SIZE)
        return false;

    radio_write_global_connection_word(row_offset + empty_offset,
                                       neighbor_address);
    *changed = true;
    return true;
}


static bool radio_add_connection_edge(uint32_t first_address,
                                      uint32_t second_address,
                                      bool *changed)
{
    if (first_address == 0 || second_address == 0 ||
        first_address == second_address)
        return false;

    size_t first_row;
    size_t second_row;
    if (!radio_ensure_global_connection_row(first_address,
                                            &first_row,
                                            changed) ||
        !radio_ensure_global_connection_row(second_address,
                                            &second_row,
                                            changed))
        return false;

    if (!radio_add_connection_to_row(first_row, second_address, changed))
        return false;
    return radio_add_connection_to_row(second_row, first_address, changed);
}


static bool radio_parse_neighbor_file(radio_neighbor_t *neighbors,
                                      uint8_t *neighbor_count)
{
    char *line = (char *)neighbor_file;
    char *end = (char *)neighbor_file + neighbor_file_length;
    uint8_t count = 0;

    while (line < end && count < RADIO_NEIGHBOR_COUNT_MAX)
    {
        char *line_end = memchr(line, '\n', (size_t)(end - line));
        if (line_end == NULL)
            line_end = end;

        *line_end = '\0';

        char *separator = strchr(line, ',');
        if (separator != NULL)
        {
            char *global_end;
            char *local_end;
            unsigned long global_address = strtoul(line, &global_end, 16);
            unsigned long local_address = strtoul(separator + 1,
                                                  &local_end,
                                                  10);

            while (*global_end == ' ' || *global_end == '\t')
                ++global_end;
            while (*local_end == ' ' || *local_end == '\t' ||
                   *local_end == '\r')
                ++local_end;

            if (global_end == separator && *local_end == '\0' &&
                global_address <= UINT32_MAX && local_address <= UINT16_MAX)
            {
                neighbors[count].global_address = (uint32_t)global_address;
                neighbors[count].local_address = (uint16_t)local_address;
                ++count;
            }
        }

        line = line_end < end ? line_end + 1 : end;
    }

    *neighbor_count = count;
    return count > 0;
}


static bool radio_find_oldest_neighbor(uint32_t global_address,
                                       radio_neighbor_t *oldest,
                                       ftp_client_t *ftp)
{
    if (ftp == NULL || oldest == NULL)
        return false;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    bool found = false;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address == global_address)
            continue;

        if (!found || neighbors[i].global_address < oldest->global_address)
        {
            *oldest = neighbors[i];
            found = true;
        }
    }

    return found;
}


static uint16_t radio_read_u16_be(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[4] << 8) | data[5]);
}


static void radio_write_u16_be(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}


static void radio_write_u32_be(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}


static bool radio_local_address_used(const uint16_t *addresses,
                                     size_t address_count,
                                     uint16_t candidate)
{
    for (size_t i = 0; i < address_count; ++i)
    {
        if (addresses[i] == candidate)
            return true;
    }

    return false;
}


uint16_t Generate_Local_Adress(uint32_t global_address,
                               e32_t *radio,
                               ftp_client_t *ftp)
{
    if (radio == NULL || ftp == NULL)
        return 0;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return 0;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return 0;
    }

    uint16_t sequence = 1;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        radio_packet_t request;
        if (!radio_packet_create(&request,
                                 global_address,
                                 neighbors[i].global_address,
                                 RADIO_CMD_SEND_CONNECTIONS,
                                 RADIO_FLAG_ACK_REQUEST,
                                 sequence++))
            return 0;

        if (!radio_send_packet(radio,
                       &request,
                       neighbors[i].local_address,
                       0))
            printf("Failed to request connections from %08lX\n",
                   (unsigned long)neighbors[i].global_address);
    }

    uint16_t received_local_addresses[64];
    size_t received_count = 0;
    absolute_time_t timeout =
        make_timeout_time_ms(RADIO_CONNECTION_RESPONSE_TIMEOUT_MS);

    while (!time_reached(timeout))
    {
        radio_packet_t response;
        if (radio_receive_packet(radio, &response) &&
            response.command == RADIO_CMD_DATA &&
            response.destination == global_address &&
            response.length > 0 &&
            response.length <= RADIO_CONNECTIONS_PER_PACKET *
                               RADIO_CONNECTION_RECORD_SIZE &&
            response.length % RADIO_CONNECTION_RECORD_SIZE == 0)
        {
            for (uint16_t offset = 0;
                 offset < response.length && received_count < 64;
                 offset += RADIO_CONNECTION_RECORD_SIZE)
            {
                uint16_t local_address =
                    radio_read_u16_be(&response.data[offset]);

                if (!radio_local_address_used(received_local_addresses,
                                               received_count,
                                               local_address))
                {
                    received_local_addresses[received_count++] =
                        local_address;
                }
            }
        }

        sleep_ms(1);
    }

    uint16_t candidate = (uint16_t)(get_rand_32() % UINT16_MAX) + 1u;
    for (uint32_t attempts = 0; attempts < UINT16_MAX; ++attempts)
    {
        if (!radio_local_address_used(received_local_addresses,
                                       received_count,
                                       candidate))
            return candidate;

        candidate = candidate == UINT16_MAX ? 1u : (uint16_t)(candidate + 1u);
    }

    return 0;
}


bool Respond_To_Connections_Request(uint32_t global_address,
                                     e32_t *radio,
                                     ftp_client_t *ftp,
                                     const radio_packet_t *request)
{
    if (radio == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_SEND_CONNECTIONS)
        return false;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    uint8_t response_data[RADIO_CONNECTIONS_PER_PACKET *
                          RADIO_CONNECTION_RECORD_SIZE];
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        uint8_t *record = &response_data[i * RADIO_CONNECTION_RECORD_SIZE];
        radio_write_u32_be(record, neighbors[i].global_address);
        radio_write_u16_be(&record[4], neighbors[i].local_address);
    }

    radio_packet_t response;
    if (!radio_packet_create(&response,
                             global_address,
                             request->source,
                             RADIO_CMD_DATA,
                             0,
                             request->sequence) ||
        !radio_packet_set_data(&response,
                               response_data,
                               (uint16_t)(neighbor_count *
                                          RADIO_CONNECTION_RECORD_SIZE)))
        return false;

    uint16_t e32_destination = 0xFFFF;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address == request->source)
        {
            e32_destination = neighbors[i].local_address;
            break;
        }
    }

    return radio_send_packet(radio, &response, e32_destination, 0);
}


bool Request_Global_Connections(uint32_t global_address,
                                e32_t *radio,
                                ftp_client_t *ftp)
{
    if (radio == NULL || ftp == NULL)
        return false;

    radio_neighbor_t oldest;
    if (!radio_find_oldest_neighbor(global_address, &oldest, ftp))
    {
        printf("No older neighbor found\n");
        return false;
    }

    static uint16_t sequence;
    ++sequence;

    radio_packet_t request;
    if (!radio_packet_create(&request,
                             global_address,
                             oldest.global_address,
                             RADIO_CMD_RECEIVE_GLOBAL_CONNECTIONS,
                             RADIO_FLAG_ACK_REQUEST,
                             sequence) ||
        !radio_send_packet(radio, &request, oldest.local_address, 0))
    {
        printf("Failed to request global connections from %08lX\n",
               (unsigned long)oldest.global_address);
        return false;
    }

    global_connections_file_length = 0;
    absolute_time_t timeout = make_timeout_time_ms(
        RADIO_GLOBAL_CONNECTIONS_RESPONSE_TIMEOUT_MS);
    uint32_t expected_length = 0;

    while (!time_reached(timeout))
    {
        radio_packet_t response;
        if (radio_receive_packet(radio, &response) &&
            response.command == RADIO_CMD_SEND_GLOBAL_CONNECTIONS &&
            response.destination == global_address &&
            response.source == oldest.global_address &&
            response.sequence >= sequence &&
            response.length >= RADIO_GLOBAL_CONNECTIONS_CHUNK_HEADER_SIZE)
        {
            uint32_t total_length = radio_read_u32_be(response.data);
            uint32_t offset = radio_read_u32_be(&response.data[4]);
            uint16_t chunk_length = (uint16_t)(response.length -
                                               RADIO_GLOBAL_CONNECTIONS_CHUNK_HEADER_SIZE);

            if (total_length <= sizeof(global_connections_file) &&
                total_length % RADIO_GLOBAL_CONNECTIONS_ROW_SIZE == 0 &&
                offset == global_connections_file_length &&
                chunk_length <= RADIO_GLOBAL_CONNECTIONS_CHUNK_SIZE &&
                offset + chunk_length <= total_length)
            {
                if (expected_length == 0)
                    expected_length = total_length;

                if (total_length == expected_length)
                {
                    memcpy(&global_connections_file[offset],
                           &response.data[RADIO_GLOBAL_CONNECTIONS_CHUNK_HEADER_SIZE],
                           chunk_length);
                    global_connections_file_length += chunk_length;

                    if (global_connections_file_length == expected_length)
                        break;
                }
            }
        }

        sleep_ms(1);
    }

    if (expected_length == 0 ||
        global_connections_file_length != expected_length)
    {
        printf("Global connections response timed out or was invalid\n");
        return false;
    }

    if (!ftp_upload(ftp,
                    RADIO_GLOBAL_CONNECTIONS_FILE,
                    global_connections_file,
                    (uint32_t)global_connections_file_length))
    {
        printf("FTP upload failed\n");
        ftp_disconnect(ftp);
        return false;
    }

    return true;
}


bool Respond_To_Global_Connections_Request(uint32_t global_address,
                                           e32_t *radio,
                                           ftp_client_t *ftp,
                                           const radio_packet_t *request)
{
    if (radio == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_RECEIVE_GLOBAL_CONNECTIONS)
        return false;

    global_connections_file_length = 0;
    global_connections_file_overflow = false;
    if (!ftp_download(ftp,
                      RADIO_GLOBAL_CONNECTIONS_FILE,
                      radio_global_connections_file_cb) ||
        global_connections_file_overflow ||
        global_connections_file_length == 0 ||
        global_connections_file_length % RADIO_GLOBAL_CONNECTIONS_ROW_SIZE != 0)
    {
        printf("FTP %s download failed or has an invalid format\n",
               RADIO_GLOBAL_CONNECTIONS_FILE);
        return false;
    }

    uint16_t e32_destination = 0;
    bool requester_found = false;
    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    {
        radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
        uint8_t neighbor_count = 0;
        if (radio_parse_neighbor_file(neighbors, &neighbor_count))
        {
            for (uint8_t i = 0; i < neighbor_count; ++i)
            {
                if (neighbors[i].global_address == request->source)
                {
                    e32_destination = neighbors[i].local_address;
                    requester_found = true;
                    break;
                }
            }
        }
    }

    if (!requester_found)
    {
        printf("Requester is not present in local_neighbors.txt\n");
        return false;
    }

    uint16_t chunk_sequence = request->sequence;
    for (uint32_t offset = 0;
         offset < global_connections_file_length;
         offset += RADIO_GLOBAL_CONNECTIONS_CHUNK_SIZE)
    {
        uint32_t remaining = (uint32_t)global_connections_file_length - offset;
        uint16_t chunk_length = (uint16_t)(remaining >
                                           RADIO_GLOBAL_CONNECTIONS_CHUNK_SIZE
                                               ? RADIO_GLOBAL_CONNECTIONS_CHUNK_SIZE
                                               : remaining);
        uint8_t response_data[RADIO_MAX_DATA];
        radio_write_u32_be(response_data, (uint32_t)global_connections_file_length);
        radio_write_u32_be(&response_data[4], offset);
        memcpy(&response_data[RADIO_GLOBAL_CONNECTIONS_CHUNK_HEADER_SIZE],
               &global_connections_file[offset],
               chunk_length);

        radio_packet_t response;
        if (!radio_packet_create(&response,
                                 global_address,
                                 request->source,
                                 RADIO_CMD_SEND_GLOBAL_CONNECTIONS,
                                 0,
                                 chunk_sequence++) ||
            !radio_packet_set_data(&response,
                                   response_data,
                                   (uint16_t)(RADIO_GLOBAL_CONNECTIONS_CHUNK_HEADER_SIZE +
                                              chunk_length)) ||
            !radio_send_packet(radio, &response, e32_destination, 0))
        {
            printf("Failed to send global connections chunk\n");
            return false;
        }
    }

    return true;
}


bool Request_Global_RSA_Keys(uint32_t global_address,
                             e32_t *radio,
                             ftp_client_t *ftp)
{
    if (radio == NULL || ftp == NULL)
        return false;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        for (uint8_t j = (uint8_t)(i + 1); j < neighbor_count; ++j)
        {
            if (neighbors[j].global_address < neighbors[i].global_address)
            {
                radio_neighbor_t swap = neighbors[i];
                neighbors[i] = neighbors[j];
                neighbors[j] = swap;
            }
        }
    }

    static uint16_t sequence;
    for (uint8_t neighbor_index = 0;
         neighbor_index < neighbor_count;
         ++neighbor_index)
    {
        radio_neighbor_t *provider = &neighbors[neighbor_index];
        if (provider->global_address == global_address)
            continue;

        for (uint8_t attempt = 0;
             attempt < RADIO_GLOBAL_RSA_KEYS_ATTEMPTS_PER_NEIGHBOR;
             ++attempt)
        {
            ++sequence;
            radio_packet_t request;
            if (!radio_packet_create(&request,
                                     global_address,
                                     provider->global_address,
                                     RADIO_CMD_RECEIVE_GLOBAL_RSA_KEYS,
                                     RADIO_FLAG_ACK_REQUEST,
                                     sequence) ||
                !radio_send_packet(radio, &request, provider->local_address, 0))
            {
                printf("Failed to request RSA keys from %08lX\n",
                       (unsigned long)provider->global_address);
                continue;
            }

            global_rsa_keys_file_length = 0;
            uint32_t expected_length = 0;
            uint32_t expected_crc = 0;
            absolute_time_t timeout = make_timeout_time_ms(
                RADIO_GLOBAL_RSA_KEYS_RESPONSE_TIMEOUT_MS);

            while (!time_reached(timeout))
            {
                radio_packet_t response;
                if (radio_receive_packet(radio, &response) &&
                    response.command == RADIO_CMD_SEND_GLOBAL_RSA_KEYS &&
                    response.destination == global_address &&
                    response.source == provider->global_address &&
                    response.sequence == sequence &&
                    response.length > RADIO_GLOBAL_RSA_KEYS_CHUNK_HEADER_SIZE)
                {
                    uint32_t total_length = radio_read_u32_be(response.data);
                    uint32_t offset = radio_read_u32_be(&response.data[4]);
                    uint32_t file_crc = radio_read_u32_be(&response.data[8]);
                    uint16_t chunk_length = (uint16_t)(response.length -
                        RADIO_GLOBAL_RSA_KEYS_CHUNK_HEADER_SIZE);

                    if (total_length > 0 &&
                        total_length <= sizeof(global_rsa_keys_file) &&
                        offset == global_rsa_keys_file_length &&
                        chunk_length <= RADIO_GLOBAL_RSA_KEYS_CHUNK_SIZE &&
                        offset + chunk_length <= total_length &&
                        (expected_length == 0 ||
                         (expected_length == total_length &&
                          expected_crc == file_crc)))
                    {
                        if (expected_length == 0)
                        {
                            expected_length = total_length;
                            expected_crc = file_crc;
                        }

                        memcpy(&global_rsa_keys_file[offset],
                               &response.data[RADIO_GLOBAL_RSA_KEYS_CHUNK_HEADER_SIZE],
                               chunk_length);
                        global_rsa_keys_file_length += chunk_length;

                        if (global_rsa_keys_file_length == expected_length)
                            break;
                    }
                }

                sleep_ms(1);
            }

            bool complete = expected_length > 0 &&
                            global_rsa_keys_file_length == expected_length &&
                            radio_crc32(global_rsa_keys_file,
                                        global_rsa_keys_file_length) == expected_crc;
            if (!complete)
            {
                printf("RSA key file from %08lX was incomplete or corrupted; retrying\n",
                       (unsigned long)provider->global_address);
                continue;
            }

            if (!ftp_upload(ftp,
                            RADIO_GLOBAL_RSA_KEYS_FILE,
                            global_rsa_keys_file,
                            (uint32_t)global_rsa_keys_file_length))
            {
                printf("FTP upload of %s failed\n", RADIO_GLOBAL_RSA_KEYS_FILE);
                ftp_disconnect(ftp);
                return false;
            }

            radio_packet_t acknowledgement;
            if (!radio_packet_create(&acknowledgement,
                                     global_address,
                                     provider->global_address,
                                     RADIO_CMD_ACK,
                                     RADIO_FLAG_ACK,
                                     sequence) ||
                !radio_send_packet(radio,
                                   &acknowledgement,
                                   provider->local_address,
                                   0))
            {
                printf("RSA key file saved, but provider acknowledgement failed\n");
                return false;
            }

            return true;
        }
    }

    printf("Could not retrieve a valid RSA key file from any neighbor\n");
    return false;
}


bool Respond_To_Global_RSA_Keys_Request(uint32_t global_address,
                                        e32_t *radio,
                                        ftp_client_t *ftp,
                                        const radio_packet_t *request)
{
    if (radio == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_RECEIVE_GLOBAL_RSA_KEYS)
        return false;

    global_rsa_keys_file_length = 0;
    global_rsa_keys_file_overflow = false;
    if (!ftp_download(ftp,
                      RADIO_GLOBAL_RSA_KEYS_FILE,
                      radio_global_rsa_keys_file_cb) ||
        global_rsa_keys_file_overflow ||
        global_rsa_keys_file_length == 0)
    {
        printf("FTP %s download failed or is empty/too large\n",
               RADIO_GLOBAL_RSA_KEYS_FILE);
        return false;
    }

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    uint16_t e32_destination = 0;
    bool requester_found = false;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address == request->source)
        {
            e32_destination = neighbors[i].local_address;
            requester_found = true;
            break;
        }
    }

    if (!requester_found)
    {
        printf("RSA key requester is not present in local_neighbors.txt\n");
        return false;
    }

    uint32_t file_crc = radio_crc32(global_rsa_keys_file,
                                    global_rsa_keys_file_length);
    uint32_t offset = 0;
    while (offset < global_rsa_keys_file_length)
    {
        uint32_t remaining = (uint32_t)global_rsa_keys_file_length - offset;
        uint16_t chunk_length = (uint16_t)(remaining >
                                            RADIO_GLOBAL_RSA_KEYS_CHUNK_SIZE
                                                ? RADIO_GLOBAL_RSA_KEYS_CHUNK_SIZE
                                                : remaining);
        uint8_t response_data[RADIO_MAX_DATA];
        radio_write_u32_be(response_data,
                           (uint32_t)global_rsa_keys_file_length);
        radio_write_u32_be(&response_data[4], offset);
        radio_write_u32_be(&response_data[8], file_crc);
        memcpy(&response_data[RADIO_GLOBAL_RSA_KEYS_CHUNK_HEADER_SIZE],
               &global_rsa_keys_file[offset],
               chunk_length);

        radio_packet_t response;
        if (!radio_packet_create(&response,
                                 global_address,
                                 request->source,
                                 RADIO_CMD_SEND_GLOBAL_RSA_KEYS,
                                 0,
                                 request->sequence) ||
            !radio_packet_set_data(&response,
                                   response_data,
                                   (uint16_t)(RADIO_GLOBAL_RSA_KEYS_CHUNK_HEADER_SIZE +
                                              chunk_length)) ||
            !radio_send_packet(radio, &response, e32_destination, 0))
        {
            printf("Failed to send RSA key file chunk\n");
            return false;
        }

        offset += chunk_length;
    }

    return true;
}


bool Find_Shortest_Global_Route(uint32_t source,
                                uint32_t destination,
                                ftp_client_t *ftp,
                                uint32_t *path,
                                uint8_t *path_length)
{
    if (ftp == NULL || path == NULL || path_length == NULL)
        return false;

    *path_length = 0;

    global_connections_file_length = 0;
    global_connections_file_overflow = false;
    if (!ftp_download(ftp,
                      RADIO_GLOBAL_CONNECTIONS_FILE,
                      radio_global_connections_file_cb) ||
        global_connections_file_overflow ||
        global_connections_file_length == 0 ||
        global_connections_file_length % RADIO_GLOBAL_CONNECTIONS_ROW_SIZE != 0)
    {
        printf("FTP %s download failed or has an invalid format\n",
               RADIO_GLOBAL_CONNECTIONS_FILE);
        return false;
    }

    if (source == destination)
    {
        path[0] = source;
        *path_length = 1;
        return true;
    }

    uint32_t nodes[RADIO_GLOBAL_CONNECTIONS_MAX_NODES];
    int16_t parent[RADIO_GLOBAL_CONNECTIONS_MAX_NODES];
    uint8_t depth[RADIO_GLOBAL_CONNECTIONS_MAX_NODES];
    uint16_t queue[RADIO_GLOBAL_CONNECTIONS_MAX_NODES];
    size_t node_count = 0;
    size_t row_count = global_connections_file_length /
                       RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;

    for (size_t row = 0; row < row_count; ++row)
    {
        for (uint8_t column = 0; column < 9; ++column)
        {
            uint32_t address;
            memcpy(&address,
                   &global_connections_file[row * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE +
                                            column * sizeof(uint32_t)],
                   sizeof(address));

            if (address == 0)
                continue;

            bool already_present = false;
            for (size_t i = 0; i < node_count; ++i)
            {
                if (nodes[i] == address)
                {
                    already_present = true;
                    break;
                }
            }

            if (!already_present && node_count < RADIO_GLOBAL_CONNECTIONS_MAX_NODES)
            {
                nodes[node_count] = address;
                parent[node_count] = -1;
                depth[node_count] = 0;
                ++node_count;
            }
        }
    }

    size_t source_index = node_count;
    size_t destination_index = node_count;
    for (size_t i = 0; i < node_count; ++i)
    {
        if (nodes[i] == source)
            source_index = i;
        if (nodes[i] == destination)
            destination_index = i;
    }

    if (source_index == node_count || destination_index == node_count)
    {
        printf("It is not possible to connect to %08lX\n",
               (unsigned long)destination);
        return false;
    }

    size_t queue_head = 0;
    size_t queue_tail = 0;
    queue[queue_tail++] = (uint16_t)source_index;
    parent[source_index] = -2;

    while (queue_head < queue_tail && parent[destination_index] == -1)
    {
        size_t current_index = queue[queue_head++];
        if (depth[current_index] >= RADIO_GLOBAL_ROUTE_MAX_JUMPS)
            continue;

        size_t row = row_count;
        for (size_t candidate_row = 0; candidate_row < row_count; ++candidate_row)
        {
            uint32_t row_node;
            memcpy(&row_node,
                   &global_connections_file[candidate_row * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE],
                   sizeof(row_node));
            if (row_node == nodes[current_index])
            {
                row = candidate_row;
                break;
            }
        }

        if (row == row_count)
            continue;

        for (uint8_t column = 1; column < 9; ++column)
        {
            uint32_t neighbor;
            memcpy(&neighbor,
                   &global_connections_file[row * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE +
                                            column * sizeof(uint32_t)],
                   sizeof(neighbor));
            if (neighbor == 0)
                continue;

            size_t neighbor_index = node_count;
            for (size_t i = 0; i < node_count; ++i)
            {
                if (nodes[i] == neighbor)
                {
                    neighbor_index = i;
                    break;
                }
            }

            if (neighbor_index == node_count || parent[neighbor_index] != -1)
                continue;

            parent[neighbor_index] = (int16_t)current_index;
            depth[neighbor_index] = (uint8_t)(depth[current_index] + 1);
            queue[queue_tail++] = (uint16_t)neighbor_index;
        }
    }

    if (parent[destination_index] == -1)
    {
        printf("It is not possible to connect to %08lX within %u jumps\n",
               (unsigned long)destination,
               RADIO_GLOBAL_ROUTE_MAX_JUMPS);
        return false;
    }

    uint16_t reverse_path[RADIO_GLOBAL_ROUTE_MAX_ADDRESSES];
    uint8_t reverse_length = 0;
    for (int16_t current = (int16_t)destination_index;
         current != -2 && reverse_length < RADIO_GLOBAL_ROUTE_MAX_ADDRESSES;
         current = parent[current])
    {
        reverse_path[reverse_length++] = (uint16_t)current;
    }

    if (reverse_length == 0 || reverse_length > RADIO_GLOBAL_ROUTE_MAX_ADDRESSES)
        return false;

    for (uint8_t i = 0; i < reverse_length; ++i)
        path[i] = nodes[reverse_path[reverse_length - i - 1]];

    *path_length = reverse_length;
    return true;
}


bool Relay_New_Node(uint32_t global_address,
                    e32_t *radio,
                    ftp_client_t *ftp)
{
    if (radio == NULL || ftp == NULL || global_address == 0)
        return false;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    uint8_t node_record[RADIO_NEW_NODE_RECORD_SIZE] = {0};
    radio_write_u32_be(node_record, global_address);
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address != global_address)
        {
            radio_write_u32_be(&node_record[(i + 1u) * sizeof(uint32_t)],
                               neighbors[i].global_address);
        }
    }

    static uint16_t sequence;
    bool sent = true;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        radio_packet_t packet;
        if (!radio_packet_create(&packet,
                                 global_address,
                                 neighbors[i].global_address,
                                 RADIO_CMD_RELAY_NEW_NODE,
                                 RADIO_FLAG_ACK_REQUEST,
                                 ++sequence) ||
                        !radio_packet_set_data(&packet,
                                                                     node_record,
                                                                     sizeof(node_record)) ||
            !radio_send_packet(radio, &packet, neighbors[i].local_address, 0))
        {
            printf("Failed to announce new node to %08lX\n",
                   (unsigned long)neighbors[i].global_address);
            sent = false;
        }
    }

    return sent;
}


bool Respond_To_New_Node(uint32_t global_address,
                         e32_t *radio,
                         ftp_client_t *ftp,
                         const radio_packet_t *request)
{
    if (radio == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_RELAY_NEW_NODE ||
        request->source == 0 ||
        request->length != RADIO_NEW_NODE_RECORD_SIZE)
        return false;

    uint32_t new_global_address = request->source;
    if (radio_read_u32_be(request->data) != new_global_address)
        return false;

    /* The origin already knows its own address; do not bounce the packet. */
    if (new_global_address == global_address)
        return true;

    uint32_t announced_neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t announced_count = 0;
    for (uint8_t i = 0; i < RADIO_NEIGHBOR_COUNT_MAX; ++i)
    {
        uint32_t neighbor = radio_read_u32_be(
            &request->data[(i + 1u) * sizeof(uint32_t)]);
        if (neighbor == 0)
            continue;
        if (neighbor == new_global_address)
            return false;

        for (uint8_t j = 0; j < announced_count; ++j)
        {
            if (announced_neighbors[j] == neighbor)
                return false;
        }
        announced_neighbors[announced_count++] = neighbor;
    }

    if (!radio_download_global_connections(ftp))
    {
        printf("FTP %s download failed or has an invalid format\n",
               RADIO_GLOBAL_CONNECTIONS_FILE);
        return false;
    }

    bool already_known = radio_global_connection_saved(new_global_address);
    bool changed = false;
    size_t new_node_row;
    if (!radio_ensure_global_connection_row(new_global_address,
                                            &new_node_row,
                                            &changed))
    {
        printf("Could not create a connection row for %08lX\n",
               (unsigned long)new_global_address);
        return false;
    }

    for (uint8_t i = 0; i < announced_count; ++i)
    {
        if (!radio_add_connection_edge(new_global_address,
                                       announced_neighbors[i],
                                       &changed))
        {
            printf("Could not add connection between %08lX and %08lX\n",
                   (unsigned long)new_global_address,
                   (unsigned long)announced_neighbors[i]);
            return false;
        }
    }

    if (changed &&
        !ftp_upload(ftp,
                    RADIO_GLOBAL_CONNECTIONS_FILE,
                    global_connections_file,
                    (uint32_t)global_connections_file_length))
    {
        printf("FTP upload failed\n");
        ftp_disconnect(ftp);
        return false;
    }

    /* Known nodes may need missing graph edges repaired, but not rebroadcast. */
    if (already_known)
        return true;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    static uint16_t sequence;
    bool sent = true;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        radio_packet_t packet;
        if (!radio_packet_create(&packet,
                                 new_global_address,
                                 neighbors[i].global_address,
                                 RADIO_CMD_RELAY_NEW_NODE,
                                 RADIO_FLAG_ACK_REQUEST,
                                 ++sequence) ||
                        !radio_packet_set_data(&packet,
                                                                     request->data,
                                                                     request->length) ||
            !radio_send_packet(radio, &packet, neighbors[i].local_address, 0))
        {
            printf("Failed to relay new node to %08lX\n",
                   (unsigned long)neighbors[i].global_address);
            sent = false;
        }
    }

    return sent;
}


bool Relay_RSA_Public_Key(uint32_t global_address,
                          mpz_t public_modulo,
                          e32_t *radio,
                          ftp_client_t *ftp)
{
    if (global_address == 0 || radio == NULL || ftp == NULL)
        return false;

    uint8_t modulus[RADIO_RSA_PUBLIC_MODULUS_SIZE];
    if (!radio_encode_rsa_public_modulus(public_modulo, modulus))
    {
        printf("Public RSA modulo must be a positive 2048-bit value\n");
        return false;
    }

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    static uint16_t sequence;
    bool sent = true;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address == global_address)
            continue;

        radio_packet_t packet;
        if (!radio_packet_create(&packet,
                                 global_address,
                                 neighbors[i].global_address,
                                 RADIO_CMD_RELAY_RSA_KEYS,
                                 RADIO_FLAG_ACK_REQUEST,
                                 ++sequence) ||
            !radio_packet_set_data(&packet, modulus, sizeof(modulus)) ||
            !radio_send_packet(radio, &packet, neighbors[i].local_address, 0))
        {
            printf("Failed to relay RSA public key to %08lX\n",
                   (unsigned long)neighbors[i].global_address);
            sent = false;
        }
    }

    return sent;
}


bool Respond_To_RSA_Key_Relay(uint32_t global_address,
                              e32_t *radio,
                              ftp_client_t *ftp,
                              const radio_packet_t *request)
{
    if (radio == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_RELAY_RSA_KEYS ||
        request->source == 0 ||
        request->length != RADIO_RSA_PUBLIC_MODULUS_SIZE ||
        !radio_valid_rsa_public_modulus(request->data))
        return false;

    uint32_t owner_address = request->source;

    /* The originating node receives its own relay and already has the key. */
    if (owner_address == global_address)
        return true;

    global_rsa_keys_file_length = 0;
    global_rsa_keys_file_overflow = false;
    if (!ftp_download(ftp,
                      RADIO_GLOBAL_RSA_KEYS_FILE,
                      radio_global_rsa_keys_file_cb) ||
        global_rsa_keys_file_overflow ||
        global_rsa_keys_file_length % RADIO_RSA_KEY_ROW_SIZE != 0)
    {
        printf("FTP %s download failed or has an invalid row format\n",
               RADIO_GLOBAL_RSA_KEYS_FILE);
        return false;
    }

    if (radio_rsa_key_address_saved(owner_address))
        return true;

    if (global_rsa_keys_file_length + RADIO_RSA_KEY_ROW_SIZE >
        sizeof(global_rsa_keys_file))
    {
        printf("RSA public key list is full\n");
        return false;
    }

    size_t row_offset = global_rsa_keys_file_length;
    radio_write_u32_be(&global_rsa_keys_file[row_offset], owner_address);
    memcpy(&global_rsa_keys_file[row_offset + sizeof(uint32_t)],
           request->data,
           RADIO_RSA_PUBLIC_MODULUS_SIZE);
    global_rsa_keys_file_length += RADIO_RSA_KEY_ROW_SIZE;

    if (!ftp_upload(ftp,
                    RADIO_GLOBAL_RSA_KEYS_FILE,
                    global_rsa_keys_file,
                    (uint32_t)global_rsa_keys_file_length))
    {
        printf("FTP upload of %s failed\n", RADIO_GLOBAL_RSA_KEYS_FILE);
        ftp_disconnect(ftp);
        return false;
    }

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    static uint16_t sequence;
    bool sent = true;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address == global_address)
            continue;

        radio_packet_t relay;
        if (!radio_packet_create(&relay,
                                 owner_address,
                                 neighbors[i].global_address,
                                 RADIO_CMD_RELAY_RSA_KEYS,
                                 RADIO_FLAG_ACK_REQUEST,
                                 ++sequence) ||
            !radio_packet_set_data(&relay,
                                   request->data,
                                   RADIO_RSA_PUBLIC_MODULUS_SIZE) ||
            !radio_send_packet(radio, &relay, neighbors[i].local_address, 0))
        {
            printf("Failed to forward RSA public key to %08lX\n",
                   (unsigned long)neighbors[i].global_address);
            sent = false;
        }
    }

    return sent;
}

bool Respond_To_Local_Address(uint32_t global_address,
                              e32_t *radio,
                              ftp_client_t *ftp,
                              const radio_packet_t *request);


                              
bool Handle_Radio_Packet(uint32_t global_address,
                         e32_t *radio,
                         ftp_client_t *ftp,
                         const radio_packet_t *packet)
{
    if (packet == NULL)
        return false;

    if (packet->command == RADIO_CMD_SEND_CONNECTIONS)
    {
        return Respond_To_Connections_Request(global_address,
                                               radio,
                                               ftp,
                                               packet);
    }

    if (packet->command == RADIO_CMD_SEND_LOCAL_ADRESS)
    {
        return Respond_To_Local_Address(global_address,
                                        radio,
                                        ftp,
                                        packet);
    }

    if (packet->command == RADIO_CMD_RECEIVE_GLOBAL_CONNECTIONS)
    {
        return Respond_To_Global_Connections_Request(global_address,
                                                     radio,
                                                     ftp,
                                                     packet);
    }

    if (packet->command == RADIO_CMD_RECEIVE_GLOBAL_RSA_KEYS)
    {
        return Respond_To_Global_RSA_Keys_Request(global_address,
                                                  radio,
                                                  ftp,
                                                  packet);
    }

    if (packet->command == RADIO_CMD_RELAY_NEW_NODE)
    {
        return Respond_To_New_Node(global_address,
                                   radio,
                                   ftp,
                                   packet);
    }

    if (packet->command == RADIO_CMD_RELAY_RSA_KEYS)
    {
        return Respond_To_RSA_Key_Relay(global_address,
                                        radio,
                                        ftp,
                                        packet);
    }

    return false;
}


void Find_Neighbors(uint32_t Global_Adress, e32_t *radio, ftp_client_t *ftp) {

    radio_packet_t ping_packet;

    radio_packet_create(
        &ping_packet,
        Global_Adress,        // Global source
        0xFFFFFFFF,           // Global destination, aka everyone in radio range
        RADIO_CMD_PING,           // Command
        RADIO_FLAG_ACK_REQUEST,   // Ask nodes to respond
        1                         // Sequence number
    );

    radio_send_packet(
        radio,
        &ping_packet,
        0xFFFF,                   // E32 broadcast address
        0                         // E32 channel
    );
    
    // Wait for a response

    printf("Global PING sent. Listening for neighbors...\n");

    /* Store both addresses for each neighbor */
    typedef struct
    {
        uint32_t global_address;
        uint16_t local_address;
    } neighbor_t;

    static neighbor_t neighbors[8];
    static uint8_t neighbor_count = 0;

    absolute_time_t timeout =
        make_timeout_time_ms(5000);


    /* Listen for PONG responses */
    while (!time_reached(timeout))
    {
        radio_packet_t response;

        if (radio_receive_packet(radio, &response))
        {
            if (response.command == RADIO_CMD_PONG)
            {
                if (response.destination == Global_Adress &&
                    response.sequence == 1)
                {
                    printf(
                        "PONG received from %08lX\n",
                        (unsigned long)response.source
                    );

                    /* Add neighbor if there is room */
                    if (neighbor_count < 8)
                    {
                        neighbors[neighbor_count].global_address =
                            response.source;

                        neighbors[neighbor_count].local_address =
                            (uint16_t)(((uint16_t)response.data[0] << 8) |
                                       response.data[1]);

                        neighbor_count++;

                        printf(
                            "Neighbor Added: Global=%08lX Local=%u\n",
                            (unsigned long)response.source,
                            (unsigned int)neighbors[neighbor_count - 1].local_address
                        );
                    }
                }
            }
        }

        sleep_ms(1);
    }


    /* No neighbors found */
    if (neighbor_count == 0)
    {
        printf("No neighbors found\n");
        return;
    }


    /*
    * Build the neighbor file.
    *
    * Format:
    * NEIGHBOR_GLOBAL_ADDRESS,NEIGHBOR_LOCAL_ADDRESS
    * NEIGHBOR_GLOBAL_ADDRESS,NEIGHBOR_LOCAL_ADDRESS
    * ...
    */
    
    char neighbor_file[256];
    size_t offset = 0;



    /* Write each neighbor */
    for (uint8_t i = 0; i < neighbor_count; i++)
    {
        int len = snprintf(
            neighbor_file + offset,
            sizeof(neighbor_file) - offset,
            "%08lX,%u\n",
            (unsigned long)neighbors[i].global_address,
            (unsigned int)neighbors[i].local_address
        );

        if (len < 0)
        {
            printf("Failed to format neighbor address\n");
            return;
        }

        offset += len;

        if (offset >= sizeof(neighbor_file))
        {
            printf("Neighbor file buffer full\n");
            return;
        }
    }


    /* Upload the complete file */
    if (!ftp_upload(
            ftp,
            "local_neighbors.txt",
            (uint8_t *)neighbor_file,
            offset))
    {
        printf("FTP upload failed\n");
        ftp_disconnect(ftp);
        return;
    }

    printf("FTP upload ok\n");
};


void Ping_Response(uint32_t Global_Adress,
                   uint16_t Local_Adress,
                   e32_t *radio,
                   ftp_client_t *ftp,
                   radio_packet_t sender_packet)
{
    if (radio == NULL || ftp == NULL)
        return;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return;
    }

    if (neighbor_count >= RADIO_NEIGHBOR_COUNT_MAX)
    {
        printf("Neighbor limit reached; PONG not sent\n");
        return;
    }

    radio_packet_t pong_packet;

    radio_packet_create(
        &pong_packet,
        sender_packet.source,        // Send PONG back to whoever pinged us
        Global_Adress,              // Our global address
        RADIO_CMD_PONG,
        0,
        sender_packet.sequence      // Match the ping sequence
    );

    uint8_t pong_data[2];

    pong_data[0] = (Local_Adress >> 8) & 0xFF;
    pong_data[1] = Local_Adress & 0xFF;

    radio_packet_set_data(
        &pong_packet,
        pong_data,
        2
    );


    radio_send_packet(
        radio,
        &pong_packet,
        0xFFFF,
        0
    );
};


bool Send_Local_Adress_To_Neighbors(uint32_t global_address,
                                    uint16_t local_address,
                                    e32_t *radio,
                                    ftp_client_t *ftp)
{
    if (radio == NULL || ftp == NULL)
        return false;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    uint8_t address_data[2];
    radio_write_u16_be(address_data, local_address);

    bool sent = true;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        radio_packet_t packet;
        if (!radio_packet_create(&packet,
                                 global_address,
                                 neighbors[i].global_address,
                                 RADIO_CMD_SEND_LOCAL_ADRESS,
                                 RADIO_FLAG_ACK_REQUEST,
                                 (uint16_t)(i + 1)) ||
            !radio_packet_set_data(&packet, address_data, sizeof(address_data)) ||
            !radio_send_packet(radio, &packet, neighbors[i].local_address, 0))
        {
            printf("Failed to send local address to %08lX\n",
                   (unsigned long)neighbors[i].global_address);
            sent = false;
        }
    }

    return sent;
}

bool Respond_To_Local_Address(uint32_t global_address,
                              e32_t *radio,
                              ftp_client_t *ftp,
                              const radio_packet_t *request)
{
    if (radio == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_SEND_LOCAL_ADRESS ||
        request->length != sizeof(uint16_t))
        return false;

    uint16_t local_address = (uint16_t)(((uint16_t)request->data[0] << 8) |
                                        request->data[1]);

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    bool has_neighbors = radio_parse_neighbor_file(neighbors, &neighbor_count);

    for (uint8_t i = 0; has_neighbors && i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address == request->source)
        {
            neighbors[i].local_address = local_address;
            goto upload_neighbors;
        }
    }

    if (neighbor_count >= RADIO_NEIGHBOR_COUNT_MAX)
    {
        printf("Neighbor limit reached; local address not stored\n");
        return false;
    }

    neighbors[neighbor_count].global_address = request->source;
    neighbors[neighbor_count].local_address = local_address;
    ++neighbor_count;

upload_neighbors:
    {
        uint8_t output[sizeof(neighbor_file)];
        size_t output_length = 0;

        for (uint8_t i = 0; i < neighbor_count; ++i)
        {
            int written = snprintf((char *)&output[output_length],
                                   sizeof(output) - output_length,
                                   "%08lX,%u\n",
                                   (unsigned long)neighbors[i].global_address,
                                   (unsigned int)neighbors[i].local_address);
            if (written < 0 || (size_t)written >= sizeof(output) - output_length)
                return false;

            output_length += (size_t)written;
        }

        return ftp_upload(ftp,
                          "local_neighbors.txt",
                          output,
                          (uint32_t)output_length);
    }
}

e32_t radio;

bool Create_DH_Exchange_Packet(uint32_t target_global_address,
                               uint32_t personal_global_address,
                               const uint32_t *route,
                               uint8_t *route_length,
                               uint16_t first_hop_local_address,
                               mpz_t private_rsa_exponent,
                               mpz_t rsa_modulus)
{
    if (route == NULL || route_length == NULL || *route_length < 2 ||
        *route_length > RADIO_MAX_ROUTE_ADDRESSES ||
        route[0] != personal_global_address ||
        route[*route_length - 1u] != target_global_address ||
        mpz_sgn(private_rsa_exponent) <= 0 || mpz_sgn(rsa_modulus) <= 0)
        return false;

    mpz_t private_number;
    mpz_t sending_number;
    mpz_t modulus;
    mpz_t random_number;
    mpz_t seed;
    mpz_t generator;
    mpz_t packed_message;
    mpz_t cipher_text;

    mpz_init(private_number);
    mpz_init(sending_number);
    mpz_init(modulus);
    mpz_init(random_number);
    mpz_init(seed);
    mpz_init(generator);
    mpz_init(packed_message);
    mpz_init(cipher_text);

    bool success = false;
    uint8_t cipher_bytes[RADIO_DH_RSA_CIPHERTEXT_MAX_SIZE];

    do
    {
        generate_random_seed(seed, 256);
        generate_random_number(seed,
                              random_number,
                              RADIO_DH_MODULUS_BITS,
                              256);
        mpz_setbit(random_number, RADIO_DH_MODULUS_BITS - 1u);
        mpz_setbit(random_number, 0);
        generate_random_prime_number(random_number, modulus);
    } while (mpz_sizeinbase(modulus, 2) > RADIO_DH_MODULUS_BITS);

    mpz_set_ui(generator, 2);
    DH_Generate_Private_Number(private_number);
    DH_Generate_Sending_Number(sending_number,
                               generator,
                               modulus,
                               private_number);

    if (mpz_sgn(sending_number) < 0 ||
        mpz_sizeinbase(sending_number, 2) > RADIO_DH_MODULUS_BITS)
        goto cleanup;

    mpz_mul_2exp(packed_message, modulus, RADIO_DH_MODULUS_BITS);
    mpz_add(packed_message, packed_message, sending_number);

    if (mpz_cmp(packed_message, rsa_modulus) >= 0)
    {
        printf("RSA modulus is too small for the packed DH values\n");
        goto cleanup;
    }

    RSA_encrypt(packed_message,
                private_rsa_exponent,
                rsa_modulus,
                cipher_text);

    size_t cipher_length = (mpz_sizeinbase(rsa_modulus, 2) + 7u) / 8u;
    if (cipher_length == 0 ||
        cipher_length > sizeof(cipher_bytes))
    {
        printf("RSA ciphertext exceeds the supported fragment limit\n");
        goto cleanup;
    }

    memset(cipher_bytes, 0, sizeof(cipher_bytes));
    size_t exported_length = 0;
    mpz_export(cipher_bytes,
               &exported_length,
               1,
               1,
               1,
               0,
               cipher_text);
    if (exported_length > cipher_length)
        goto cleanup;

    if (exported_length < cipher_length)
    {
        memmove(&cipher_bytes[cipher_length - exported_length],
                cipher_bytes,
                exported_length);
        memset(cipher_bytes, 0, cipher_length - exported_length);
    }

    static uint16_t sequence;
    ++sequence;
    for (size_t offset = 0; offset < cipher_length;)
    {
        size_t remaining = cipher_length - offset;
        uint16_t fragment_length = (uint16_t)(remaining >
                                               RADIO_DH_RSA_FRAGMENT_DATA_SIZE
                                                   ? RADIO_DH_RSA_FRAGMENT_DATA_SIZE
                                                   : remaining);
        uint8_t fragment_data[RADIO_MAX_DATA];
        radio_write_u16_be(fragment_data, (uint16_t)cipher_length);
        radio_write_u16_be(&fragment_data[2], (uint16_t)offset);
        memcpy(&fragment_data[RADIO_DH_RSA_FRAGMENT_HEADER_SIZE],
               &cipher_bytes[offset],
               fragment_length);

        radio_packet_t packet;
        if (!radio_packet_create(&packet,
                                 personal_global_address,
                                 target_global_address,
                                 RADIO_CMD_SEND_ENCRYPTION_REQUEST,
                                 RADIO_FLAG_ACK_REQUEST | RADIO_FLAG_FRAGMENT,
                                 sequence) ||
            !radio_packet_set_path(&packet, route, *route_length) ||
            !radio_packet_set_data(&packet,
                                   fragment_data,
                                   (uint16_t)(RADIO_DH_RSA_FRAGMENT_HEADER_SIZE +
                                              fragment_length)) ||
            !radio_send_packet(&radio,
                               &packet,
                               first_hop_local_address,
                               0))
        {
            printf("Failed to send encryption request to %08lX\n",
                   (unsigned long)target_global_address);
            goto cleanup;
        }

        offset += fragment_length;
    }

    success = true;

cleanup:
    mpz_clear(private_number);
    mpz_clear(sending_number);
    mpz_clear(modulus);
    mpz_clear(random_number);
    mpz_clear(seed);
    mpz_clear(generator);
    mpz_clear(packed_message);
    mpz_clear(cipher_text);
    return success;
}
