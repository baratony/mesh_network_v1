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

#define RADIO_NEIGHBOR_FILE_MAX_SIZE 1024
#define RADIO_NEIGHBOR_COUNT_MAX 8
#define RADIO_CONNECTION_RECORD_SIZE 6
#define RADIO_CONNECTIONS_PER_PACKET 8
#define RADIO_CONNECTION_RESPONSE_TIMEOUT_MS 5000


typedef struct
{
    uint32_t global_address;
    uint16_t local_address;
} radio_neighbor_t;


static uint8_t neighbor_file[RADIO_NEIGHBOR_FILE_MAX_SIZE + 1];
static size_t neighbor_file_length;
static bool neighbor_file_overflow;


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