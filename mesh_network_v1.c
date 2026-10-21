/* ============================================================================
 * mesh_network_v1.c
 *
 * Core 0 : W5500 / Ethernet  - HTTP requests and the HTML control panel.
 * Core 1 : E32 radio          - wake the module, receive packets, sort them
 *                              and run the matching protocol handler.
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/mutex.h"
#include "hardware/rtc.h"
#include "hardware/uart.h"

#include "Ethernet_FTP/ethernet_setup.h"
#include "Ethernet_FTP/ftp_client.h"
#include "Website/site_server.h"
#include "Website/site_actions.h"
#include "Radio/ebyte_e32.h"
#include "Radio/radio.h"
#include "Radio/radio_packet_protocol.h"
#include "Cryptographic_Functions/Cryptographic_Functions.h"

/* ---------------------------------------------------------------------------
 * 1. Node configuration
 * --------------------------------------------------------------------------- */

/* E32 module: UART data lines + M0/M1 control lines. */
#define RADIO_UART        uart1
#define RADIO_TX_PIN      4
#define RADIO_RX_PIN      5
#define RADIO_M0_PIN      6
#define RADIO_M1_PIN      7
#define RADIO_CHANNEL     0
#define E32_BROADCAST     0xFFFFu

/* Control panel outputs driven by RADIO_CMD_SET_OUTPUT. */
#define OUTPUT_FIRST_PIN  10
#define OUTPUT_LAST_PIN   13

/* Creation date used to build the global address. */
#define NODE_CREATION_YEAR  2026
#define NODE_CREATION_MONTH 9
#define NODE_CREATION_DAY   6

/* File that keeps this node's own RSA key pair. */
#define NODE_KEY_FILE       "node_rsa_key.txt"
#define NODE_KEY_FILE_MAX   1024

/* ---------------------------------------------------------------------------
 * 2. Shared node state
 * --------------------------------------------------------------------------- */

static ftp_client_t node_ftp;

static uint32_t node_global_address;
static uint16_t node_local_address;

static mpz_t rsa_private_exponent;
static mpz_t rsa_public_modulus;
static mpz_t shared_secret;
static bool shared_secret_valid;

/* shared_secret is only meaningful together with the node it belongs to:
 * there is exactly one exchange in flight at a time, so the peer has to be
 * remembered next to it. A private letter can only be opened by that node. */
static uint32_t shared_secret_peer;

/* A zero bignum to hand to Respond_To_Private_Message when the letter did not
 * come from the node this shared secret belongs to. The handler rejects a
 * non-positive secret, so an unrelated letter is simply not opened. */
static mpz_t shared_secret_empty;

/* The W5500 is shared between the two cores: Core 0 answers HTTP requests
   while Core 1 runs FTP. Every network access must be serialised.
   NOTE: the FTP calls inside radio.c must use the same lock. */
static lock_t network_lock;

static void network_lock_enter(void) { lock_enter(&network_lock); }
static void network_lock_exit(void)  { lock_exit(&network_lock); }

/* ---------------------------------------------------------------------------
 * 3. Small helpers
 * --------------------------------------------------------------------------- */

/* Export an mpz as a fixed size big-endian block (used as the AEAD key). */
static void mpz_to_fixed_be(mpz_t value, uint8_t *out, size_t length)
{
    memset(out, 0, length);

    char *text = mpz_get_str(NULL, 16, value);
    if (text == NULL)
        return;

    size_t digits = strlen(text);
    size_t max_digits = length * 2u;

    if (digits > max_digits)
        digits = max_digits;

    for (size_t i = 0; i < digits; i += 2)
    {
        size_t offset = max_digits - digits + i;
        unsigned int byte = 0;

        if (offset >= 2)
            sscanf(text + (offset - 2u), "%2x", &byte);
        else
            sscanf(text, "%2x", &byte);

        out[offset / 2u] = (uint8_t)byte;
    }

    free(text);
}

/* Send a reply back to the node that sent the packet. */
static bool send_reply(const radio_packet_t *request,
                       uint16_t command,
                       const uint8_t *data,
                       uint16_t length)
{
    radio_packet_t reply;

    if (!radio_packet_create(&reply,
                             node_global_address,
                             request->source,
                             command,
                             0,
                             request->sequence))
        return false;

    if (length > 0 && !radio_packet_set_data(&reply, data, length))
        return false;

    uint16_t next_hop = E32_BROADCAST;

    network_lock_enter();
    if (!radio_find_neighbor_local_address(&node_ftp, request->source, &next_hop))
        next_hop = E32_BROADCAST;
    network_lock_exit();

    return radio_send_packet(&radio, &reply, next_hop, RADIO_CHANNEL);
}

/* ---------------------------------------------------------------------------
 * 4. Packet sorting
 *
 * Before a packet is dispatched it is checked:
 *   - is it addressed to us (or a broadcast)?
 *   - have we already handled it (duplicate / retransmission)?
 * --------------------------------------------------------------------------- */

#define RECENT_PACKETS 16

static uint32_t recent_packets[RECENT_PACKETS];
static uint8_t recent_count;

static bool packet_is_for_us(const radio_packet_t *packet)
{
    if (packet->destination == node_global_address)
        return true;

    if (packet->destination == 0xFFFFFFFFu ||
        (packet->flags & RADIO_FLAG_BROADCAST))
        return true;

    return false;
}

static bool packet_already_seen(const radio_packet_t *packet)
{
    uint32_t key = packet->source ^
                   (uint32_t)packet->sequence ^
                   ((uint32_t)packet->command << 12);

    for (uint8_t i = 0; i < recent_count; ++i)
    {
        if (recent_packets[i] == key)
            return true;
    }

    recent_packets[recent_count] = key;
    recent_count = (uint8_t)((recent_count + 1u) % RECENT_PACKETS);

    return false;
}

/* ---------------------------------------------------------------------------
 * 5. Command handlers that do not exist in radio.c
 * --------------------------------------------------------------------------- */

static void handle_pong(const radio_packet_t *packet)
{
    if (packet->length >= 2)
    {
        uint16_t sender_local = (uint16_t)(((uint16_t)packet->data[0] << 8) |
                                           packet->data[1]);

        printf("[RADIO] PONG from %08lX (local %u)\n",
               (unsigned long)packet->source,
               (unsigned int)sender_local);
    }
    else
    {
        printf("[RADIO] PONG from %08lX\n", (unsigned long)packet->source);
    }
}

static void handle_ack(const radio_packet_t *packet)
{
    printf("[RADIO] ACK for packet %u from %08lX\n",
           (unsigned int)packet->sequence,
           (unsigned long)packet->source);
}

static void handle_data_packet(const radio_packet_t *packet)
{
    if (packet->length == 0)
        return;

    /* Payload format used when the packet is encrypted:
     *   nonce (12) + ciphertext + tag (16) */
    if ((packet->flags & RADIO_FLAG_ENCRYPTED) && shared_secret_valid)
    {
        if (packet->length < 12u + 16u)
        {
            printf("[RADIO] Encrypted data packet is too short\n");
            return;
        }

        uint8_t key[32];
        mpz_to_fixed_be(shared_secret, key, sizeof(key));

        const uint8_t *nonce = packet->data;
        const uint8_t *ciphertext = packet->data + 12u;
        const uint8_t *tag = packet->data + packet->length - 16u;
        size_t ciphertext_length = packet->length - 12u - 16u;

        uint8_t plaintext[RADIO_MAX_DATA];

        if (chacha20poly1305_decrypt(key,
                                     nonce,
                                     ciphertext,
                                     ciphertext_length,
                                     tag,
                                     plaintext) != 0)
        {
            printf("[RADIO] Data from %08lX failed authentication\n",
                   (unsigned long)packet->source);
            return;
        }

        printf("[RADIO] Data from %08lX: %.*s\n",
               (unsigned long)packet->source,
               (int)ciphertext_length,
               (char *)plaintext);

        return;
    }

    printf("[RADIO] Data from %08lX: %.*s\n",
           (unsigned long)packet->source,
           (int)packet->length,
           (char *)packet->data);
}

static void handle_set_output(const radio_packet_t *packet)
{
    if (packet->length < 2)
    {
        printf("[RADIO] SET_OUTPUT payload is too short\n");
        return;
    }

    uint output = OUTPUT_FIRST_PIN + packet->data[0];
    bool level = packet->data[1] != 0;

    if (output > OUTPUT_LAST_PIN)
    {
        printf("[RADIO] Unknown output %u\n", (unsigned int)packet->data[0]);
        return;
    }

    gpio_put(output, level);
    printf("[RADIO] Output %u -> %d\n", (unsigned int)packet->data[0], level);

    send_reply(packet, RADIO_CMD_ACK, NULL, 0);
}

static void handle_get_status(const radio_packet_t *packet)
{
    uint8_t status[8];

    status[0] = (uint8_t)(node_global_address >> 24);
    status[1] = (uint8_t)(node_global_address >> 16);
    status[2] = (uint8_t)(node_global_address >> 8);
    status[3] = (uint8_t)(node_global_address);
    status[4] = (uint8_t)(node_local_address >> 8);
    status[5] = (uint8_t)(node_local_address);

    uint8_t neighbor_count = 0;

    network_lock_enter();
    if (radio_download_neighbor_file(&node_ftp))
    {
        radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
        radio_parse_neighbor_file(neighbors, &neighbor_count);
    }
    network_lock_exit();

    status[6] = neighbor_count;
    status[7] = shared_secret_valid ? 1u : 0u;

    send_reply(packet, RADIO_CMD_GET_STATUS, status, sizeof(status));
}

/* ---------------------------------------------------------------------------
 * 6. Packet dispatch
 *
 * Every command is mapped to the function that handles it. Commands that have
 * no protocol handler in radio.c are handled here.
 * --------------------------------------------------------------------------- */

static void dispatch_packet(const radio_packet_t *packet)
{
    switch (packet->command)
    {
        /* --- application / control panel ---------------------------- */
        case RADIO_CMD_PING:
            Ping_Response(node_global_address,
                          node_local_address,
                          &radio,
                          &node_ftp,
                          *packet);
            break;

        case RADIO_CMD_PONG:
            handle_pong(packet);
            break;

        case RADIO_CMD_DATA:
            handle_data_packet(packet);
            break;

        case RADIO_CMD_ACK:
            handle_ack(packet);
            break;

        case RADIO_CMD_SET_OUTPUT:
            handle_set_output(packet);
            break;

        case RADIO_CMD_GET_STATUS:
            handle_get_status(packet);
            break;

        /* --- mesh protocol (handlers live in radio.c) --------------- */
        case RADIO_CMD_SEND_CONNECTIONS:
            Respond_To_Connections_Request(node_global_address,
                                           &radio,
                                           &node_ftp,
                                           packet);
            break;

        case RADIO_CMD_SEND_LOCAL_ADRESS:
            Respond_To_Local_Address(node_global_address,
                                    &radio,
                                    &node_ftp,
                                    packet);
            break;

        case RADIO_CMD_REMOVE_LOCAL_ADDRESS:
            Respond_To_Local_Address_Removal(node_global_address,
                                             &radio,
                                             &node_ftp,
                                             packet);
            break;

        case RADIO_CMD_RECEIVE_GLOBAL_CONNECTIONS:
            Respond_To_Global_Connections_Request(node_global_address,
                                                  &radio,
                                                  &node_ftp,
                                                  packet);
            break;

        case RADIO_CMD_RECEIVE_GLOBAL_RSA_KEYS:
            Respond_To_Global_RSA_Keys_Request(node_global_address,
                                              &radio,
                                              &node_ftp,
                                              packet);
            break;

        case RADIO_CMD_RELAY_NEW_NODE:
            Respond_To_New_Node(node_global_address,
                                &radio,
                                &node_ftp,
                                packet);
            break;

        case RADIO_CMD_RELAY_REMOVE_NODE:
            Respond_To_Node_Removal(node_global_address,
                                    &radio,
                                    &node_ftp,
                                    packet);
            break;

        case RADIO_CMD_RELAY_RSA_KEYS:
            Respond_To_RSA_Key_Relay(node_global_address,
                                     &radio,
                                     &node_ftp,
                                     packet);
            break;

        case RADIO_CMD_SEND_ENCRYPTION_REQUEST:
            /* The peer of a finished exchange is the node that sent us the
             * parameters, so it is recorded only when the handler actually
             * derived a secret. */
            if (Respond_To_DH_Exchange_Request(node_global_address,
                                               &radio,
                                               &node_ftp,
                                               packet,
                                               rsa_private_exponent,
                                               rsa_public_modulus,
                                               shared_secret))
            {
                shared_secret_valid = true;
                shared_secret_peer = packet->source;
            }
            break;

        case RADIO_CMD_SEND_ENCRYPTION_RESPONSE:
            if (Respond_To_DH_Exchange_Response(node_global_address,
                                                &radio,
                                                &node_ftp,
                                                packet,
                                                rsa_private_exponent,
                                                rsa_public_modulus,
                                                shared_secret))
            {
                shared_secret_valid = true;
                shared_secret_peer = packet->source;
            }
            break;

        case RADIO_CMD_DH_EXCHANGE_CONFIRMED:
        case RADIO_CMD_DH_EXCHANGE_FAILED:
            Respond_To_DH_Exchange_Result(node_global_address,
                                         &node_ftp,
                                         packet);
            break;

        /* --- the two message types the control panel can send ---------- */
        case RADIO_CMD_PRIVATE_MESSAGE:
            Respond_To_Private_Message(node_global_address,
                                       &radio,
                                       &node_ftp,
                                       packet,
                                       (packet->source == shared_secret_peer)
                                           ? shared_secret
                                           : shared_secret_empty);
            break;

        case RADIO_CMD_PUBLIC_MESSAGE:
            Respond_To_Public_Message(node_global_address,
                                      &radio,
                                      &node_ftp,
                                      packet);
            break;

        default:
            printf("[RADIO] Unknown command 0x%02X from %08lX\n",
                   (unsigned int)packet->command,
                   (unsigned long)packet->source);
            break;
    }
}

/* ---------------------------------------------------------------------------
 * 7. RSA key pair
 * --------------------------------------------------------------------------- */

static char key_file_text[NODE_KEY_FILE_MAX];
static size_t key_file_length;

static void key_file_cb(uint8_t *data, uint16_t length)
{
    size_t available = sizeof(key_file_text) - key_file_length - 1;

    if (length > available)
        length = (uint16_t)available;

    memcpy(key_file_text + key_file_length, data, length);
    key_file_length += length;
    key_file_text[key_file_length] = '\0';
}

static bool node_load_or_generate_rsa_keypair(void)
{
    char modulus_text[512];
    char exponent_text[512];

    network_lock_enter();

    key_file_length = 0;
    key_file_text[0] = '\0';

    if (ftp_download(&node_ftp, NODE_KEY_FILE, key_file_cb) &&
        sscanf(key_file_text, "%511s %511s", modulus_text, exponent_text) == 2 &&
        mpz_set_str(rsa_public_modulus, modulus_text, 10) == 0 &&
        mpz_set_str(rsa_private_exponent, exponent_text, 10) == 0)
    {
        printf("[NODE] RSA key pair loaded from %s\n", NODE_KEY_FILE);
        network_lock_exit();
        return true;
    }

    /* Brand new node: build our own key pair and publish it. */
    mpz_t p;
    mpz_t q;
    mpz_t seed;
    mpz_t random;

    mpz_init(p);
    mpz_init(q);
    mpz_init(seed);
    mpz_init(random);

    for (int attempt = 0; attempt < 8; ++attempt)
    {
        generate_random_seed(seed, 256);
        generate_random_number(seed, random, 1028, 256);
        generate_random_prime_number(random, p);

        generate_random_seed(seed, 256);
        generate_random_number(seed, random, 1028, 256);
        generate_random_prime_number(random, q);

        if (RSA_safe_prime_check(p, q) &&
            RSA_key_generation(p, q, rsa_public_modulus, rsa_private_exponent))
            break;
    }

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(seed);
    mpz_clear(random);

    if (mpz_sizeinbase(rsa_public_modulus, 2) != 2048)
    {
        printf("[NODE] RSA key generation failed\n");
        network_lock_exit();
        return false;
    }

    char *modulus_str = mpz_get_str(NULL, 10, rsa_public_modulus);
    char *exponent_str = mpz_get_str(NULL, 10, rsa_private_exponent);

    if (modulus_str == NULL || exponent_str == NULL)
    {
        network_lock_exit();
        return false;
    }

    char file[512];
    int length = snprintf(file, sizeof(file), "%s %s\n", modulus_str, exponent_str);

    free(modulus_str);
    free(exponent_str);

    if (length > 0)
        ftp_upload(&node_ftp, NODE_KEY_FILE, (uint8_t *)file, (uint32_t)length);

    /* TODO: the node's own key pair must also be added to the global RSA key
       list so other nodes can verify our signatures. radio.c has no function
       for that yet. */

    printf("[NODE] New RSA key pair generated and stored as %s\n", NODE_KEY_FILE);
    network_lock_exit();

    return true;
}

/* ---------------------------------------------------------------------------
 * 8. New node process
 * --------------------------------------------------------------------------- */

static bool join_mesh_as_new_node(void)
{
    printf("[NODE] Brand new node, joining the mesh.\n");

    /* Global address = creation date + current RTC time. */
    node_global_address = radio_generate_global_address(NODE_CREATION_YEAR,
                                                        NODE_CREATION_MONTH,
                                                        NODE_CREATION_DAY);

    printf("[NODE] Global address: %08lX\n", (unsigned long)node_global_address);

    network_lock_enter();

    /* 1. Discover the nodes in radio range and create local_neighbors.txt. */
    Find_Neighbors(node_global_address, &radio, &node_ftp);

    /* 2. Ask the neighbours for the addresses they already use and take a free
       one for ourselves. */
    node_local_address = Generate_Local_Adress(node_global_address, &radio, &node_ftp);

    if (node_local_address == 0)
    {
        printf("[NODE] No free local address, retrying later\n");
        network_lock_exit();
        return false;
    }

    printf("[NODE] Local address: %u\n", (unsigned int)node_local_address);

    /* 3. Tell the neighbours about us and announce ourselves to the mesh. */
    if (!Send_Local_Adress_To_Neighbors(node_global_address,
                                        node_local_address,
                                        &radio,
                                        &node_ftp))
    {
        printf("[NODE] Could not register the local address with the neighbours\n");
    }

    if (!Relay_New_Node(node_global_address, &radio, &node_ftp))
    {
        printf("[NODE] Could not announce the new node\n");
    }

    /* 4. Collect the network RSA keys and the global connection list. */
    Request_Global_RSA_Keys(node_global_address, &radio, &node_ftp);
    Request_Global_Connections(node_global_address, &radio, &node_ftp);

    network_lock_exit();

    return true;
}

/* ---------------------------------------------------------------------------
 * 10. Control panel actions
 *
 * These are the buttons of the hosted site. site_server.c turns a browser
 * request into a call to one of them, so the wiring already exists end to end:
 * click -> HTTP request -> parse -> call here.
 *
 * IMPORTANT: the buttons are pressed on Core 0, but sending a message needs the
 * radio and the FTP client, which belong to Core 1. So a button only QUEUES
 * what was asked; Core 1 carries it out between packets, when neither the
 * radio nor the ledger is in the middle of something else.
 * --------------------------------------------------------------------------- */

#define SITE_ACTION_TEXT_MAX     1024
#define SITE_ACTION_NAME_MAX     100

static char pending_public_text[SITE_ACTION_TEXT_MAX];
static bool pending_public_active;

static char pending_private_text[SITE_ACTION_TEXT_MAX];
static char pending_private_recipient[SITE_ACTION_NAME_MAX];
static bool pending_private_active;

/* Discussion Hall: the visitor pressed "Send". Queue a public post. */
void site_action_discussion_send(const char *message)
{
    if (message == NULL || message[0] == '\0')
        return;

    /* One post at a time: a second click before the first was carried out is
     * dropped rather than overwriting it. */
    if (pending_public_active)
        return;

    size_t length = strlen(message);
    if (length >= sizeof(pending_public_text))
        length = sizeof(pending_public_text) - 1u;

    memcpy(pending_public_text, message, length);
    pending_public_text[length] = '\0';
    pending_public_active = true;
}

/* Post Office: the compose form was submitted. Queue a private letter. */
void site_action_post_send(const char *recipient, const char *message)
{
    if (recipient == NULL || message == NULL ||
        recipient[0] == '\0' || message[0] == '\0')
        return;

    if (pending_private_active)
        return;

    size_t length = strlen(message);
    if (length >= sizeof(pending_private_text))
        length = sizeof(pending_private_text) - 1u;

    memcpy(pending_private_text, message, length);
    pending_private_text[length] = '\0';

    length = strlen(recipient);
    if (length >= sizeof(pending_private_recipient))
        length = sizeof(pending_private_recipient) - 1u;

    memcpy(pending_private_recipient, recipient, length);
    pending_private_recipient[length] = '\0';
    pending_private_active = true;
}

/* Post Office: "Refresh". Nothing to carry out yet: the page re-reads the
 * file itself, and the node's copy is already up to date. */
void site_action_post_refresh(void)
{
}

/* Post Office: the "Inbox" / "All Messages" switches. */
void site_action_post_show_folder(const char *folder)
{
    (void)folder;
}

/* Post Office: "Compose" and the sidebar shortcut. */
void site_action_compose_open(void)
{
}

/* Post Office: the minimise button of the compose window. */
void site_action_compose_toggle(void)
{
}

/* Curia Regis: "Reset Node". */
void site_action_node_reset(void)
{
}

/* Curia Regis: "Regenerate Keys". */
void site_action_keys_regenerate(void)
{
}

/* Carry out whatever the buttons queued, on Core 1. Called between packets so
 * a send never interrupts the receive loop. */
static void service_pending_site_actions(void)
{
    if (pending_public_active)
    {
        pending_public_active = false;

        network_lock_enter();
        bool sent = Send_Public_Message(pending_public_text,
                                       node_global_address,
                                       &radio,
                                       &node_ftp);
        network_lock_exit();

        if (!sent)
            printf("[NODE] Public message did not reach the mesh\n");
    }

    if (pending_private_active)
    {
        /* The addressee is typed as the global address shown on the pages. */
        unsigned long target_value = 0;
        if (sscanf(pending_private_recipient, "%lX", &target_value) != 1)
            target_value = 0;

        uint32_t target = (uint32_t)target_value;

        pending_private_active = false;

        if (target == 0 || !shared_secret_valid || target != shared_secret_peer)
        {
            printf("[NODE] No shared secret with %08lX, letter not sent\n",
                   (unsigned long)target);
            return;
        }

        network_lock_enter();
        bool sent = Send_Private_Message(node_global_address,
                                        target,
                                        pending_private_text,
                                        shared_secret,
                                        &radio,
                                        &node_ftp);
        network_lock_exit();

        if (!sent)
            printf("[NODE] Private letter to %08lX was not acknowledged\n",
                   (unsigned long)target);
    }
}

/* ---------------------------------------------------------------------------
 * 11. Core 1 - the radio
 * --------------------------------------------------------------------------- */

void second_core_code(void)
{
    /* Wake the E32 module. */
    e32_init(&radio, RADIO_UART, RADIO_TX_PIN, RADIO_RX_PIN, RADIO_M0_PIN, RADIO_M1_PIN);
    e32_set_mode(&radio, E32_MODE_WAKEUP);
    sleep_ms(100);
    e32_set_mode(&radio, E32_MODE_NORMAL);
    e32_write_config(&radio, E32_BROADCAST, RADIO_CHANNEL);

    printf("[CORE1] E32 radio is ready.\n");

    /* The FTP client runs on this core. */
    network_lock_enter();

    if (!ftp_connect(&node_ftp) || !ftp_login(&node_ftp))
    {
        printf("[CORE1] FTP connection failed, the node cannot join the mesh\n");
        network_lock_exit();
        return;
    }

    if (!node_load_or_generate_rsa_keypair())
    {
        network_lock_exit();
        return;
    }

    /* Brand new node? local_neighbors.txt is missing, empty or invalid. */
    bool new_node = radio_is_new_node(&node_ftp);

    network_lock_exit();

    if (new_node)
    {
        if (!join_mesh_as_new_node())
            return;
    }
    else
    {
        /* We already belong to the mesh: read the neighbour list again and
           re-claim a local address. */
        network_lock_enter();

        node_local_address = Generate_Local_Adress(node_global_address, &radio, &node_ftp);

        network_lock_exit();

        printf("[NODE] Rejoined as %08lX with local address %u\n",
               (unsigned long)node_global_address,
               (unsigned int)node_local_address);
    }

    /* Receive, sort and dispatch. */
    while (true)
    {
        /* Anything the control panel queued is carried out here, between
         * packets, so a send never interrupts the receive loop. */
        service_pending_site_actions();

        radio_packet_t packet;

        if (!radio_receive_packet(&radio, &packet))
        {
            sleep_ms(1);
            continue;
        }

        if (!packet_is_for_us(&packet))
            continue;

        if (packet_already_seen(&packet))
            continue;

        dispatch_packet(&packet);
    }
}

/* ---------------------------------------------------------------------------
 * 12. Core 0 - Ethernet and the control panel
 * --------------------------------------------------------------------------- */

int main(void)
{
    stdio_init_all();
    sleep_ms(2000);

    mutex_init(&network_lock);

    /* A zeroed mpz_t is not an initialized one: mini-gmp needs the size and
     * capacity fields that only mpz_init() sets, so both the real secret and
     * the empty stand-in have to be initialized before any handler touches
     * them. */
    mpz_init(shared_secret);
    mpz_init(shared_secret_empty);

    ethernet_w5500_config_t w5500 = {
        .spi = spi0,
        .miso_pin = 16,
        .cs_pin = 17,
        .sck_pin = 18,
        .mosi_pin = 19,
        .reset_pin = 20,
    };

    init_w5500(&w5500);
    http_server_init();

    /* The global address is built from the RTC, so the clock must run and be
       set to the node creation date. */
    rtc_init();

    datetime_t now;
    now.year = NODE_CREATION_YEAR;
    now.month = NODE_CREATION_MONTH;
    now.day = NODE_CREATION_DAY;
    now.hours = 0;
    now.minutes = 0;
    now.seconds = 0;
    now.weekday = 0;
    rtc_set_datetime(&now);

    /* Faster random clock used to seed the RSA/DH number generator. */
    rosc_setup();

    for (uint output = OUTPUT_FIRST_PIN; output <= OUTPUT_LAST_PIN; ++output)
        gpio_init(output), gpio_set_dir(output, GPIO_OUT);

    multicore_launch_core1(second_core_code);

    while (true)
    {
        http_server_poll();
        sleep_ms(10);
    }
}
