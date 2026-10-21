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
static mutex_t network_lock;

static void network_lock_enter(void) { mutex_enter_blocking(&network_lock); }
static void network_lock_exit(void)  { mutex_exit(&network_lock); }

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

    /* A packet that carries a route is also ours when we are somewhere along
     * it: the handlers then either act on it (we are the end of the route)
     * or pass it on (we are a courier). Without this a private letter, a
     * public post or a DH leg addressed to ONE node would be dropped at the
     * first hop and would never reach the addressee. */
    for (uint8_t hop = 0;
         hop < packet->path_length && hop < RADIO_MAX_ROUTE_ADDRESSES;
         ++hop)
    {
        if (packet->path[hop] == node_global_address)
            return true;
    }

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

/* A Diffie-Hellman fragment addressed further away is a courier job: put it
 * on the next hop of the route it came by, unchanged, so the far end still
 * sees the original author, the original target and the same sequence number.
 * radio.c only has a courier path for private letters, and without one here a
 * multi-hop exchange would stop at the first node that is not the target. */
static bool forward_mesh_fragment(const radio_packet_t *packet)
{
    uint8_t hop = packet->path_length;

    for (uint8_t i = 0; i + 1u < packet->path_length; ++i)
    {
        if (packet->path[i] == node_global_address)
        {
            hop = (uint8_t)(i + 1u);
            break;
        }
    }

    /* The route does not go through us: this packet took a different way. */
    if (hop == packet->path_length || hop >= RADIO_MAX_ROUTE_ADDRESSES)
        return false;

    uint16_t next_hop_local_address = 0;

    network_lock_enter();
    bool known = radio_find_neighbor_local_address(&node_ftp,
                                                  packet->path[hop],
                                                  &next_hop_local_address);
    network_lock_exit();

    if (!known)
    {
        printf("[RADIO] No radio address for the next hop %08lX\n",
               (unsigned long)packet->path[hop]);
        return false;
    }

    radio_packet_t forwarded = *packet;
    return radio_send_packet(&radio, &forwarded, next_hop_local_address, 0);
}

/* Is this packet one of the legs we are supposed to ACT on, rather than a
 * fragment that is merely passing through us on its way to a distant node?
 * Every protocol handler in radio.c insists on being the end of the route, so
 * the dispatcher asks the same question before choosing between them. */
static bool mesh_leg_is_ours(const radio_packet_t *packet)
{
    if (packet->path_length == 0 || packet->path_length > RADIO_MAX_ROUTE_ADDRESSES)
        return false;

    return packet->destination == node_global_address &&
           packet->path[packet->path_length - 1u] == node_global_address;
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
            if (!mesh_leg_is_ours(packet))
            {
                forward_mesh_fragment(packet);
                break;
            }
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
            if (!mesh_leg_is_ours(packet))
            {
                forward_mesh_fragment(packet);
                break;
            }
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
            if (!mesh_leg_is_ours(packet))
            {
                forward_mesh_fragment(packet);
                break;
            }
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

        /* --- chunked file replies ---------------------------------- */
        /* The requester reassembles those inside Request_Global_Connections
         * and Request_Global_RSA_Keys, so reaching the receive loop means we
         * were not the one waiting for them: there is nothing to answer. */
        case RADIO_CMD_SEND_GLOBAL_CONNECTIONS:
        case RADIO_CMD_SEND_GLOBAL_RSA_KEYS:
            printf("[RADIO] Unsolicited file chunk from %08lX, dropped\n",
                   (unsigned long)packet->source);
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

/* The generator is shared by the boot sequence and by "Regenerate Keys", so
 * it is declared first and takes the network lock from its caller. */
static bool node_generate_rsa_keypair(void);

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

    bool generated = node_generate_rsa_keypair();

    network_lock_exit();
    return generated;
}

/* Build a fresh RSA key pair and store it. The caller must already hold the
 * network lock: this runs at boot for a brand new node and from the
 * "Regenerate Keys" button. */
static bool node_generate_rsa_keypair(void)
{
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
        return false;
    }

    char *modulus_str = mpz_get_str(NULL, 10, rsa_public_modulus);
    char *exponent_str = mpz_get_str(NULL, 10, rsa_private_exponent);

    if (modulus_str == NULL || exponent_str == NULL)
        return false;

    char file[512];
    int length = snprintf(file, sizeof(file), "%s %s\n", modulus_str, exponent_str);

    free(modulus_str);
    free(exponent_str);

    if (length > 0)
        ftp_upload(&node_ftp, NODE_KEY_FILE, (uint8_t *)file, (uint32_t)length);

    /* Our own modulus is not written into the ledger here: it is published
     * with Relay_RSA_Public_Key, which every neighbour's
     * Respond_To_RSA_Key_Relay stores and forwards. Both callers do that. */
    printf("[NODE] New RSA key pair generated and stored as %s\n", NODE_KEY_FILE);

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

    /* 4. Collect the network RSA keys and the global connection list. Both
     *    are checked: without them the node cannot verify signatures or plan
     *    a route, so a failure is worth reporting rather than ignoring. */
    if (!Request_Global_RSA_Keys(node_global_address, &radio, &node_ftp))
        printf("[NODE] No RSA key ledger from any neighbour\n");

    if (!Request_Global_Connections(node_global_address, &radio, &node_ftp))
        printf("[NODE] No global connection graph yet\n");

    /* 5. Publish our own public modulus. Nothing else in the program does
     *    that, so without this step the ledger never holds our key and every
     *    packet we send fails its signature check at the far end. */
    if (!Relay_RSA_Public_Key(node_global_address,
                              rsa_public_modulus,
                              &radio,
                              &node_ftp))
        printf("[NODE] Could not publish our own RSA public key\n");

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
 * IMPORTANT: the buttons are pressed on Core 0, but everything below needs the
 * radio and the FTP client, which belong to Core 1. So a button only QUEUES
 * what was asked; Core 1 carries it out between packets, when neither the
 * radio nor the ledger is in the middle of something else.
 *
 * A queued action is only reported as done when the other node actually
 * answered. What each button does:
 *
 *   Post Office "Send"    -> Find_Shortest_Global_Route to the addressee
 *                         -> Create_DH_Exchange_Packet along that route
 *                         -> wait until the peer's half of the exchange is
 *                            received and dispatch_packet() confirms the
 *                            shared secret
 *                         -> Send_Private_Message, which waits for the
 *                            addressee's acknowledgement
 *
 *   Discussion Hall "Send" -> Send_Public_Message. No secret is needed: the
 *                              text is plain and every neighbour gets a copy,
 *                              and that function requires all of them to
 *                              acknowledge before it returns true.
 *
 *   "Refresh" / the folder switches -> re-read the node's own copy of the
 *                                       letter and discussion files
 *
 *   "Regenerate Keys" -> build a fresh RSA pair and publish the new modulus
 *   "Reset Node"     -> redo the join sequence without changing our identity
 *
 *   "Compose" / the minimise button -> nothing on the node: that window is
 *                                       state inside the browser
 * --------------------------------------------------------------------------- */

#define SITE_ACTION_TEXT_MAX     1024
#define SITE_ACTION_NAME_MAX     100
#define SITE_ACTION_TIMEOUT_MS   15000u
#define SITE_LEDGER_TEXT_MAX     2048

/* The two files the pages read. The names must match the ones radio.c
 * appends to, so they are repeated here rather than shared. */
#define LEDGER_PRIVATE_MESSAGES_FILE "private_mesagges.txt"
#define LEDGER_DISCUSSION_FILE      "current_discussion.txt"

static char pending_public_text[SITE_ACTION_TEXT_MAX];
static bool pending_public_active;

static char pending_private_text[SITE_ACTION_TEXT_MAX];
static char pending_private_recipient[SITE_ACTION_NAME_MAX];
static bool pending_private_active;

static bool pending_refresh_active;

static char pending_folder_name[SITE_ACTION_NAME_MAX];
static bool pending_folder_active;

static bool pending_reset_active;
static bool pending_keys_active;

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

/* Post Office: "Refresh". The page re-fetches the file for itself; queue a
 * re-read of the node's own copy so the two sides are looking at the same
 * list and the operator can see what is actually stored. */
void site_action_post_refresh(void)
{
    pending_refresh_active = true;
}

/* Post Office: the "Inbox" / "All Messages" switches. */
void site_action_post_show_folder(const char *folder)
{
    if (folder == NULL)
        return;

    size_t length = strlen(folder);
    if (length >= sizeof(pending_folder_name))
        return;

    memcpy(pending_folder_name, folder, length);
    pending_folder_name[length] = '\0';
    pending_folder_active = true;
}

/* Post Office: "Compose" and the sidebar shortcut.
 * Nothing for the node to do: opening and minimising the compose window is
 * state inside the page (see Post_Office.html); no packet is involved. */
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
    pending_reset_active = true;
}

/* Curia Regis: "Regenerate Keys". */
void site_action_keys_regenerate(void)
{
    pending_keys_active = true;
}

/* --- helpers used by the actions below -----------------------------------
 * The addressee is typed as the global address shown on the pages, i.e. the
 * eight hex digits printed in front of every letter. An optional 0x prefix is
 * accepted, anything else is refused, so a mistyped name never becomes a
 * letter to node 00000000. */
static bool parse_global_address(const char *text, uint32_t *address)
{
    if (text == NULL)
        return false;

    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        text += 2;

    uint32_t value = 0;
    size_t digits = 0;

    for (const char *c = text; *c != '\0'; ++c)
    {
        uint8_t digit;

        if (*c >= '0' && *c <= '9')
            digit = (uint8_t)(*c - '0');
        else if (*c >= 'a' && *c <= 'f')
            digit = (uint8_t)(*c - 'a' + 10);
        else if (*c >= 'A' && *c <= 'F')
            digit = (uint8_t)(*c - 'A' + 10);
        else
            return false;

        if (digits == 8u)
            return false;

        value = (value << 4) | digit;
        ++digits;
    }

    if (digits == 0 || value == 0 || value == RADIO_BROADCAST_ADDRESS)
        return false;

    *address = value;
    return true;
}

/* "Refresh" and the folder switches re-read the node's own copy of a text
 * file and show what is in it, so the page and the node are known to be
 * looking at the same list. */
static char ledger_text[SITE_LEDGER_TEXT_MAX];
static size_t ledger_text_length;
static bool ledger_text_overflow;

static void ledger_text_cb(uint8_t *data, uint16_t length)
{
    size_t available = sizeof(ledger_text) - ledger_text_length - 1;

    if (length > available)
    {
        length = (uint16_t)available;
        ledger_text_overflow = true;
    }

    memcpy(ledger_text + ledger_text_length, data, length);
    ledger_text_length += length;
    ledger_text[ledger_text_length] = '\0';
}

static bool node_show_ledger_file(const char *file_name)
{
    bool ok = false;

    network_lock_enter();

    ledger_text_length = 0;
    ledger_text_overflow = false;
    ledger_text[0] = '\0';

    if (ftp_download(&node_ftp, file_name, ledger_text_cb) &&
        !ledger_text_overflow)
    {
        printf("[SITE] %s holds %u bytes:\n%.*s\n",
               file_name,
               (unsigned)ledger_text_length,
               (int)ledger_text_length,
               ledger_text);
        ok = true;
    }
    else
    {
        printf("[SITE] %s is empty or could not be read\n", file_name);
    }

    network_lock_exit();
    return ok;
}

/* Route to a node and start a Diffie-Hellman exchange along that route.
 * Returns true once g^a mod p has been put on the wire. */
static bool start_dh_exchange_with(uint32_t peer)
{
    bool started = false;

    network_lock_enter();

    uint32_t route[RADIO_MAX_ROUTE_ADDRESSES];
    uint8_t route_length = 0;

    if (!Find_Shortest_Global_Route(node_global_address,
                                    peer,
                                    &node_ftp,
                                    route,
                                    &route_length))
    {
        printf("[SITE] No route to %08lX in the global connection graph\n",
               (unsigned long)peer);
    }
    else if (route_length < 2 ||
             route[0] != node_global_address ||
             route[route_length - 1u] != peer)
    {
        printf("[SITE] The route to %08lX is not usable\n", (unsigned long)peer);
    }
    else
    {
        uint16_t first_hop = 0;

        if (!radio_find_neighbor_local_address(&node_ftp, route[1], &first_hop))
            printf("[SITE] The first hop of the route is not a neighbour we can dial\n");
        else if (!Create_DH_Exchange_Packet(peer,
                                           node_global_address,
                                           route,
                                           &route_length,
                                           first_hop,
                                           rsa_private_exponent,
                                           rsa_public_modulus))
            printf("[SITE] Could not start the exchange, one may be in flight\n");
        else
            started = true;
    }

    network_lock_exit();
    return started;
}

/* Wait for the peer's half of a Diffie-Hellman exchange.
 *
 * The answer is not read here: it is handed to dispatch_packet() exactly like
 * every other packet, so the node keeps answering the mesh while it waits and
 * the shared secret is derived by Respond_To_DH_Exchange_Response. The
 * exchange counts as confirmed only when that handler stored a secret for
 * THIS peer. */
static bool await_shared_secret_with(uint32_t peer)
{
    absolute_time_t timeout = make_timeout_time_ms(SITE_ACTION_TIMEOUT_MS);

    while (!time_reached(timeout))
    {
        radio_packet_t packet;

        if (radio_receive_packet(&radio, &packet) &&
            packet_is_for_us(&packet) &&
            !packet_already_seen(&packet))
            dispatch_packet(&packet);

        if (shared_secret_valid &&
            shared_secret_peer == peer &&
            mpz_sgn(shared_secret) > 0)
            return true;

        sleep_ms(1);
    }

    printf("[SITE] Nothing came back from %08lX, the exchange is not confirmed\n",
           (unsigned long)peer);
    return false;
}

/* The whole private-letter pipeline: route, exchange, confirm, send. */
static void run_private_letter(void)
{
    uint32_t target;

    if (!parse_global_address(pending_private_recipient, &target))
    {
        printf("[SITE] \"%s\" is not a node address, letter not sent\n",
               pending_private_recipient);
        return;
    }

    if (target == node_global_address)
    {
        printf("[SITE] A letter to this node makes no sense\n");
        return;
    }

    /* A new exchange replaces the secret we hold: there is room for exactly
     * one pair at a time, so the old one is dropped before a new one starts.
     * Waiting for a fresh confirmation is also the only way to tell this
     * exchange apart from an identical one that finished earlier. */
    shared_secret_valid = false;
    shared_secret_peer = 0;
    mpz_set_ui(shared_secret, 0);

    if (!start_dh_exchange_with(target))
        return;

    if (!await_shared_secret_with(target))
        return;

    printf("[SITE] Shared secret with %08lX confirmed\n", (unsigned long)target);

    bool acknowledged;

    network_lock_enter();
    acknowledged = Send_Private_Message(node_global_address,
                                       target,
                                       pending_private_text,
                                       shared_secret,
                                       &radio,
                                       &node_ftp);
    network_lock_exit();

    if (!acknowledged)
        printf("[SITE] The letter to %08lX was not acknowledged\n",
               (unsigned long)target);
    else
        printf("[SITE] Letter sealed and delivered to %08lX\n",
               (unsigned long)target);
}

/* A public post needs no secret: the text is plain and every neighbour gets
 * a copy. Send_Public_Message only returns true once all of them answer. */
static void run_public_message(void)
{
    bool acknowledged;

    network_lock_enter();
    acknowledged = Send_Public_Message(pending_public_text,
                                      node_global_address,
                                      &radio,
                                      &node_ftp);
    network_lock_exit();

    if (!acknowledged)
        printf("[SITE] The post did not reach every neighbour\n");
    else
        printf("[SITE] Post published to the discussion hall\n");
}

/* The folder switches: "inbox" is the private letters, "all" adds the public
 * discussion of the hall. */
static void run_folder_show(void)
{
    if (pending_folder_name[0] == '\0' ||
        strcmp(pending_folder_name, "inbox") == 0)
    {
        node_show_ledger_file(LEDGER_PRIVATE_MESSAGES_FILE);
        return;
    }

    if (strcmp(pending_folder_name, "all") == 0)
    {
        node_show_ledger_file(LEDGER_PRIVATE_MESSAGES_FILE);
        node_show_ledger_file(LEDGER_DISCUSSION_FILE);
        return;
    }

    printf("[SITE] Unknown folder \"%s\"\n", pending_folder_name);
}

/* "Regenerate Keys": a brand new RSA pair for this node, then publish the
 * new modulus so the mesh can verify what we send from now on. */
static void run_keys_regenerate(void)
{
    network_lock_enter();
    bool generated = node_generate_rsa_keypair();
    network_lock_exit();

    if (!generated)
    {
        printf("[SITE] No new key pair was generated\n");
        return;
    }

    network_lock_enter();
    bool published = Relay_RSA_Public_Key(node_global_address,
                                         rsa_public_modulus,
                                         &radio,
                                         &node_ftp);
    network_lock_exit();

    if (!published)
        printf("[SITE] The new public key could not be published\n");
}

/* "Reset Node": a global address is permanent by design, so a reset keeps our
 * identity and redoes everything that connects us to the mesh - the same
 * steps the boot sequence uses, minus the physical neighbour search, which
 * would need a broadcast PING that every other node would answer too. */
static void run_node_reset(void)
{
    network_lock_enter();

    if (!Remove_Local_Address_From_Neighbors(node_global_address,
                                            &radio,
                                            &node_ftp))
        printf("[SITE] The neighbours were not told we are rejoining\n");

    uint16_t local_address = Generate_Local_Adress(node_global_address,
                                                  &radio,
                                                  &node_ftp);

    if (local_address == 0)
        printf("[SITE] No free radio address, keeping %u\n",
               (unsigned)node_local_address);
    else
        node_local_address = local_address;

    if (!Send_Local_Adress_To_Neighbors(node_global_address,
                                        node_local_address,
                                        &radio,
                                        &node_ftp))
        printf("[SITE] The new radio address did not reach every neighbour\n");

    if (!Relay_New_Node(node_global_address, &radio, &node_ftp))
        printf("[SITE] The mesh was not told we rejoined\n");

    if (!Request_Global_RSA_Keys(node_global_address, &radio, &node_ftp))
        printf("[SITE] No RSA key ledger after the reset\n");

    if (!Request_Global_Connections(node_global_address, &radio, &node_ftp))
        printf("[SITE] No global connection graph after the reset\n");

    if (!Relay_RSA_Public_Key(node_global_address,
                             rsa_public_modulus,
                             &radio,
                             &node_ftp))
        printf("[SITE] Our public key was not published\n");

    network_lock_exit();

    printf("[SITE] Node reset done, still %08lX with radio address %u\n",
           (unsigned long)node_global_address,
           (unsigned)node_local_address);
}

/* Carry out whatever the buttons queued, on Core 1. Called between packets so
 * a send never interrupts the receive loop. */
static void service_pending_site_actions(void)
{
    if (pending_public_active)
    {
        pending_public_active = false;
        run_public_message();
    }

    if (pending_private_active)
    {
        pending_private_active = false;
        run_private_letter();
    }

    if (pending_refresh_active)
    {
        pending_refresh_active = false;
        node_show_ledger_file(LEDGER_PRIVATE_MESSAGES_FILE);
    }

    if (pending_folder_active)
    {
        pending_folder_active = false;
        run_folder_show();
    }

    if (pending_keys_active)
    {
        pending_keys_active = false;
        run_keys_regenerate();
    }

    /* Last: this is the longest operation and it blocks the receive loop for
     * as long as the join sequence takes. */
    if (pending_reset_active)
    {
        pending_reset_active = false;
        run_node_reset();
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
    now.hour = 0;
    now.min = 0;
    now.sec = 0;
    now.dotw = 0;
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
