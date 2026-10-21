/* ==========================================================================
 * radio.c -- the MESH PROTOCOL layer.
 *
 * THE PROGRAM IN ONE PARAGRAPH
 * ----------------------------
 * Each Raspberry Pi Pico is a node. It can only talk physically to nodes in
 * radio range, through an E32 broadcast radio with 16-bit addresses. The
 * program's job is to turn that local, physical, unreliable channel into a
 * global, reliable mesh: unique identities, a shared map of who-is-connected-
 * to-whom, a shared table of public keys, and a shared secret per pair of
 * nodes that want to exchange encrypted text.
 *
 * HOW THIS FILE FITS
 * ------------------
 *   mesh_network_v1.c  = the scheduler. Core 0 serves the HTML control panel,
 *                        Core 1 receives packets and calls dispatch_packet().
 *   radio_packet_protocol.c = framing: bytes <-> radio_packet_t.
 *   radio.c (here)    = the meaning of each command. Every function here is
 *                        either a REQUESTER (sends something on our behalf)
 *                        or a RESPONDER (reacts to a packet we received).
 *   Ethernet_FTP/     = the persistent storage. The node's whole idea of the
 *                        mesh is a handful of files on an FTP server.
 *   Cryptographic_Functions/ = mini-GMP bignum maths: RSA, DH, SHA-256,
 *                        ChaCha20-Poly1305.
 *
 * THE THREE FILES THAT ARE THE NODE'S MEMORY
 * ------------------------------------------
 *   local_neighbors.txt      text: GLOBAL,LOCAL per line. Physical map.
 *   global_connections.bin   rows of 9 uint32: [self, up to 8 neighbours].
 *                            The map of the whole mesh.
 *   global_rsa_key_list      rows of [4-byte global address | 256-byte modulus].
 *                            Who can verify whose signature.
 *   node_rsa_key.txt         this node's own modulus + private exponent.
 *
 * The static buffers at the top of this file are the in-RAM copies of those
 * files. FTP callbacks fill them, handlers edit them in place, and ftp_upload
 * writes them back. That is the whole data flow of the program.
 * ==========================================================================*/
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
#include "radio.h"



/* --- local neighbour ledger ----------------------------------------------
 * A neighbour record on the wire is its 4-byte global address + 2-byte local
 * address = 6. Eight of them fit in one DATA packet, which is why the
 * response timeout is sized for a single round trip of one neighbour. */
#define RADIO_NEIGHBOR_FILE_MAX_SIZE 1024
#define RADIO_CONNECTION_RECORD_SIZE 6
#define RADIO_CONNECTIONS_PER_PACKET 8
#define RADIO_CONNECTION_RESPONSE_TIMEOUT_MS 5000
/* --- global connection graph ---------------------------------------------
 * One row = the node itself plus up to 8 neighbours, all 32-bit global
 * addresses, zero padded. Files are moved over the radio in RADIO_MAX_DATA
 * sized chunks, hence the 8-byte chunk header [total length | offset]. */
#define RADIO_GLOBAL_CONNECTIONS_FILE "global_connections.bin"
#define RADIO_GLOBAL_CONNECTIONS_ROW_SIZE (9u * sizeof(uint32_t))
#define RADIO_NEW_NODE_RECORD_SIZE (9u * sizeof(uint32_t))
/* The 4 KiB cap is a RAM decision, not a protocol one: it bounds the graph
 * to ~450 nodes and, together with RADIO_GLOBAL_ROUTE_MAX_JUMPS, keeps the
 * breadth-first search in Find_Shortest_Global_Route stack-safe. */
#define RADIO_GLOBAL_CONNECTIONS_FILE_MAX_SIZE 4096
#define RADIO_GLOBAL_CONNECTIONS_CHUNK_HEADER_SIZE 8
#define RADIO_GLOBAL_CONNECTIONS_CHUNK_SIZE \
    (RADIO_MAX_DATA - RADIO_GLOBAL_CONNECTIONS_CHUNK_HEADER_SIZE)
#define RADIO_GLOBAL_CONNECTIONS_RESPONSE_TIMEOUT_MS 10000
#define RADIO_GLOBAL_ROUTE_MAX_JUMPS 14
#define RADIO_GLOBAL_ROUTE_MAX_ADDRESSES 16
#define RADIO_GLOBAL_CONNECTIONS_MAX_NODES \
    (RADIO_GLOBAL_CONNECTIONS_FILE_MAX_SIZE / sizeof(uint32_t))
#define RADIO_NODE_REMOVAL_CACHE_SIZE \
    (RADIO_GLOBAL_CONNECTIONS_FILE_MAX_SIZE / RADIO_GLOBAL_CONNECTIONS_ROW_SIZE)
/* --- RSA public-key ledger -----------------------------------------------
 * A row is 4 bytes of global address + the full 2048-bit modulus, so 16 KiB
 * holds only 31 keys. The 12-byte chunk header adds a CRC-32 of the whole
 * file: a half-received key list would silently break every signature check
 * later, so it must be verified before being stored. */
#define RADIO_GLOBAL_RSA_KEYS_FILE "global_rsa_key_list"
#define RADIO_GLOBAL_RSA_KEYS_FILE_MAX_SIZE 16384
#define RADIO_GLOBAL_RSA_KEYS_CHUNK_HEADER_SIZE 12
#define RADIO_GLOBAL_RSA_KEYS_CHUNK_SIZE \
    (RADIO_MAX_DATA - RADIO_GLOBAL_RSA_KEYS_CHUNK_HEADER_SIZE)
#define RADIO_GLOBAL_RSA_KEYS_RESPONSE_TIMEOUT_MS 10000
#define RADIO_GLOBAL_RSA_KEYS_ATTEMPTS_PER_NEIGHBOR 2
/* --- crypto sizes --------------------------------------------------------
 * RSA is done at full 2048-bit strength because the modulus doubles as the
 * node's identity in the key ledger. The Diffie-Hellman modulus is much
 * smaller (1023 bits) since it only has to hide a shared secret, and that
 * secret is later truncated to a ChaCha20-Poly1305 key.
 *
 * The *_SIGNED_* sizes matter because a signature is as long as the whole
 * RSA block: a DH message cannot fit one radio frame, which is exactly why
 * the fragmenting helpers exist. */
#define RADIO_RSA_PUBLIC_MODULUS_BITS 2048
#define RADIO_RSA_PUBLIC_MODULUS_SIZE (RADIO_RSA_PUBLIC_MODULUS_BITS / 8)
#define RADIO_RSA_KEY_ROW_SIZE (sizeof(uint32_t) + RADIO_RSA_PUBLIC_MODULUS_SIZE)
#define RADIO_DH_MODULUS_BITS 1023u
#define RADIO_DH_FIELD_SIZE ((RADIO_DH_MODULUS_BITS + 7u) / 8u)
#define RADIO_DH_MESSAGE_SIZE (2u * RADIO_DH_FIELD_SIZE)
#define RADIO_DH_HASH_SIZE 32u
#define RADIO_DH_RESPONSE_MESSAGE_SIZE \
    (RADIO_DH_FIELD_SIZE + RADIO_DH_HASH_SIZE)
#define RADIO_DH_PRIVATE_SIZE 32u
#define RADIO_DH_SIGNATURE_SIZE RADIO_RSA_PUBLIC_MODULUS_SIZE
#define RADIO_DH_SIGNATURE_CONTEXT_SIZE 12u
#define RADIO_DH_SIGNATURE_INPUT_MAX_SIZE \
    (RADIO_DH_SIGNATURE_CONTEXT_SIZE + RADIO_DH_MESSAGE_SIZE)
#define RADIO_DH_SIGNED_REQUEST_SIZE \
    (RADIO_DH_MESSAGE_SIZE + RADIO_DH_SIGNATURE_SIZE)
#define RADIO_DH_SIGNED_RESPONSE_SIZE \
    (RADIO_DH_RESPONSE_MESSAGE_SIZE + RADIO_DH_SIGNATURE_SIZE)
#define RADIO_DH_RSA_FRAGMENT_HEADER_SIZE 4u
#define RADIO_DH_RSA_FRAGMENT_DATA_SIZE \
    (RADIO_MAX_DATA - RADIO_DH_RSA_FRAGMENT_HEADER_SIZE)


/* ==========================================================================
 * THE NODE'S ENTIRE STATE, in RAM, mirroring the files on the FTP server.
 *
 * These are file-scope on purpose: the FTP API is callback based, so a
 * download has to accumulate bytes into one of these buffers, and a handler
 * then edits it in place and uploads it back. Only one Core 1 thread touches
 * them, so no locking is needed here (the lock in main() protects the W5500,
 * not these buffers).
 * ==========================================================================*/
static uint8_t neighbor_file[RADIO_NEIGHBOR_FILE_MAX_SIZE + 1]; /* +1 for the NUL terminator */
static size_t neighbor_file_length;
static bool neighbor_file_overflow; /* set when a download did not fit: treat the data as unusable */

static uint8_t global_connections_file[RADIO_GLOBAL_CONNECTIONS_FILE_MAX_SIZE];
static size_t global_connections_file_length;
static bool global_connections_file_overflow;
static uint8_t global_rsa_keys_file[RADIO_GLOBAL_RSA_KEYS_FILE_MAX_SIZE];
static size_t global_rsa_keys_file_length;
static bool global_rsa_keys_file_overflow;
/* --- the removal wave ---------------------------------------------------
 * A "node X left" announcement must travel the whole mesh but must not be
 * bounced back and forth forever. This small ring remembers which removals
 * this node has already processed, which is what makes the wave terminate. */
static uint32_t radio_node_removal_cache[RADIO_NODE_REMOVAL_CACHE_SIZE];
static size_t radio_node_removal_cache_next;
/* --- the Diffie-Hellman exchange, spread over several packets -----------
 * A DH message plus its RSA signature is ~512 bytes, larger than one radio
 * frame, so it is split into fragments that may interleave with other
 * traffic. These variables are the reassembly buffers, keyed by (source,
 * sequence) so an interleaved packet from another exchange cannot corrupt
 * the one in progress.
 *
 *   dh_request_*  -> we are the RECEIVER of an exchange (someone asked us)
 *   dh_response_* -> we are the ORIGIN (we sent g^a and await the reply)
 *   dh_pending_*  -> our own secret b and modulus, parked until the reply
 *   dh_responder_pending_* -> the outcome packet we expect back from the
 *                             node we answered
 * ------------------------------------------------------------------------- */
static uint8_t dh_request_reassembly[RADIO_DH_SIGNED_REQUEST_SIZE];
static size_t dh_request_reassembly_length;
static uint32_t dh_request_reassembly_source;
static uint16_t dh_request_reassembly_sequence;
static bool dh_request_reassembly_active;
static uint32_t dh_request_completed_source;
static uint16_t dh_request_completed_sequence;
static bool dh_request_completed_valid;
static uint8_t dh_response_reassembly[RADIO_DH_SIGNED_RESPONSE_SIZE];
static size_t dh_response_reassembly_length;
static uint32_t dh_response_reassembly_source;
static uint16_t dh_response_reassembly_sequence;
static bool dh_response_reassembly_active;
static uint8_t dh_pending_private[RADIO_DH_PRIVATE_SIZE];
static uint8_t dh_pending_modulus[RADIO_DH_FIELD_SIZE];
static uint32_t dh_pending_source;
static uint32_t dh_pending_destination;
static uint16_t dh_pending_sequence;
static bool dh_pending_active;
static uint32_t dh_responder_pending_source;
static uint16_t dh_responder_pending_sequence;
static bool dh_responder_pending_active;

/* Forward declarations: the byte helpers are used by almost every function
 * below, including ones defined before them. */
static uint32_t radio_read_u32_be(const uint8_t *data);
static void radio_write_u16_be(uint8_t *data, uint16_t value);
static void radio_write_u32_be(uint8_t *data, uint32_t value);

/* FTP download callback for local_neighbors.txt.
 * ftp_download() hands us the file in pieces; this appends each piece to the
 * static buffer and flags an overflow so a truncated file can be rejected
 * rather than parsed half. */
static void radio_neighbor_file_cb(uint8_t *data, uint16_t length)
{
    /* Keep one byte spare for the terminator, because the neighbour file is
     * later parsed with C string functions (memchr/strchr/strtoul). */
    size_t available = sizeof(neighbor_file) - neighbor_file_length - 1;

    if (length > available)
    {
        length = (uint16_t)available;
        neighbor_file_overflow = true; /* caller must refuse the whole file */
    }

    memcpy(&neighbor_file[neighbor_file_length], data, length);
    neighbor_file_length += length;
    neighbor_file[neighbor_file_length] = '\0';
}

/* Same pattern for global_connections.bin. Binary, so no terminator byte is
 * reserved and the length is used as the exact size, never a NUL scan. */
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


/* Same pattern for global_rsa_key_list. */
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


/* CRC-32 (reflected, polynomial 0xEDB88320 - the standard zlib CRC).
 * Used only on the RSA key ledger transfer, where a partial file would not
 * be caught by the per-packet CRC-16: each packet is fine, the whole file is
 * not. This is the integrity check for the *transfer*, not for one packet. */
static uint32_t radio_crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = 0xFFFFFFFFu;

    for (size_t i = 0; i < length; ++i)
    {
        crc ^= data[i];
        /* Branchless bit-at-a-time CRC: the mask is 0 or all-ones. */
        for (uint8_t bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int32_t)(crc & 1u));
    }

    return ~crc;
}

/* Is this node's public key already in the ledger? Keeps the relay of a key
 * finite: the first node that stores it stops the others from re-adding it. */
static bool radio_rsa_key_address_saved(uint32_t global_address)
{
    /* A torn file must never be trusted, so a partial row means 'no'. */
    if (global_rsa_keys_file_length % RADIO_RSA_KEY_ROW_SIZE != 0)
        return false;

    /* Walk row by row; the first 4 bytes of a row are its owner's address. */
    for (size_t offset = 0;
         offset < global_rsa_keys_file_length;
         offset += RADIO_RSA_KEY_ROW_SIZE)
    {
        if (radio_read_u32_be(&global_rsa_keys_file[offset]) == global_address)
            return true;
    }

    return false;
}

/* Convert our bignum modulus into the fixed 256-byte big-endian block that
 * goes on the wire. The left-pad is essential: mpz_export drops leading zero
 * bytes, and without them the row offsets in the ledger would drift. */
static bool radio_encode_rsa_public_modulus(mpz_t public_modulo,
                                            uint8_t output[RADIO_RSA_PUBLIC_MODULUS_SIZE])
{
    /* Reject anything that is not exactly 2048 bits: the row layout and the
     * signature size both assume that exact width. */
    if (mpz_sgn(public_modulo) <= 0 ||
        mpz_sizeinbase(public_modulo, 2) != RADIO_RSA_PUBLIC_MODULUS_BITS)
        return false;

    size_t exported_length = 0;
    memset(output, 0, RADIO_RSA_PUBLIC_MODULUS_SIZE);
    mpz_export(output,
               &exported_length,
               1,   /* one limb per word */
               1,   /* most significant word first (big-endian) */
               1,   /* one byte per word */
               0,   /* no extra space at the start */
               public_modulo);

    if (exported_length > RADIO_RSA_PUBLIC_MODULUS_SIZE)
        return false;

    /* mpz_export writes right-aligned into a buffer it thinks is big enough;
     * slide the value to the right edge and clear the head. */
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


/* --- byte helpers used by every binary format in this file --------------
 * The wire is big-endian everywhere (see radio_packet_protocol.h), so these
 * are the only conversions used anywhere in the protocol. */
static uint32_t radio_read_u32_be(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}


static uint16_t radio_read_u16_be_value(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

/* bignum -> fixed-size big-endian block. The mirror of
 * radio_encode_rsa_public_modulus but for any size; used for the DH numbers
 * and for the signatures. Returns false if the value would not fit. */
static bool radio_export_mpz_fixed(mpz_t value, uint8_t *output, size_t length)
{
    if (mpz_sgn(value) < 0 || output == NULL || length == 0 ||
        mpz_sizeinbase(value, 2) > length * 8u)
        return false;

    memset(output, 0, length);
    size_t exported_length = 0;
    mpz_export(output, &exported_length, 1, 1, 1, 0, value);
    if (exported_length > length)
        return false;

    if (exported_length < length)
    {
        memmove(&output[length - exported_length], output, exported_length);
        memset(output, 0, length - exported_length);
    }

    return true;
}


/* bytes -> bignum. Inverse of radio_export_mpz_fixed, used on every packet
 * we receive: the wire is the only place a peer's numbers exist. */
static void radio_import_mpz_fixed(mpz_t value,
                                   const uint8_t *input,
                                   size_t length)
{
    mpz_import(value, length, 1, 1, 1, 0, input);
}


/* Build a PKCS#1 v1.5 'EMSA-PKCS1-v1_5' block for a SHA-256 digest.
 *
 * Why this matters: the node does not sign the raw message. It signs a
 * standard, self-describing encoding of the message's hash. That is what
 * makes the signature verifiable by any other node that knows only the
 * public key, and it is why the same helper is used on both the signing and
 * the verifying side. */
static bool radio_build_rsa_sha256_digest_info(const uint8_t *data,
                                                size_t data_length,
                                                uint8_t encoded[RADIO_RSA_PUBLIC_MODULUS_SIZE])
{
    /* 0x00 0x01 then a run of 0xFF padding, a 0x00 separator, the DER
     * prefix that says 'this is a SHA-256 digest', and the digest itself. */
    static const uint8_t digest_info_prefix[] = {
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    };
    uint8_t digest[32];
    const size_t padding_length = RADIO_RSA_PUBLIC_MODULUS_SIZE - 3u -
                                  sizeof(digest_info_prefix) - sizeof(digest);

    if (data == NULL || padding_length < 8u)
        return false;

    sha256_hash(data, data_length, digest);
    encoded[0] = 0;
    encoded[1] = 1;
    memset(&encoded[2], 0xFF, padding_length);
    encoded[2u + padding_length] = 0;
    memcpy(&encoded[3u + padding_length],
           digest_info_prefix,
           sizeof(digest_info_prefix));
    memcpy(&encoded[3u + padding_length + sizeof(digest_info_prefix)],
           digest,
           sizeof(digest));
    return true;
}


/* SIGN with this node's private key. Called every time a node sends something
 * that must be attributable: a DH request/response and the outcome packets.
 * RSA_encrypt() here is really 'modular exponentiation', used with d as the
 * exponent, i.e. the private direction. */
static bool radio_rsa_sign_sha256(const uint8_t *data,
                                 size_t data_length,
                                 mpz_t private_exponent,
                                 mpz_t rsa_modulus,
                                 uint8_t signature[RADIO_DH_SIGNATURE_SIZE])
{
    if (data == NULL || mpz_sgn(private_exponent) <= 0 ||
        mpz_sizeinbase(rsa_modulus, 2) != RADIO_RSA_PUBLIC_MODULUS_BITS)
        return false;

    uint8_t encoded[RADIO_RSA_PUBLIC_MODULUS_SIZE];
    mpz_t encoded_message;
    mpz_t signature_value;
    mpz_init(encoded_message);
    mpz_init(signature_value);

    bool success = radio_build_rsa_sha256_digest_info(data,
                                                       data_length,
                                                       encoded);
    /* The message must be smaller than the modulus or the exponentiation
     * would wrap around and the signature could not be verified. */
    if (success)
    {
        radio_import_mpz_fixed(encoded_message, encoded, sizeof(encoded));
        if (mpz_cmp(encoded_message, rsa_modulus) >= 0)
            success = false;
    }

    if (success)
    {
        RSA_encrypt(encoded_message,
                    private_exponent,
                    rsa_modulus,
                    signature_value);
        success = radio_export_mpz_fixed(signature_value,
                                         signature,
                                         RADIO_DH_SIGNATURE_SIZE);
    }

    mpz_clear(encoded_message);
    mpz_clear(signature_value);
    return success;
}


/* VERIFY with someone else's public key.
 * The counterpart of the function above: it re-computes the expected block
 * and compares it byte for byte with what the signature actually contained.
 * This is the authentication gate of the whole mesh protocol - without it,
 * any node could claim to be any other node. */
static bool radio_rsa_verify_sha256(const uint8_t *data,
                                   size_t data_length,
                                   const uint8_t signature[RADIO_DH_SIGNATURE_SIZE],
                                   mpz_t public_exponent,
                                   mpz_t rsa_modulus)
{
    if (data == NULL || signature == NULL || mpz_sgn(public_exponent) <= 0 ||
        mpz_sizeinbase(rsa_modulus, 2) != RADIO_RSA_PUBLIC_MODULUS_BITS)
        return false;

    uint8_t expected[RADIO_RSA_PUBLIC_MODULUS_SIZE];
    uint8_t recovered[RADIO_RSA_PUBLIC_MODULUS_SIZE];
    mpz_t signature_value;
    mpz_t recovered_message;
    mpz_init(signature_value);
    mpz_init(recovered_message);

    bool success = radio_build_rsa_sha256_digest_info(data,
                                                       data_length,
                                                       expected);
    if (success)
    {
        radio_import_mpz_fixed(signature_value,
                               signature,
                               RADIO_DH_SIGNATURE_SIZE);
        if (mpz_cmp(signature_value, rsa_modulus) >= 0)
            success = false;
    }

    if (success)
    {
        RSA_encrypt(signature_value,
                    public_exponent,
                    rsa_modulus,
                    recovered_message);
        success = radio_export_mpz_fixed(recovered_message,
                                         recovered,
                                         sizeof(recovered)) &&
                  memcmp(expected, recovered, sizeof(expected)) == 0;
    }

    mpz_clear(signature_value);
    mpz_clear(recovered_message);
    return success;
}


static void radio_build_dh_signature_input(uint16_t command,
                                           uint32_t source,
                                           uint32_t destination,
                                           uint16_t sequence,
                                           const uint8_t *message,
                                           size_t message_length,
                                           uint8_t *input)
{
    radio_write_u16_be(input, command);
    radio_write_u32_be(&input[2], source);
    radio_write_u32_be(&input[6], destination);
    radio_write_u16_be(&input[10], sequence);
    if (message_length > 0)
        memcpy(&input[RADIO_DH_SIGNATURE_CONTEXT_SIZE],
               message,
               message_length);
}


static bool radio_load_rsa_public_key(ftp_client_t *ftp,
                                      uint32_t global_address,
                                      mpz_t public_exponent,
                                      mpz_t public_modulus)
{
    global_rsa_keys_file_length = 0;
    global_rsa_keys_file_overflow = false;
    if (ftp == NULL ||
        !ftp_download(ftp,
                      RADIO_GLOBAL_RSA_KEYS_FILE,
                      radio_global_rsa_keys_file_cb) ||
        global_rsa_keys_file_overflow ||
        global_rsa_keys_file_length % RADIO_RSA_KEY_ROW_SIZE != 0)
        return false;

    /* Walk the ledger row by row looking for the owner's address. */
    for (size_t offset = 0;
         offset < global_rsa_keys_file_length;
         offset += RADIO_RSA_KEY_ROW_SIZE)
    {
        const uint8_t *modulus_bytes =
            &global_rsa_keys_file[offset + sizeof(uint32_t)];
        if (radio_read_u32_be(&global_rsa_keys_file[offset]) != global_address)
            continue;

        if (!radio_valid_rsa_public_modulus(modulus_bytes))
            return false;

        radio_import_mpz_fixed(public_modulus,
                               modulus_bytes,
                               RADIO_RSA_PUBLIC_MODULUS_SIZE);
        if (mpz_sizeinbase(public_modulus, 2) !=
            RADIO_RSA_PUBLIC_MODULUS_BITS)
            return false;

        /* The public exponent is a constant for the whole project: every
         * node uses e = 65537, so only the modulus has to be shared. That is
         * what keeps the ledger at 260 bytes per node instead of two numbers. */
        mpz_set_ui(public_exponent, 65537u);
        return true;
    }

    printf("No RSA public key found for %08lX\n",
           (unsigned long)global_address);
    return false;
}


/* Public helper: translate a global address into the radio address we must
 * dial. Used by send_reply() in main and by the DH handlers here. It re-
 *downloads the neighbour file each time, which is slow but keeps the file the
 * single source of truth and avoids any stale in-memory copy. */
bool radio_find_neighbor_local_address(ftp_client_t *ftp,
                                               uint32_t global_address,
                                               uint16_t *local_address)
{
    if (ftp == NULL || local_address == NULL)
        return false;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
        return false;

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
        return false;

    /* Linear scan: at most 8 neighbours, so no index is worth the RAM. */
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address == global_address)
        {
            *local_address = neighbors[i].local_address;
            return true;
        }
    }

    return false;
}

/* -------------------------------------------------------------------------
 * SENDING A SIGNED, FRAGMENTED DH MESSAGE
 *
 * The only place a large payload is split for the radio. It writes a 4-byte
 * header (total length, offset) in front of each piece so the receiver can
 * reassemble it, and keeps the SAME sequence number for every fragment - that
 * is what the reassembly state machines key on.
 * ------------------------------------------------------------------------- */
static bool radio_send_dh_signed_message(e32_t *device,
                                         uint32_t source,
                                         uint32_t destination,
                                         const uint32_t *route,
                                         uint8_t route_length,
                                         uint16_t first_hop_local_address,
                                         uint16_t command,
                                         uint16_t sequence,
                                         const uint8_t *message,
                                         size_t message_length,
                                         const uint8_t signature[RADIO_DH_SIGNATURE_SIZE])
{
    if (device == NULL || route == NULL || message == NULL || signature == NULL ||
        message_length > RADIO_DH_MESSAGE_SIZE ||
        message_length + RADIO_DH_SIGNATURE_SIZE > RADIO_DH_SIGNED_REQUEST_SIZE)
        return false;

    /* Message and signature are laid end to end once, then cut into pieces.
     * Keeping them in one buffer is what makes the offsets below simple and
     * lets the receiver split them again at a fixed, known boundary. */
    uint8_t signed_request[RADIO_DH_SIGNED_REQUEST_SIZE];
    size_t signed_request_length = message_length + RADIO_DH_SIGNATURE_SIZE;
    memcpy(signed_request, message, message_length);
    memcpy(&signed_request[message_length],
           signature,
           RADIO_DH_SIGNATURE_SIZE);

    /* Cut the buffer into radio-sized chunks. Note the empty increment: the
     * loop advances at the bottom, by exactly the bytes it just sent. */
    for (size_t offset = 0; offset < signed_request_length;)
    {
        /* Clamp to one frame; the last iteration sends the remainder. */
        size_t remaining = signed_request_length - offset;
        uint16_t fragment_length = (uint16_t)(remaining >
                                               RADIO_DH_RSA_FRAGMENT_DATA_SIZE
                                                   ? RADIO_DH_RSA_FRAGMENT_DATA_SIZE
                                                   : remaining);
        /* Every fragment carries the same total length and its own offset,
         * plus the same sequence number, so an interleaved packet from a
         * different exchange cannot be mixed into this one. */
        uint8_t fragment_data[RADIO_MAX_DATA];
        radio_write_u16_be(fragment_data,
                           (uint16_t)signed_request_length);
        radio_write_u16_be(&fragment_data[2], (uint16_t)offset);
        memcpy(&fragment_data[RADIO_DH_RSA_FRAGMENT_HEADER_SIZE],
               &signed_request[offset],
               fragment_length);

        radio_packet_t packet;
        if (!radio_packet_create(&packet,
                                 source,
                                 destination,
                                 command,
                                 RADIO_FLAG_ACK_REQUEST | RADIO_FLAG_FRAGMENT,
                                 sequence) ||
            !radio_packet_set_path(&packet, route, route_length) ||
            !radio_packet_set_data(&packet,
                                   fragment_data,
                                   (uint16_t)(RADIO_DH_RSA_FRAGMENT_HEADER_SIZE +
                                              fragment_length)) ||
            !radio_send_packet(device,
                               &packet,
                               first_hop_local_address,
                               0))
            return false;

        offset += fragment_length;
    }

    return true;
}


/* ==========================================================================
 * THE GLOBAL CONNECTION GRAPH - in-place editing of global_connections.bin
 *
 * Layout: rows of 9 uint32. Column 0 is the row's owner, columns 1..8 are
 * its neighbours, 0 means empty. Every handler that changes the mesh ends up
 * here, then uploads the whole file back to FTP.
 *
 * The 'changed' out-parameter threaded through these functions exists so the
 * caller can skip the FTP upload when a packet brought no new information -
 * which is extremely common, because the same announcement reaches every node.
 * ==========================================================================*/

/* Read one address out of the buffer. memcpy rather than a cast: the buffer
 * is a byte array whose alignment is not guaranteed to be 4. */
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


/* Pull the graph from FTP into the buffer. The modulo check is the format
 * check: a file whose size is not a whole number of rows is corrupt and must
 * not be used, because every later index computation assumes row alignment. */
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


/* Locate the row belonging to a node. Rows are unordered, so this is a scan;
 * with a 4 KiB cap that is at most ~450 comparisons. */
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


/* Is this address anywhere in the graph? Scans every word, not just column
 * 0, so it answers 'is this node known at all', which is what
 * Respond_To_New_Node uses to decide whether to rebroadcast. */
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


/* Get the row for a node, creating an empty one if it does not exist.
 * Sets *changed only when a row really was added. This is the 'insert'
 * half of every graph edit. */
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


/* Add one edge to an existing row.
 *
 * The loop deliberately looks at all 8 neighbour columns before deciding,
 * because it has to detect both 'already there' (no change, return true)
 * and 'first free slot' (use it) in one pass. */
static bool radio_add_connection_to_row(size_t row_index,
                                        uint32_t neighbor_address,
                                        bool *changed)
{
    size_t row_offset = row_index * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;
    size_t empty_offset = RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;

    /* Scan the 8 neighbour columns. */
    for (uint8_t column = 1; column < 9; ++column)
    {
        size_t offset = row_offset + column * sizeof(uint32_t);
        uint32_t existing = radio_read_global_connection_word(offset);
        if (existing == neighbor_address)
            return true; /* edge already present: not a change */
        if (existing == 0 && empty_offset == RADIO_GLOBAL_CONNECTIONS_ROW_SIZE)
            empty_offset = offset - row_offset; /* remember the first hole */
    }

    if (empty_offset == RADIO_GLOBAL_CONNECTIONS_ROW_SIZE)
        return false;

    radio_write_global_connection_word(row_offset + empty_offset,
                                       neighbor_address);
    *changed = true;
    return true;
}


/* The primitive every mesh edit is built from: record an edge in BOTH
 * directions. Doing it symmetrically is what lets any node later run a
 * search over the graph without knowing which node learned the edge first. */
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


/* --- the removal wave, part 1: 'have I already processed this?' ---------
 * A plain ring buffer, not a set: we only need 'did I see this before', and
 * a bounded history is enough because the wave is finite. */
static bool radio_node_removal_seen(uint32_t global_address)
{
    for (size_t i = 0; i < RADIO_NODE_REMOVAL_CACHE_SIZE; ++i)
    {
        if (radio_node_removal_cache[i] == global_address)
            return true;
    }

    return false;
}


/* Record that we processed this removal, overwriting the oldest entry. */
static void radio_mark_node_removal_seen(uint32_t global_address)
{
    radio_node_removal_cache[radio_node_removal_cache_next] = global_address;
    radio_node_removal_cache_next =
        (radio_node_removal_cache_next + 1u) % RADIO_NODE_REMOVAL_CACHE_SIZE;
}


/* Delete a node from the graph: drop its own row and blank every reference
 * to it in other rows. The compaction (retained_rows) is what keeps the
 * file a whole number of rows, so the format check on the next download
 * still passes. */
static bool radio_remove_global_connection_node(uint32_t global_address,
                                                bool *changed)
{
    size_t row_count = global_connections_file_length /
                       RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;
    size_t retained_rows = 0;

    /* Compact-in-place rewrite: rows we keep are slid down over the ones we
     * drop, so no second buffer is needed. */
    for (size_t row = 0; row < row_count; ++row)
    {
        size_t row_offset = row * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;
        uint32_t row_address = radio_read_global_connection_word(row_offset);
        if (row_address == global_address)
        {
            *changed = true;
            continue; /* this is the node itself: its row is deleted */
        }

        /* Any other row that lists it as a neighbour keeps the row but
         * blanks the slot, so the edge disappears from both sides. */
        for (uint8_t column = 1; column < 9; ++column)
        {
            size_t word_offset = row_offset + column * sizeof(uint32_t);
            if (radio_read_global_connection_word(word_offset) == global_address)
            {
                radio_write_global_connection_word(word_offset, 0);
                *changed = true;
            }
        }

        if (retained_rows != row)
        {
            memmove(&global_connections_file[
                        retained_rows * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE],
                    &global_connections_file[row_offset],
                    RADIO_GLOBAL_CONNECTIONS_ROW_SIZE);
        }
        ++retained_rows;
    }

    global_connections_file_length =
        retained_rows * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;
    return true;
}


/* Decode local_neighbors.txt into a struct array.
 *
 * The file is text on purpose ("%08lX,%u\n" per line) so it can be inspected
 * with a plain FTP client. The parser is deliberately strict: a line is only
 * accepted if the hex part ends exactly at the comma and the decimal part
 * ends exactly at the line end. Anything else is skipped, so a hand-edited
 * or corrupted file degrades to 'fewer neighbours' rather than to garbage. */
bool radio_parse_neighbor_file(radio_neighbor_t *neighbors,
                               uint8_t *neighbor_count)
{
    char *line = (char *)neighbor_file;
    char *end = (char *)neighbor_file + neighbor_file_length;
    uint8_t count = 0;

    /* One iteration per line, stopping at the buffer end or the cap. */
    while (line < end && count < RADIO_NEIGHBOR_COUNT_MAX)
    {
        /* Find the end of this line; the last line may have no newline. */
        char *line_end = memchr(line, '\n', (size_t)(end - line));
        if (line_end == NULL)
            line_end = end;

        *line_end = '\0'; /* temporarily terminate so strtoul can be used */

        char *separator = strchr(line, ',');
        if (separator != NULL)
        {
            char *global_end;
            char *local_end;
            /* Global address is hex (it is a 32-bit counter), the local one
             * is decimal (it is a 16-bit radio address). */
            unsigned long global_address = strtoul(line, &global_end, 16);
            unsigned long local_address = strtoul(separator + 1,
                                                  &local_end,
                                                  10);

            /* Tolerate the whitespace a human might have typed. */
            while (*global_end == ' ' || *global_end == '\t')
                ++global_end;
            while (*local_end == ' ' || *local_end == '\t' ||
                   *local_end == '\r')
                ++local_end;

            /* Strict acceptance test, including the range checks. */
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


/* ==========================================================================
 * PUBLIC PROTOCOL FUNCTIONS
 *
 * From here on the functions correspond one-to-one to the commands listed in
 * radio_packet_protocol.h. Read them in the order the boot sequence uses them:
 * download/parse the neighbour file -> pick a local address -> announce
 * ourselves -> pull the global graph and the key ledger -> optionally start a
 * DH exchange.
 * ==========================================================================*/
bool radio_download_neighbor_file(ftp_client_t *ftp)
{
    neighbor_file_length = 0;
    neighbor_file_overflow = false;

    if (ftp == NULL)
        return false;

    /* A missing file is the normal situation for a node that has never
       joined the mesh, so a failed download means "brand new node". */
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb))
        return false;

    return !neighbor_file_overflow;
}


/*
 * A node is brand new when it has no neighbour list on the FTP server:
 * the file is missing, empty, or contains no valid "GLOBAL,LOCAL" entry.
 */
bool radio_is_new_node(ftp_client_t *ftp)
{
    if (!radio_download_neighbor_file(ftp))
        return true;

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;

    return !radio_parse_neighbor_file(neighbors, &neighbor_count);
}


/* Pick the neighbour with the SMALLEST global address, i.e. the node that
 * was created earliest. That node has had the longest time to learn about the
 * mesh, so its copy of global_connections.bin is the most complete one
 * available nearby - which is why the join sequence asks it and nobody else. */
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

    /* Scan our neighbours, skipping ourselves, and keep the minimum. */
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


/* Reads the local address out of a 6-byte neighbour record produced by
 * Respond_To_Connections_Request: [global:4][local:2]. The offset is baked in
 * on purpose, and the name now says so - it is NOT a generic big-endian reader
 * (that one is radio_read_u16_be_value). */
static uint16_t radio_read_local_address_in_record(const uint8_t *record)
{
    return (uint16_t)(((uint16_t)record[4] << 8) | record[5]);
}


/* The generic writers, used by every handler that builds a payload. */
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


/* Is a candidate radio address already taken by someone we know?
 * Linear scan over at most 64 entries - small enough that a set would cost
 * more RAM than it saves. */
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


/* -------------------------------------------------------------------------
 * LOCAL ADDRESS ALLOCATION - step 2 of the join sequence.
 *
 * The E32 radio addresses nodes with a bare 16-bit number, so two physically
 * adjacent nodes that picked the same number would hear each other's packets
 * mixed together. There is no coordinator, so the node asks every neighbour
 * for ITS neighbour list, unions all the addresses in use, and takes a free
 * one. A collision is only possible with a node that is not in either list,
 * i.e. one that is out of range - where a clash does not matter.
 * ------------------------------------------------------------------------- */
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

    /* Phase 1 - ask every neighbour for its neighbour list.
     * A different sequence number per neighbour, so the replies can be told
     * apart even though they all carry the same command. */
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

    /* Phase 2 - collect the answers. This is the only non-deterministic part
     * of the protocol: packets arrive in any order and may interleave with
     * unrelated traffic, so the filter below has to accept only our own
     * requests' replies. The length checks re-derive the record structure
     * from the wire, so a malformed packet is simply ignored. */
    uint16_t received_local_addresses[64];
    size_t received_count = 0;
    absolute_time_t timeout =
        make_timeout_time_ms(RADIO_CONNECTION_RESPONSE_TIMEOUT_MS);

    /* Wait a fixed window rather than a fixed count: a neighbour that does
     * not answer just contributes nothing. */
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
            /* Walk the payload as 6-byte records: [global:4][local:2]. */
            for (uint16_t offset = 0;
                 offset < response.length && received_count < 64;
                 offset += RADIO_CONNECTION_RECORD_SIZE)
            {
                uint16_t local_address =
                    radio_read_local_address_in_record(&response.data[offset]);

                /* De-duplicate: the same neighbour appears in several lists. */
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

    /* Phase 3 - choose. Start from a random value so that two nodes joining
     * at the same moment do not both pick 1, then walk forward deterministically
     * so the search always terminates. 0 is never used: it means 'unused'. */
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


/* -------------------------------------------------------------------------
 * Serving side of the neighbour-list exchange (RADIO_CMD_SEND_CONNECTIONS).
 * Paired with the collection loop in Generate_Local_Adress: this is what
 * answers that request. It is also the reason every node's view of its
 * physical neighbourhood is symmetric.
 * ------------------------------------------------------------------------- */
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

    /* Serialize our neighbour list into the 6-byte record format. */
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

    /* Choose the radio to answer through. We must NOT broadcast: only the
     * requester can be the one waiting for this reply, and broadcasting would
     * also reach every other neighbour, wasting radio traffic. */
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


/* -------------------------------------------------------------------------
 * PULL THE GLOBAL GRAPH (join-sequence step 4a).
 *
 * Only the oldest neighbour is asked, and only once: its copy of the graph is
 * the most complete one around. The result is uploaded to OUR OWN FTP server,
 * which is where this node's permanent copy of the mesh lives.
 * ------------------------------------------------------------------------- */
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

    /* Reassembly of a chunked file. Each chunk says 'the file is N bytes
     * long, this piece starts at offset M'. Accepting a chunk only when
     * M equals what we have so far is what makes out-of-order or duplicated
     * chunks harmless, and lets us stop as soon as the file is complete. */
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

            /* Every condition here is a rejection of a possible corruption:
             * too big for RAM, not a whole number of rows, not the piece we
             * expect next, bigger than one frame, or past the declared end. */
            if (total_length <= sizeof(global_connections_file) &&
                total_length % RADIO_GLOBAL_CONNECTIONS_ROW_SIZE == 0 &&
                offset == global_connections_file_length &&
                chunk_length <= RADIO_GLOBAL_CONNECTIONS_CHUNK_SIZE &&
                offset + chunk_length <= total_length)
            {
                /* The first accepted chunk fixes the target size; every later
                 * chunk must agree with it or it is discarded. */
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


/* -------------------------------------------------------------------------
 * Serving side of the graph transfer. Paired with the reassembly loop above:
 * same chunk header, same sizes, opposite direction.
 * ------------------------------------------------------------------------- */
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

    /* Stream the file out in RADIO_MAX_DATA-sized pieces. The sequence number
     * is incremented per chunk so the receiver can see progress and reject a
     * chunk that belongs to a different request. */
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


/* -------------------------------------------------------------------------
 * PULL THE RSA KEY LEDGER (join-sequence step 4b).
 *
 * Unlike the graph, this file is verified with a CRC-32 and retried, because
 * a wrong key does not crash anything - it silently makes every later
 * signature check fail, which is much harder to notice.
 * ------------------------------------------------------------------------- */
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

    /* Sort neighbours oldest-first (selection sort, at most 8 items).
     * Try the most-informed neighbour first so the first attempt usually
     * succeeds and no retry traffic is generated. */
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

    /* Try each neighbour in turn; the inner loop retries the same neighbour,
     * which covers a lost or corrupted transmission. */
    static uint16_t sequence;
    for (uint8_t neighbor_index = 0;
         neighbor_index < neighbor_count;
         ++neighbor_index)
    {
        radio_neighbor_t *provider = &neighbors[neighbor_index];
        if (provider->global_address == global_address)
            continue; /* that is us: our own copy is already correct */

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

            /* Three independent checks: the declared size was reached, nothing
             * was dropped, and the CRC the sender advertised matches. Only
             * then is the ledger safe to store. */
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

            /* Tell the provider we stored it. Without this the provider would
             * keep re-sending the whole file every time it sees our request. */
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


/* Serving side of the key-ledger transfer. Note the CRC is computed once over
 * the whole file and repeated in every chunk header - the receiver only needs
 * it once, but repeating it makes a truncated stream detectable. */
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

    /* Chunked send, same geometry as the graph transfer above. */
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


/* -------------------------------------------------------------------------
 * SHORTEST ROUTE THROUGH THE MESH (breadth-first search)
 *
 * This is what makes the Diffie-Hellman exchange possible between nodes that
 * are not physically adjacent: it turns the adjacency list into an ordered
 * list of global addresses, which the DH senders then convert hop by hop into
 * 16-bit radio addresses with radio_find_neighbor_local_address.
 *
 * Everything is done on indices into nodes[] rather than on addresses, so the
 * 'is this node already visited' test is an array lookup instead of a scan.
 * ------------------------------------------------------------------------- */
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

    /* Parallel arrays = a tiny struct-of-arrays graph node record.
     * parent is -1 for 'unvisited', -2 for 'this is the start' (so the
     * reconstruction loop below has a sentinel to stop at). */
    uint32_t nodes[RADIO_GLOBAL_CONNECTIONS_MAX_NODES];
    int16_t parent[RADIO_GLOBAL_CONNECTIONS_MAX_NODES];
    uint8_t depth[RADIO_GLOBAL_CONNECTIONS_MAX_NODES];
    uint16_t queue[RADIO_GLOBAL_CONNECTIONS_MAX_NODES];
    size_t node_count = 0;
    size_t row_count = global_connections_file_length /
                       RADIO_GLOBAL_CONNECTIONS_ROW_SIZE;

    /* Phase 1 - build the vertex set. Every address mentioned anywhere in the
     * file becomes a node, whether or not it owns a row (a node can appear
     * only as someone else's neighbour). */
    for (size_t row = 0; row < row_count; ++row)
    {
        /* Column 0 is the row owner, 1..8 are its neighbours. */
        for (uint8_t column = 0; column < 9; ++column)
        {
            uint32_t address;
            memcpy(&address,
                   &global_connections_file[row * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE +
                                            column * sizeof(uint32_t)],
                   sizeof(address));

            if (address == 0)
                continue;

            /* De-duplicate: the same address appears in its own row and in
             * every row that lists it as a neighbour. Linear because the
             * vertex count is bounded by the 4 KiB file cap. */
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

    /* Phase 2 - map the two endpoints to indices. node_count is used as the
     * 'not found' sentinel, which is safe because it is one past the end. */
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

    /* Phase 3 - the breadth-first search. FIFO order is what guarantees the
     * first time we reach the destination it is by a shortest route, which
     * is what keeps radio traffic minimal. */
    size_t queue_head = 0;
    size_t queue_tail = 0;
    queue[queue_tail++] = (uint16_t)source_index;
    parent[source_index] = -2;

    /* Stop as soon as the destination has a parent: no need to explore the
     * rest of the mesh. */
    while (queue_head < queue_tail && parent[destination_index] == -1)
    {
        size_t current_index = queue[queue_head++];
        /* Depth cap: a route longer than the packet's path[] could not be
         * transmitted anyway, so we refuse it instead of truncating it. */
        if (depth[current_index] >= RADIO_GLOBAL_ROUTE_MAX_JUMPS)
            continue;

        /* Find the row for the current node. The file is unsorted, so this
         * is a scan - acceptable at a few hundred rows, and it is the reason
         * the search is O(V^2) rather than O(V+E). */
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

        /* Expand: push every neighbour we have not visited yet. */
        for (uint8_t column = 1; column < 9; ++column)
        {
            uint32_t neighbor;
            memcpy(&neighbor,
                   &global_connections_file[row * RADIO_GLOBAL_CONNECTIONS_ROW_SIZE +
                                            column * sizeof(uint32_t)],
                   sizeof(neighbor));
            if (neighbor == 0)
                continue;

            /* Translate the address back to an index, and skip it if it is
             * unknown or already reached (parent != -1 means visited). */
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

            /* Recording the parent is both the visited mark and the
             * breadcrumb trail used by the reconstruction below. */
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

    /* Phase 4 - walk the breadcrumbs backwards from the destination until the
     * start's sentinel (-2) is reached. This yields the route in reverse. */
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

    /* Flip it, so path[0] is the requester and path[n-1] the target - the
     * order radio_packet_set_path and the senders expect. */
    for (uint8_t i = 0; i < reverse_length; ++i)
        path[i] = nodes[reverse_path[reverse_length - i - 1]];

    *path_length = reverse_length;
    return true;
}


/* -------------------------------------------------------------------------
 * MESH CHANGE PROPAGATION
 *
 * None of these functions has a global view. Each one tells its neighbours
 * and each neighbour relays further, so a change spreads as a wave through
 * the graph. The removal cache and the 'already known' tests are what stop
 * that wave from bouncing back along the edge it came from.
 * ------------------------------------------------------------------------- */

/* Tell everyone we know that a node has left the mesh. */
bool Relay_Node_Removal(uint32_t global_address,
                        e32_t *radio,
                        ftp_client_t *ftp)
{
    if (radio == NULL || ftp == NULL || global_address == 0)
        return false;

    /* Already processed this removal? Return success without re-sending,
     * which is the termination condition of the wave. */
    if (radio_node_removal_seen(global_address))
        return true;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    if (neighbor_file_length == 0)
        return true;

    radio_neighbor_t neighbors[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbor_count = 0;
    if (!radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    /* Send to every neighbour except the node that is being removed (it is
     * gone, so nobody there needs the news) and count failures rather than
     * aborting: a partial wave is still useful to the rest of the mesh. */
    static uint16_t sequence;
    ++sequence;
    radio_mark_node_removal_seen(global_address);
    bool sent = true;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address == global_address)
            continue;

        radio_packet_t request;
        if (!radio_packet_create(&request,
                                 global_address,
                                 neighbors[i].global_address,
                                 RADIO_CMD_RELAY_REMOVE_NODE,
                                 RADIO_FLAG_ACK_REQUEST,
                                 sequence) ||
            !radio_send_packet(radio,
                               &request,
                               neighbors[i].local_address,
                               0))
        {
            printf("Failed to request node removal from %08lX\n",
                   (unsigned long)neighbors[i].global_address);
            sent = false;
        }
    }

    return sent;
}


/* Announce a node that has just joined. The payload is the same 9-word
 * record used everywhere: [new node, its neighbours..., 0 padding]. Sending
 * the neighbour list with the announcement is what lets a distant node insert
 * the correct edges without ever talking to the new node directly. */
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

    /* Build the record: our own address first, then every neighbour we have,
     * skipping ourselves. Zero-initialised, so unused slots are the 'empty'
     * marker the receiving side expects. */
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


/* Receiving side of the join announcement. This is where a node that is far
 * from the newcomer still learns about it: the record carries the newcomer's
 * own neighbour list, so the edges can be added locally. */
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

    /* Read the announced neighbour list out of the payload. */
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

    /* Merge every announced edge into our copy of the graph. */
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

    /* Only a node we had never heard of is worth relaying. A known node may
     * have needed edge repair (done above) but re-broadcasting it would make
     * the wave infinite. */
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

    /* Forward the announcement unchanged, but re-addressed as coming from the
     * new node (not from us) and sent to every neighbour we have. */
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


/* Publish our own public key. Called once per node; the relay form (below)
 * is what carries other nodes' keys across the mesh. */
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

    /* Skip ourselves: our own copy of the ledger already has our key. */
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


/* Receiving side of the key relay: store it if new, then pass it on.
 * The 'already have it' test is the termination condition, exactly like the
 * one in Respond_To_New_Node. */
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

    /* Append the row: 4-byte owner address, then the 256-byte modulus. */
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
    /* Relay to every neighbour except ourselves and except the key's owner:
     * the owner already holds its own key, so sending it back is pure waste.
     * (The packet does not record which hop it arrived from, so the owner is
     * the only hop we can prove does not need it - that is why the previous
     * code terminated only via radio_rsa_key_address_saved.) */
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address == global_address ||
            neighbors[i].global_address == owner_address)
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

/* ==========================================================================
 * THE DIFFIE-HELLMAN EXCHANGE
 *
 * Why it exists: two nodes that want to exchange encrypted DATA packets must
 * agree on a key, and the only channel they have is the mesh itself. Classic
 * DH needs two rounds of communication, which the route in
 * Find_Shortest_Global_Route provides. The agreed value is then truncated to
 * the ChaCha20-Poly1305 key used by handle_data_packet() in main.
 *
 * The three handlers below are the three legs of that conversation:
 *   Create_DH_Exchange_Packet      -> we send g^a mod p
 *   Respond_To_DH_Exchange_Request -> they answer with g^b mod p, we compute
 *   Respond_To_DH_Exchange_Response-> we answer, they confirm
 *   Respond_To_DH_Exchange_Result  -> the outcome is reported back
 *
 * Every leg is RSA-signed by its sender and verified against the key ledger,
 * so a leg that cannot be attributed is dropped rather than acted on.
 * ==========================================================================*/

/* Leg 2, our side: we were asked. Reassemble the fragments, verify the
 * signature, then generate our own exponent b and reply. */
bool Respond_To_DH_Exchange_Request(uint32_t global_address,
                                    e32_t *radio_device,
                                    ftp_client_t *ftp,
                                    const radio_packet_t *request,
                                    mpz_t private_rsa_exponent,
                                    mpz_t rsa_modulus,
                                    mpz_t shared_secret)
{
    if (radio_device == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_SEND_ENCRYPTION_REQUEST ||
        request->path_length < 2 ||
        request->path_length > RADIO_MAX_ROUTE_ADDRESSES ||
        request->path[0] != request->source ||
        request->path[request->path_length - 1u] != global_address ||
        request->destination != global_address ||
        (request->flags & RADIO_FLAG_FRAGMENT) == 0 ||
        request->length <= RADIO_DH_RSA_FRAGMENT_HEADER_SIZE)
        return false;

    uint16_t total_length = radio_read_u16_be_value(request->data);
    uint16_t offset = radio_read_u16_be_value(&request->data[2]);
    size_t fragment_length = request->length -
                             RADIO_DH_RSA_FRAGMENT_HEADER_SIZE;
    if (total_length != RADIO_DH_SIGNED_REQUEST_SIZE ||
        offset > total_length ||
        fragment_length > total_length - offset)
        return false;

    /* Already finished this exchange? Answer once, not once per fragment. */
    if (dh_request_completed_valid &&
        dh_request_completed_source == request->source &&
        dh_request_completed_sequence == request->sequence)
        return true;

    /* Start a new reassembly only at a fragment with offset 0; anything else
     * means we lost the beginning of the message and must drop the rest. */
    if (!dh_request_reassembly_active ||
        dh_request_reassembly_source != request->source ||
        dh_request_reassembly_sequence != request->sequence)
    {
        if (offset != 0)
            return false;
        dh_request_reassembly_source = request->source;
        dh_request_reassembly_sequence = request->sequence;
        dh_request_reassembly_length = 0;
        dh_request_reassembly_active = true;
    }

    if (offset != dh_request_reassembly_length)
        return false;

    memcpy(&dh_request_reassembly[offset],
           &request->data[RADIO_DH_RSA_FRAGMENT_HEADER_SIZE],
           fragment_length);
    /* Return early while the message is still incomplete: 'true' here means
     * 'accepted, nothing to do yet'. Only a full reassembly continues down. */
    dh_request_reassembly_length += fragment_length;
    if (dh_request_reassembly_length < total_length)
        return true;

    dh_request_reassembly_active = false;
    mpz_set_ui(shared_secret, 0);

    const uint8_t *message = dh_request_reassembly;
    const uint8_t *signature =
        &dh_request_reassembly[RADIO_DH_MESSAGE_SIZE];
    uint8_t signature_input[RADIO_DH_SIGNATURE_INPUT_MAX_SIZE];
    radio_build_dh_signature_input(RADIO_CMD_SEND_ENCRYPTION_REQUEST,
                                   request->source,
                                   global_address,
                                   request->sequence,
                                   message,
                                   RADIO_DH_MESSAGE_SIZE,
                                   signature_input);

    mpz_t sender_public_exponent;
    mpz_t sender_rsa_modulus;
    mpz_t dh_modulus;
    mpz_t sender_dh_number;
    mpz_t receiver_private_number;
    mpz_t receiver_dh_number;
    mpz_t generator;
    mpz_t derived_secret;
    mpz_init(sender_public_exponent);
    mpz_init(sender_rsa_modulus);
    mpz_init(dh_modulus);
    mpz_init(sender_dh_number);
    mpz_init(receiver_private_number);
    mpz_init(receiver_dh_number);
    mpz_init(generator);
    mpz_init(derived_secret);

    bool success = false;
    if (!radio_load_rsa_public_key(ftp,
                                   request->source,
                                   sender_public_exponent,
                                   sender_rsa_modulus) ||
        !radio_rsa_verify_sha256(signature_input,
                                 RADIO_DH_SIGNATURE_CONTEXT_SIZE +
                                     RADIO_DH_MESSAGE_SIZE,
                                 signature,
                                 sender_public_exponent,
                                 sender_rsa_modulus))
    {
        printf("Encryption request signature is invalid\n");
        goto cleanup_dh_request;
    }

    radio_import_mpz_fixed(dh_modulus, message, RADIO_DH_FIELD_SIZE);
    radio_import_mpz_fixed(sender_dh_number,
                           &message[RADIO_DH_FIELD_SIZE],
                           RADIO_DH_FIELD_SIZE);
    if (mpz_sizeinbase(dh_modulus, 2) != RADIO_DH_MODULUS_BITS ||
        mpz_even_p(dh_modulus) ||
        mpz_probab_prime_p(dh_modulus, 8) == 0 ||
        mpz_cmp_ui(sender_dh_number, 1) <= 0 ||
        mpz_cmp(sender_dh_number, dh_modulus) >= 0)
    {
        printf("Encryption request contains invalid DH parameters\n");
        goto cleanup_dh_request;
    }

    /* THE ACTUAL EXCHANGE. Generator 2 is a convention shared by all nodes,
     * so it never has to be transmitted. We invent our own secret b, publish
     * g^b mod p, and derive the secret as (g^a)^b mod p. */
    mpz_set_ui(generator, 2);
    DH_Generate_Private_Number(receiver_private_number);
    DH_Generate_Sending_Number(receiver_dh_number,
                               generator,
                               dh_modulus,
                               receiver_private_number);
    DH_Shared_Secret(derived_secret,
                     sender_dh_number,
                     dh_modulus,
                     receiver_private_number);

        /* The reply carries g^b mod p AND a SHA-256 of the shared secret.
         * That hash is the proof: the other end can recompute the secret from
         * its own private number and compare, without ever transmitting the
         * secret itself. */
        uint8_t response_message[RADIO_DH_RESPONSE_MESSAGE_SIZE];
        uint8_t shared_secret_bytes[RADIO_DH_FIELD_SIZE];
        uint8_t response_hash[RADIO_DH_HASH_SIZE];
        if (!radio_export_mpz_fixed(receiver_dh_number,
                        response_message,
                        RADIO_DH_FIELD_SIZE) ||
         !radio_export_mpz_fixed(derived_secret,
                        shared_secret_bytes,
                        RADIO_DH_FIELD_SIZE))
        goto cleanup_dh_request;
        sha256_hash(shared_secret_bytes,
              sizeof(shared_secret_bytes),
              response_hash);
        memcpy(&response_message[RADIO_DH_FIELD_SIZE],
            response_hash,
            sizeof(response_hash));

    /* The reply must go back along the exact route the request came by,
     * reversed. Reversing rather than recomputing avoids two nodes disagreeing
     * about which route connects them. */
    uint32_t response_route[RADIO_MAX_ROUTE_ADDRESSES];
    for (uint8_t i = 0; i < request->path_length; ++i)
        response_route[i] = request->path[request->path_length - i - 1u];

    /* Convert the first hop of the reversed route into a radio address. If
     * we cannot address that node, the reply cannot be sent at all. */
    uint16_t first_hop_local_address;
    if (!radio_find_neighbor_local_address(ftp,
                                           response_route[1],
                                           &first_hop_local_address))
    {
        printf("No local radio address for response next hop %08lX\n",
               (unsigned long)response_route[1]);
        goto cleanup_dh_request;
    }

    /* Sign with OUR private key, then fragment the (message||signature)
     * buffer onto the reversed route. */
    uint8_t response_signature[RADIO_DH_SIGNATURE_SIZE];
    radio_build_dh_signature_input(RADIO_CMD_SEND_ENCRYPTION_RESPONSE,
                                   global_address,
                                   request->source,
                                   request->sequence,
                                   response_message,
                                   sizeof(response_message),
                                   signature_input);
    if (!radio_rsa_sign_sha256(signature_input,
                               RADIO_DH_SIGNATURE_CONTEXT_SIZE +
                                   sizeof(response_message),
                               private_rsa_exponent,
                               rsa_modulus,
                               response_signature) ||
        !radio_send_dh_signed_message(radio_device,
                                      global_address,
                                      request->source,
                                      response_route,
                                      request->path_length,
                                      first_hop_local_address,
                                      RADIO_CMD_SEND_ENCRYPTION_RESPONSE,
                                      request->sequence,
                                      response_message,
                                      sizeof(response_message),
                                      response_signature))
    {
        printf("Failed to send signed DH response\n");
        goto cleanup_dh_request;
    }

    /* Remember that this exchange is done, so the other fragments of the same
     * request are ignored, and remember that we now expect a result packet
     * back from the origin. */
    dh_request_completed_source = request->source;
    dh_request_completed_sequence = request->sequence;
    dh_request_completed_valid = true;
    mpz_set(shared_secret, derived_secret);
    dh_responder_pending_source = request->source;
    dh_responder_pending_sequence = request->sequence;
    dh_responder_pending_active = true;
    success = true;

cleanup_dh_request:
    mpz_clear(sender_public_exponent);
    mpz_clear(sender_rsa_modulus);
    mpz_clear(dh_modulus);
    mpz_clear(sender_dh_number);
    mpz_clear(receiver_private_number);
    mpz_clear(receiver_dh_number);
    mpz_clear(generator);
    mpz_clear(derived_secret);
    return success;
}


/* The tiny 'outcome' packet: no payload, just a signature over
 * command+source+destination+sequence. The command itself (CONFIRMED/FAILED)
 * is inside the signed bytes, so the outcome cannot be flipped in flight. */
static bool radio_send_dh_exchange_result(e32_t *radio_device,
                                          uint32_t source,
                                          uint32_t destination,
                                          const uint32_t *route,
                                          uint8_t route_length,
                                          uint16_t first_hop_local_address,
                                          uint16_t command,
                                          uint16_t sequence,
                                          mpz_t private_rsa_exponent,
                                          mpz_t rsa_modulus)
{
    uint8_t signature_input[RADIO_DH_SIGNATURE_CONTEXT_SIZE];
    uint8_t signature[RADIO_DH_SIGNATURE_SIZE];
    radio_build_dh_signature_input(command,
                                   source,
                                   destination,
                                   sequence,
                                   NULL,
                                   0,
                                   signature_input);
    if (!radio_rsa_sign_sha256(signature_input,
                               sizeof(signature_input),
                               private_rsa_exponent,
                               rsa_modulus,
                               signature))
        return false;

    radio_packet_t result;
    return radio_packet_create(&result,
                               source,
                               destination,
                               command,
                               0,
                               sequence) &&
           radio_packet_set_path(&result, route, route_length) &&
           radio_packet_set_data(&result, signature, sizeof(signature)) &&
           radio_send_packet(radio_device,
                             &result,
                             first_hop_local_address,
                             0);
}


/* Leg 3, our side: WE started the exchange and the other node has answered.
 * Recompute the shared secret with the b we parked in dh_pending_* and check
 * its hash against the one they sent. */
bool Respond_To_DH_Exchange_Response(uint32_t global_address,
                                     e32_t *radio_device,
                                     ftp_client_t *ftp,
                                     const radio_packet_t *response,
                                     mpz_t private_rsa_exponent,
                                     mpz_t rsa_modulus,
                                     mpz_t shared_secret)
{
    /* The pending state is the whole state machine here: a response is only
     * meaningful if we actually sent a request, and it must match it exactly
     * (source, destination and sequence). */
    if (radio_device == NULL || ftp == NULL || response == NULL ||
        !dh_pending_active ||
        response->command != RADIO_CMD_SEND_ENCRYPTION_RESPONSE ||
        response->source != dh_pending_destination ||
        response->destination != global_address ||
        global_address != dh_pending_source ||
        response->sequence != dh_pending_sequence ||
        response->path_length < 2 ||
        response->path_length > RADIO_MAX_ROUTE_ADDRESSES ||
        response->path[0] != response->source ||
        response->path[response->path_length - 1u] != global_address ||
        (response->flags & RADIO_FLAG_FRAGMENT) == 0 ||
        response->length <= RADIO_DH_RSA_FRAGMENT_HEADER_SIZE)
        return false;

    uint16_t total_length = radio_read_u16_be_value(response->data);
    uint16_t offset = radio_read_u16_be_value(&response->data[2]);
    size_t fragment_length = response->length -
                             RADIO_DH_RSA_FRAGMENT_HEADER_SIZE;
    if (total_length != RADIO_DH_SIGNED_RESPONSE_SIZE ||
        offset > total_length ||
        fragment_length > total_length - offset)
        return false;

    /* Same fragment reassembly as the request side, but keyed by the
     * response's own source/sequence. */
    if (!dh_response_reassembly_active ||
        dh_response_reassembly_source != response->source ||
        dh_response_reassembly_sequence != response->sequence)
    {
        if (offset != 0)
            return false;
        dh_response_reassembly_source = response->source;
        dh_response_reassembly_sequence = response->sequence;
        dh_response_reassembly_length = 0;
        dh_response_reassembly_active = true;
    }

    if (offset != dh_response_reassembly_length)
        return false;

    memcpy(&dh_response_reassembly[offset],
           &response->data[RADIO_DH_RSA_FRAGMENT_HEADER_SIZE],
           fragment_length);
    dh_response_reassembly_length += fragment_length;
    if (dh_response_reassembly_length < total_length)
        return true;
    dh_response_reassembly_active = false;

    mpz_set_ui(shared_secret, 0);
    const uint8_t *message = dh_response_reassembly;
    const uint8_t *signature =
        &dh_response_reassembly[RADIO_DH_RESPONSE_MESSAGE_SIZE];
    uint8_t signature_input[RADIO_DH_SIGNATURE_INPUT_MAX_SIZE];
    radio_build_dh_signature_input(RADIO_CMD_SEND_ENCRYPTION_RESPONSE,
                                   response->source,
                                   global_address,
                                   response->sequence,
                                   message,
                                   RADIO_DH_RESPONSE_MESSAGE_SIZE,
                                   signature_input);

    /* The result packet goes back the way the response came, i.e. to us. */
    uint32_t result_route[RADIO_MAX_ROUTE_ADDRESSES];
    for (uint8_t i = 0; i < response->path_length; ++i)
        result_route[i] = response->path[response->path_length - i - 1u];

    uint16_t first_hop_local_address;
    bool route_available = radio_find_neighbor_local_address(
        ftp,
        result_route[1],
        &first_hop_local_address);

    mpz_t sender_public_exponent;
    mpz_t sender_rsa_modulus;
    mpz_t dh_modulus;
    mpz_t private_number;
    mpz_t peer_dh_number;
    mpz_t derived_secret;
    mpz_init(sender_public_exponent);
    mpz_init(sender_rsa_modulus);
    mpz_init(dh_modulus);
    mpz_init(private_number);
    mpz_init(peer_dh_number);
    mpz_init(derived_secret);

    /* Verify their signature with THEIR public key from the ledger. */
    bool matched = false;
    if (route_available &&
        radio_load_rsa_public_key(ftp,
                                  response->source,
                                  sender_public_exponent,
                                  sender_rsa_modulus) &&
        radio_rsa_verify_sha256(signature_input,
                                RADIO_DH_SIGNATURE_CONTEXT_SIZE +
                                    RADIO_DH_RESPONSE_MESSAGE_SIZE,
                                signature,
                                sender_public_exponent,
                                sender_rsa_modulus))
    {
        radio_import_mpz_fixed(dh_modulus,
                               dh_pending_modulus,
                               sizeof(dh_pending_modulus));
        radio_import_mpz_fixed(private_number,
                               dh_pending_private,
                               sizeof(dh_pending_private));
        radio_import_mpz_fixed(peer_dh_number,
                               message,
                               RADIO_DH_FIELD_SIZE);

        /* Recompute the secret as (their g^b)^our a, then hash it and compare
         * with the hash they sent. Equality proves both sides used the same
         * p and the same a - it is the handshake's confirmation. */
        if (mpz_cmp_ui(peer_dh_number, 1) > 0 &&
            mpz_cmp(peer_dh_number, dh_modulus) < 0)
        {
            DH_Shared_Secret(derived_secret,
                             peer_dh_number,
                             dh_modulus,
                             private_number);

            uint8_t secret_bytes[RADIO_DH_FIELD_SIZE];
            uint8_t calculated_hash[RADIO_DH_HASH_SIZE];
            if (radio_export_mpz_fixed(derived_secret,
                                       secret_bytes,
                                       sizeof(secret_bytes)))
            {
                sha256_hash(secret_bytes,
                            sizeof(secret_bytes),
                            calculated_hash);
                matched = memcmp(calculated_hash,
                                 &message[RADIO_DH_FIELD_SIZE],
                                 RADIO_DH_HASH_SIZE) == 0;
            }
        }
    }

    /* Always send a verdict, even a negative one: the other node needs to know
     * the exchange is over so it can stop expecting our result packet. */
    uint16_t result_command = matched
                                  ? RADIO_CMD_DH_EXCHANGE_CONFIRMED
                                  : RADIO_CMD_DH_EXCHANGE_FAILED;
    bool result_sent = route_available &&
        radio_send_dh_exchange_result(radio_device,
                                      global_address,
                                      response->source,
                                      result_route,
                                      response->path_length,
                                      first_hop_local_address,
                                      result_command,
                                      response->sequence,
                                      private_rsa_exponent,
                                      rsa_modulus);

    /* Only a confirmed AND delivered result makes the shared secret usable;
     * main() sets shared_secret_valid only when these handlers return true. */
    bool success = matched && result_sent;
    if (success)
    {
        mpz_set(shared_secret, derived_secret);
    }
    else if (!matched)
    {
        printf("DH exchange verification failed with %08lX\n",
               (unsigned long)response->source);
    }

    /* Retire the pending exchange so a new one with the same peer may start.
     * The secrets are zeroed, never left in RAM. */
    if (result_sent)
    {
        dh_pending_active = false;
        memset(dh_pending_private, 0, sizeof(dh_pending_private));
        memset(dh_pending_modulus, 0, sizeof(dh_pending_modulus));
    }

    mpz_clear(sender_public_exponent);
    mpz_clear(sender_rsa_modulus);
    mpz_clear(dh_modulus);
    mpz_clear(private_number);
    mpz_clear(peer_dh_number);
    mpz_clear(derived_secret);
    return success;
}


/* Final leg: the origin receives the verdict. It is verified like everything
 * else, then reported. Nothing is stored - the shared secret already lives in
 * main()'s shared_secret, and this only closes the conversation. */
bool Respond_To_DH_Exchange_Result(uint32_t global_address,
                                   ftp_client_t *ftp,
                                   const radio_packet_t *result)
{
    if (ftp == NULL || result == NULL ||
        (result->command != RADIO_CMD_DH_EXCHANGE_CONFIRMED &&
         result->command != RADIO_CMD_DH_EXCHANGE_FAILED) ||
        !dh_responder_pending_active ||
        result->source != dh_responder_pending_source ||
        result->destination != global_address ||
        result->sequence != dh_responder_pending_sequence ||
        result->path_length < 2 ||
        result->path_length > RADIO_MAX_ROUTE_ADDRESSES ||
        result->path[0] != result->source ||
        result->path[result->path_length - 1u] != global_address ||
        result->length != RADIO_DH_SIGNATURE_SIZE)
        return false;

    mpz_t sender_public_exponent;
    mpz_t sender_rsa_modulus;
    mpz_init(sender_public_exponent);
    mpz_init(sender_rsa_modulus);

    uint8_t signature_input[RADIO_DH_SIGNATURE_CONTEXT_SIZE];
    radio_build_dh_signature_input(result->command,
                                   result->source,
                                   global_address,
                                   result->sequence,
                                   NULL,
                                   0,
                                   signature_input);
    bool valid = radio_load_rsa_public_key(ftp,
                                           result->source,
                                           sender_public_exponent,
                                           sender_rsa_modulus) &&
                 radio_rsa_verify_sha256(signature_input,
                                         sizeof(signature_input),
                                         result->data,
                                         sender_public_exponent,
                                         sender_rsa_modulus);
    mpz_clear(sender_public_exponent);
    mpz_clear(sender_rsa_modulus);
    if (!valid)
        return false;

    if (result->command == RADIO_CMD_DH_EXCHANGE_CONFIRMED)
        printf("DH exchange confirmed with %08lX\n",
               (unsigned long)result->source);
    else
        printf("DH exchange failed with %08lX\n",
               (unsigned long)result->source);

    dh_responder_pending_active = false;
    return true;
}


    /* These three are used by Handle_Radio_Packet below, which is defined
     * before them in this file. */
bool Respond_To_Local_Address(uint32_t global_address,
                              e32_t *radio,
                              ftp_client_t *ftp,
                              const radio_packet_t *request);

bool Respond_To_Local_Address_Removal(uint32_t global_address,
                                      e32_t *radio,
                                      ftp_client_t *ftp,
                                      const radio_packet_t *request);

bool Respond_To_Node_Removal(uint32_t global_address,
                             e32_t *radio,
                             ftp_client_t *ftp,
                             const radio_packet_t *request);

                              
/* A second dispatcher, kept inside radio.c. mesh_network_v1.c has its own
 * switch and does not call this one, so it currently serves as documentation
 * of the command-to-handler mapping. */
bool Handle_Radio_Packet(uint32_t global_address,
                         e32_t *radio,
                         ftp_client_t *ftp,
                         const radio_packet_t *packet,
                         mpz_t private_rsa_exponent,
                         mpz_t rsa_modulus,
                         mpz_t shared_secret)
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

    if (packet->command == RADIO_CMD_REMOVE_LOCAL_ADDRESS)
    {
        return Respond_To_Local_Address_Removal(global_address,
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

    if (packet->command == RADIO_CMD_RELAY_REMOVE_NODE)
    {
        return Respond_To_Node_Removal(global_address,
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

    if (packet->command == RADIO_CMD_SEND_ENCRYPTION_REQUEST)
    {
        return Respond_To_DH_Exchange_Request(global_address,
                                              radio,
                                              ftp,
                                              packet,
                                              private_rsa_exponent,
                                              rsa_modulus,
                                              shared_secret);
    }

    if (packet->command == RADIO_CMD_SEND_ENCRYPTION_RESPONSE)
    {
        return Respond_To_DH_Exchange_Response(global_address,
                                               radio,
                                               ftp,
                                               packet,
                                               private_rsa_exponent,
                                               rsa_modulus,
                                               shared_secret);
    }

    if (packet->command == RADIO_CMD_DH_EXCHANGE_CONFIRMED ||
        packet->command == RADIO_CMD_DH_EXCHANGE_FAILED)
    {
        return Respond_To_DH_Exchange_Result(global_address, ftp, packet);
    }

    return false;
}


/* ==========================================================================
 * BOOT-TIME JOIN SEQUENCE
 *
 * join_mesh_as_new_node() in main() calls these in order:
 *   Find_Neighbors -> Generate_Local_Adress -> Send_Local_Adress_To_Neighbors
 *   -> Relay_New_Node -> Request_Global_RSA_Keys -> Request_Global_Connections
 * Each step depends on the file written by the previous one, which is why the
 * order below is fixed.
 * ==========================================================================*/

/* Step 1: broadcast a PING to every radio in range and collect the PONGs.
 * A PONG carries the responder's 16-bit address, which is the only way a
 * node can ever learn how to address a neighbour it has never met. */
void Find_Neighbors(uint32_t Global_Adress, e32_t *radio, ftp_client_t *ftp) {

    radio_packet_t ping_packet;

    /* The PING is a broadcast on both layers: 0xFFFFFFFF globally (any node)
     * and 0xFFFF on the radio (every device in range). Sequence 1 is fixed so
     * the replies can be recognised below. */
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
    /* Fixed listening window rather than a fixed count: we cannot know how
     * many nodes are in range, so we simply collect whatever answers. */
    while (!time_reached(timeout))
    {
        radio_packet_t response;

        if (radio_receive_packet(radio, &response))
        {
            if (response.command == RADIO_CMD_PONG)
            {
                /* Only accept our own PING's replies: the destination must be
                 * us and the sequence must be the one we sent. Anything else
                 * belongs to another node's conversation. */
                if (response.destination == Global_Adress &&
                    response.sequence == 1)
                {
                    printf(
                        "PONG received from %08lX\n",
                        (unsigned long)response.source
                    );

                    /* A PONG with a short payload carries no local address:
                     * reading data[0]/data[1] would be out of range, so such
                     * a reply is ignored rather than recorded as garbage. */
                    if (response.length >= 2 && neighbor_count < 8)
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
    
    /* Build the text file in memory. Renamed from the original local
     * 'neighbor_file' so it no longer shadows the file-scope buffer of the
     * same name; the two are unrelated. The format here must match exactly
     * the one radio_parse_neighbor_file() accepts. */
    char neighbor_text[256];
    size_t offset = 0;



    /* Write each neighbor */
    for (uint8_t i = 0; i < neighbor_count; i++)
    {
        /* snprintf returns the length it WOULD have written, so the >= check
         * is the buffer-full test and offset is advanced by the real length. */
        int len = snprintf(
            neighbor_text + offset,
            sizeof(neighbor_text) - offset,
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

        if (offset >= sizeof(neighbor_text))
        {
            printf("Neighbor file buffer full\n");
            return;
        }
    }


    /* Upload the complete file */
    if (!ftp_upload(
            ftp,
            "local_neighbors.txt",
            (uint8_t *)neighbor_text,
            offset))
    {
        printf("FTP upload failed\n");
        ftp_disconnect(ftp);
        return;
    }

    printf("FTP upload ok\n");
};


/* Receiving side of the PING, called from main()'s dispatcher. Answering is
 * the only way a node that has already joined can be discovered by a newcomer,
 * so this keeps the physical graph symmetric over time. */
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

    /* Refuse to answer when our own list is already full: adding this node
     * would be impossible to record, so a half-tracked neighbour is worse
     * than an undiscovered one. */
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

    /* The payload is our 16-bit radio address, big-endian, 2 bytes. */
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


/* Step 3 of the join sequence: publish the local address we chose. Without
 * this the neighbours could not address us with their E32 radios. */
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

/* Used when a node is being removed from the mesh: tell every neighbour to
 * drop us from their local_neighbors.txt. */
bool Remove_Local_Address_From_Neighbors(uint32_t global_address,
                                         e32_t *radio,
                                         ftp_client_t *ftp)
{
    if (global_address == 0 || radio == NULL || ftp == NULL)
        return false;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow)
    {
        printf("FTP local_neighbors.txt download failed\n");
        return false;
    }

    if (neighbor_file_length == 0)
        return true;

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
        radio_packet_t request;
        if (!radio_packet_create(&request,
                                 global_address,
                                 neighbors[i].global_address,
                                 RADIO_CMD_REMOVE_LOCAL_ADDRESS,
                                 RADIO_FLAG_ACK_REQUEST,
                                 ++sequence) ||
            !radio_send_packet(radio,
                               &request,
                               neighbors[i].local_address,
                               0))
        {
            printf("Failed to request neighbor removal from %08lX\n",
                   (unsigned long)neighbors[i].global_address);
            sent = false;
        }
    }

    return sent;
}

/* Receiving side of RADIO_CMD_SEND_LOCAL_ADRESS.
 *
 * Two cases: the neighbour is already in our list (update its address) or it
 * is new (append it). Both end in the same rewrite-and-upload block, reached
 * with a goto so the upload code exists exactly once. */
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

    /* Look for the neighbour we were told about. */
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

/* Rewrite the whole list back to text and upload it. The file is always
 * replaced, never patched: at 8 entries that is cheaper and safer than
 * trying to splice bytes. */
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

/* Receiving side of RADIO_CMD_REMOVE_LOCAL_ADDRESS: drop one row from our
 * neighbour file. An empty file is legal, so 'nothing to remove' is success. */
bool Respond_To_Local_Address_Removal(uint32_t global_address,
                                      e32_t *radio,
                                      ftp_client_t *ftp,
                                      const radio_packet_t *request)
{
    if (global_address == 0 || radio == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_REMOVE_LOCAL_ADDRESS ||
        request->source == 0 || request->destination != global_address ||
        request->length != 0)
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
    if (neighbor_file_length > 0 &&
        !radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    /* Compact the array in place, keeping everything that is not the node
     * being removed. Same idiom as the graph row compaction. */
    uint8_t retained_count = 0;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address != request->source)
            neighbors[retained_count++] = neighbors[i];
    }

    /* Nothing changed: do not touch the file on the server. */
    if (retained_count == neighbor_count)
        return true;

    uint8_t output[sizeof(neighbor_file)];
    size_t output_length = 0;
    for (uint8_t i = 0; i < retained_count; ++i)
    {
        int written = snprintf((char *)&output[output_length],
                               sizeof(output) - output_length,
                               "%08lX,%u\n",
                               (unsigned long)neighbors[i].global_address,
                               (unsigned int)neighbors[i].local_address);
        if (written < 0 ||
            (size_t)written >= sizeof(output) - output_length)
            return false;

        output_length += (size_t)written;
    }

    return ftp_upload(ftp,
                      "local_neighbors.txt",
                      output,
                      (uint32_t)output_length);
}


/* The most involved responder: one packet causes three separate edits -
 * the graph, our own neighbour file, and a relay to our neighbours. Doing all
 * three here is what makes a departure visible everywhere in the mesh, not
 * just to the node that heard about it. */
bool Respond_To_Node_Removal(uint32_t global_address,
                             e32_t *radio,
                             ftp_client_t *ftp,
                             const radio_packet_t *request)
{
    if (global_address == 0 || radio == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_RELAY_REMOVE_NODE ||
        request->source == 0 || request->source == global_address ||
        request->destination != global_address || request->length != 0)
        return false;

    uint32_t removed_address = request->source;
    /* Termination of the wave, same guard as in Relay_Node_Removal. */
    if (radio_node_removal_seen(removed_address))
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
    if (neighbor_file_length > 0 &&
        !radio_parse_neighbor_file(neighbors, &neighbor_count))
    {
        printf("No valid neighbors in local_neighbors.txt\n");
        return false;
    }

    radio_mark_node_removal_seen(removed_address);

    /* Relay to everyone except the node that is gone and except ourselves. */
    bool sent = true;
    for (uint8_t i = 0; i < neighbor_count; ++i)
    {
        if (neighbors[i].global_address == removed_address ||
            neighbors[i].global_address == global_address)
            continue;

        radio_packet_t relay;
        if (!radio_packet_create(&relay,
                                 removed_address,
                                 neighbors[i].global_address,
                                 RADIO_CMD_RELAY_REMOVE_NODE,
                                 RADIO_FLAG_ACK_REQUEST,
                                 request->sequence) ||
            !radio_send_packet(radio,
                               &relay,
                               neighbors[i].local_address,
                               0))
        {
            printf("Failed to relay node removal to %08lX\n",
                   (unsigned long)neighbors[i].global_address);
            sent = false;
        }
    }

    /* Reuse the same packet with a different command to clean our own
     * neighbour file: the payload is empty in both cases, so only the
     * command has to change. */
    radio_packet_t local_removal = *request;
    local_removal.command = RADIO_CMD_REMOVE_LOCAL_ADDRESS;
    bool local_removed = Respond_To_Local_Address_Removal(global_address,
                                                          radio,
                                                          ftp,
                                                          &local_removal);

    if (!radio_download_global_connections(ftp))
    {
        printf("FTP %s download failed or has an invalid format\n",
               RADIO_GLOBAL_CONNECTIONS_FILE);
        return false;
    }

    /* And finally delete the node from our copy of the global graph. */
    bool ledger_changed = false;
    radio_remove_global_connection_node(removed_address, &ledger_changed);
    if (ledger_changed &&
        !ftp_upload(ftp,
                    RADIO_GLOBAL_CONNECTIONS_FILE,
                    global_connections_file,
                    (uint32_t)global_connections_file_length))
    {
        printf("FTP upload of %s failed\n", RADIO_GLOBAL_CONNECTIONS_FILE);
        ftp_disconnect(ftp);
        return false;
    }

    return sent && local_removed;
}

/* The single E32 device instance, declared 'extern e32_t radio' in radio.h so
 * that handlers can take &radio. main() initialises it in second_core_code().
 * It sits at the end of the file so it is defined after every function that
 * refers to it. */
e32_t radio;

/* Leg 1 of the DH exchange, run by the node that wants a secret with a
 * distant node. It is the only place in the program where a fresh DH group is
 * created, and the private value is parked in dh_pending_* until the reply
 * arrives - that is the entire state machine for the exchange. */
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
        dh_pending_active ||
        mpz_sgn(private_rsa_exponent) <= 0 ||
        mpz_sizeinbase(rsa_modulus, 2) != RADIO_RSA_PUBLIC_MODULUS_BITS)
        return false;

    mpz_t private_number;
    mpz_t sending_number;
    mpz_t modulus;
    mpz_t random_number;
    mpz_t seed;
    mpz_t generator;

    mpz_init(private_number);
    mpz_init(sending_number);
    mpz_init(modulus);
    mpz_init(random_number);
    mpz_init(seed);
    mpz_init(generator);

    bool success = false;
    uint8_t message[RADIO_DH_MESSAGE_SIZE];
    uint8_t signed_request[RADIO_DH_SIGNED_REQUEST_SIZE];

    /* Build a safe 1023-bit prime p. Forcing the top and bottom bits keeps
     * the candidate in the right range and odd, so generate_random_prime_number
     * has less to search. The loop repeats until the result really is 1023
     * bits, because rounding up can cross a bit boundary. */
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
    } while (mpz_sizeinbase(modulus, 2) != RADIO_DH_MODULUS_BITS);

    mpz_set_ui(generator, 2);
    DH_Generate_Private_Number(private_number);
    DH_Generate_Sending_Number(sending_number,
                               generator,
                               modulus,
                               private_number);

    if (mpz_cmp_ui(sending_number, 1) <= 0 ||
        mpz_cmp(sending_number, modulus) >= 0 ||
        !radio_export_mpz_fixed(modulus, message, RADIO_DH_FIELD_SIZE) ||
        !radio_export_mpz_fixed(sending_number,
                                &message[RADIO_DH_FIELD_SIZE],
                                RADIO_DH_FIELD_SIZE) ||
        !radio_export_mpz_fixed(private_number,
                                dh_pending_private,
                                sizeof(dh_pending_private)) ||
        !radio_export_mpz_fixed(modulus,
                                dh_pending_modulus,
                                sizeof(dh_pending_modulus)))
        goto cleanup;

    static uint16_t sequence;
    ++sequence;
    uint8_t signature_input[RADIO_DH_SIGNATURE_INPUT_MAX_SIZE];
    radio_build_dh_signature_input(RADIO_CMD_SEND_ENCRYPTION_REQUEST,
                                   personal_global_address,
                                   target_global_address,
                                   sequence,
                                   message,
                                   sizeof(message),
                                   signature_input);
    if (!radio_rsa_sign_sha256(signature_input,
                               RADIO_DH_SIGNATURE_CONTEXT_SIZE +
                                   sizeof(message),
                               private_rsa_exponent,
                               rsa_modulus,
                               &signed_request[RADIO_DH_MESSAGE_SIZE]))
        goto cleanup;

    memcpy(signed_request, message, sizeof(message));

    success = radio_send_dh_signed_message(&radio,
                                           personal_global_address,
                                           target_global_address,
                                           route,
                                           *route_length,
                                           first_hop_local_address,
                                           RADIO_CMD_SEND_ENCRYPTION_REQUEST,
                                           sequence,
                                           message,
                                           sizeof(message),
                                           &signed_request[RADIO_DH_MESSAGE_SIZE]);
    if (success)
    {
        dh_pending_source = personal_global_address;
        dh_pending_destination = target_global_address;
        dh_pending_sequence = sequence;
        dh_pending_active = true;
    }

cleanup:
    mpz_clear(private_number);
    mpz_clear(sending_number);
    mpz_clear(modulus);
    mpz_clear(random_number);
    mpz_clear(seed);
    mpz_clear(generator);
    return success;
}

/* ==========================================================================
 * THE TWO MESSAGE TYPES THE CONTROL PANEL CAN SEND
 *
 * A private letter and a public discussion post are the only two things the
 * site can put into the mesh. They differ in exactly one respect - one is
 * secret and goes to one node, the other is public and goes to all of them -
 * and they share everything else: the fragmenting, the acknowledgement
 * requirement, and the "append a line to a text file" storage idiom.
 *
 * Every message on the wire starts with the same 4-byte header
 *     [total length of the reassembled payload][offset of this piece]
 * so a receiver can tell a complete message from a partial one, and the
 * sequence number ties all pieces of one message together.
 * ==========================================================================*/

#define RADIO_MESSAGE_FRAGMENT_HEADER_SIZE 4u
#define RADIO_MESSAGE_FRAGMENT_DATA_SIZE \
    (RADIO_MAX_DATA - RADIO_MESSAGE_FRAGMENT_HEADER_SIZE)

/* A reassembled message is capped: it has to fit the buffers below, and a
 * longer message is refused rather than silently truncated. */
#define RADIO_MESSAGE_MAX 1024u
#define RADIO_PRIVATE_NONCE_SIZE 12u
#define RADIO_PRIVATE_TAG_SIZE   16u
#define RADIO_PRIVATE_OVERHEAD   (RADIO_PRIVATE_NONCE_SIZE + RADIO_PRIVATE_TAG_SIZE)
#define RADIO_PRIVATE_MESSAGE_MAX (RADIO_MESSAGE_MAX - RADIO_PRIVATE_OVERHEAD)

#define RADIO_MESSAGE_RESPONSE_TIMEOUT_MS 8000

/* The two text files the messages end up in. The names are the ones the
 * hosted pages already fetch, so the site and the protocol agree. */
#define RADIO_PRIVATE_MESSAGES_FILE "private_mesagges.txt"
#define RADIO_DISCUSSION_FILE      "current_discussion.txt"

#define RADIO_TEXT_FILE_MAX_SIZE 2048
#define RADIO_PUBLIC_MESSAGE_CACHE_SIZE 32

/* --- state ---------------------------------------------------------------
 * One reassembly buffer per message type: a private letter and a public post
 * can interleave on the wire, so they must not share one. Each is keyed by
 * (source, sequence) exactly like the DH reassembly above. */
static uint8_t radio_private_reassembly[RADIO_MESSAGE_MAX];
static size_t radio_private_reassembly_length;
static uint32_t radio_private_reassembly_source;
static uint16_t radio_private_reassembly_sequence;
static bool radio_private_reassembly_active;

static uint8_t radio_public_reassembly[RADIO_MESSAGE_MAX];
static size_t radio_public_reassembly_length;
static uint32_t radio_public_reassembly_source;
static uint16_t radio_public_reassembly_sequence;
static bool radio_public_reassembly_active;

/* A public post must reach every node exactly once. This ring remembers the
 * (author, sequence) pairs already recorded here, which is the termination
 * condition of the broadcast wave. */
typedef struct
{
    uint32_t author;
    uint16_t sequence;
} radio_public_message_seen_t;

static radio_public_message_seen_t radio_public_message_seen[RADIO_PUBLIC_MESSAGE_CACHE_SIZE];
static size_t radio_public_message_seen_next;

/* Shared scratch: the payload being sent, and the text file being edited.
 * Never used by two operations at a time, so one buffer each is enough. */
static uint8_t radio_message_payload[RADIO_MESSAGE_MAX];

static char radio_text_file[RADIO_TEXT_FILE_MAX_SIZE + 1];
static size_t radio_text_file_length;
static bool radio_text_file_overflow;

/* One counter for every message this node sends. A different sequence per
 * message is what makes an acknowledgement unambiguous and what lets two
 * messages in flight at once be told apart. */
static uint16_t radio_message_sequence;

/* The helpers below are written after the senders that use them, so they are
 * declared here first. */
static bool radio_append_text_line(ftp_client_t *ftp,
                                   const char *file_name,
                                   const char *line);

static bool radio_send_fragmented_message(e32_t *device,
                                          uint32_t source,
                                          uint32_t destination,
                                          const uint32_t *route,
                                          uint8_t route_length,
                                          uint16_t first_hop_local_address,
                                          uint16_t command,
                                          uint16_t sequence,
                                          uint8_t flags,
                                          const uint8_t *payload,
                                          size_t payload_length);

static bool radio_read_message_fragment(const radio_packet_t *packet,
                                        uint32_t *total_length,
                                        uint32_t *offset,
                                        const uint8_t **piece,
                                        uint32_t *piece_length);

/* -------------------------------------------------------------------------
 * Send a private letter.
 *
 * The key is derived, never transmitted: SHA-256 of the shared secret. Both
 * ends can compute it because both completed the same Diffie-Hellman
 * exchange, so nothing secret has to cross the wire except the ciphertext -
 * and the tag, which is what makes a corrupted or misrouted letter detectable
 * rather than silently readable garbage.
 * ------------------------------------------------------------------------- */
bool Send_Private_Message(uint32_t global_address,
                          uint32_t target_global_address,
                          const char *plain_text,
                          mpz_t shared_secret,
                          e32_t *radio,
                          ftp_client_t *ftp)
{
    if (radio == NULL || ftp == NULL || plain_text == NULL ||
        target_global_address == 0 || target_global_address == RADIO_BROADCAST_ADDRESS)
        return false;

    if (mpz_sgn(shared_secret) <= 0)
        return false;

    size_t text_length = strlen(plain_text);

    /* Refuse an empty or over-long letter rather than sending something the
     * receiving end could not reconstruct. */
    if (text_length == 0 || text_length > RADIO_PRIVATE_MESSAGE_MAX)
        return false;

    /* Derive the AEAD key from the shared secret. */
    uint8_t secret_bytes[RADIO_DH_FIELD_SIZE];
    uint8_t key[32];
    if (!radio_export_mpz_fixed(shared_secret, secret_bytes, sizeof(secret_bytes)))
        return false;

    sha256_hash(secret_bytes, sizeof(secret_bytes), key);

    /* A fresh random nonce per letter. It travels in the clear with the
     * ciphertext; what must stay secret is the key, not the nonce. */
    uint8_t nonce[RADIO_PRIVATE_NONCE_SIZE];
    for (size_t i = 0; i < RADIO_PRIVATE_NONCE_SIZE; i += 4u)
    {
        uint32_t value = get_rand_32();
        memcpy(&nonce[i], &value, sizeof(value));
    }

    /* Encrypt into the shared payload buffer: nonce || ciphertext || tag. */
    uint8_t *ciphertext = &radio_message_payload[RADIO_PRIVATE_NONCE_SIZE];
    uint8_t *tag = &radio_message_payload[RADIO_PRIVATE_NONCE_SIZE + text_length];

    if (chacha20poly1305_encrypt(key,
                                 nonce,
                                 (const uint8_t *)plain_text,
                                 text_length,
                                 ciphertext,
                                 tag) != 0)
        return false;

    memcpy(radio_message_payload, nonce, RADIO_PRIVATE_NONCE_SIZE);

    size_t payload_length = RADIO_PRIVATE_OVERHEAD + text_length;

    /* Route to the addressee. A private letter must not be broadcast: an
     * intermediate node cannot open it, so it only ever forwards it. */
    uint32_t route[RADIO_MAX_ROUTE_ADDRESSES];
    uint8_t route_length = 0;
    if (!Find_Shortest_Global_Route(global_address,
                                    target_global_address,
                                    ftp,
                                    route,
                                    &route_length))
        return false;

    if (route_length < 2 || route[0] != global_address ||
        route[route_length - 1u] != target_global_address)
        return false;

    /* The first hop has to be a neighbour we can actually dial. */
    uint16_t first_hop_local_address = 0;
    if (!radio_find_neighbor_local_address(ftp, route[1], &first_hop_local_address))
        return false;

    /* One sequence number for the whole letter: every fragment carries it, and
     * the acknowledgement comes back with it. */
    uint16_t sequence = ++radio_message_sequence;

    if (!radio_send_fragmented_message(radio,
                                       global_address,
                                       target_global_address,
                                       route,
                                       route_length,
                                       first_hop_local_address,
                                       RADIO_CMD_PRIVATE_MESSAGE,
                                       sequence,
                                       RADIO_FLAG_ENCRYPTED,
                                       radio_message_payload,
                                       payload_length))
        return false;

    /* Wait for the addressee to acknowledge. Nothing is re-sent here: a
     * letter that nobody confirmed is reported as failed, so the caller can
     * decide whether to try again. */
    absolute_time_t timeout = make_timeout_time_ms(RADIO_MESSAGE_RESPONSE_TIMEOUT_MS);

    while (!time_reached(timeout))
    {
        radio_packet_t response;

        if (radio_receive_packet(radio, &response) &&
            response.command == RADIO_CMD_ACK &&
            (response.flags & RADIO_FLAG_ACK) &&
            response.sequence == sequence &&
            response.source == target_global_address &&
            response.destination == global_address)
            return true;

        sleep_ms(1);
    }

    return false;
}

/* -------------------------------------------------------------------------
 * Answer a private letter.
 *
 * Two very different jobs share this handler, and the packet itself says
 * which: if we are the addressee we open it, otherwise we are only a courier
 * and must pass it on without trying to read it.
 * ------------------------------------------------------------------------- */
bool Respond_To_Private_Message(uint32_t global_address,
                                e32_t *radio,
                                ftp_client_t *ftp,
                                const radio_packet_t *request,
                                mpz_t shared_secret)
{
    if (radio == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_PRIVATE_MESSAGE ||
        request->source == 0 ||
        (request->flags & RADIO_FLAG_FRAGMENT) == 0)
        return false;

    /* --- we are only a courier: pass the fragment on, unread ------------
     * The letter is not ours to open, so nothing is decoded and nothing is
     * recorded. The fragment is forwarded byte for byte, keeping its source,
     * destination, sequence and flags, so the addressee still sees the
     * original author and the author can still match the acknowledgement. */
    if (request->destination != global_address)
    {
        uint8_t hop = RADIO_MAX_ROUTE_ADDRESSES;

        for (uint8_t i = 0; i + 1u < request->path_length; ++i)
        {
            if (request->path[i] == global_address)
            {
                hop = (uint8_t)(i + 1u);
                break;
            }
        }

        /* The route does not go through us: this packet took a different way
         * and we must not put it on one of its own. */
        if (hop == RADIO_MAX_ROUTE_ADDRESSES)
            return false;

        uint16_t next_hop_local_address = 0;
        if (!radio_find_neighbor_local_address(ftp,
                                               request->path[hop],
                                               &next_hop_local_address))
            return false;

        radio_packet_t forwarded = *request;
        return radio_send_packet(radio, &forwarded, next_hop_local_address, 0);
    }

    uint32_t total_length = 0;
    uint32_t offset = 0;
    const uint8_t *piece = NULL;
    uint32_t piece_length = 0;

    if (!radio_read_message_fragment(request, &total_length, &offset, &piece, &piece_length))
        return false;

    /* Start a new reassembly only at the first piece; a letter whose start
     * we missed is dropped whole, never half-recorded. */
    if (!radio_private_reassembly_active ||
        radio_private_reassembly_source != request->source ||
        radio_private_reassembly_sequence != request->sequence)
    {
        if (offset != 0)
            return false;

        radio_private_reassembly_source = request->source;
        radio_private_reassembly_sequence = request->sequence;
        radio_private_reassembly_length = 0;
        radio_private_reassembly_active = true;
    }

    /* Pieces must arrive in order; a gap would silently corrupt the letter. */
    if (offset != radio_private_reassembly_length)
        return false;

    if (radio_private_reassembly_length + piece_length > RADIO_MESSAGE_MAX)
    {
        radio_private_reassembly_active = false;
        return false;
    }

    memcpy(&radio_private_reassembly[radio_private_reassembly_length],
           piece,
           piece_length);
    radio_private_reassembly_length += piece_length;

    /* Still incomplete: accepted, but nothing to record or acknowledge yet. */
    if (radio_private_reassembly_length < total_length)
        return true;

    radio_private_reassembly_active = false;

    /* --- we are the addressee: open it, record it, acknowledge it -------- */
    if (radio_private_reassembly_length < RADIO_PRIVATE_OVERHEAD ||
        (request->flags & RADIO_FLAG_ENCRYPTED) == 0)
        return false;

    if (mpz_sgn(shared_secret) <= 0)
        return false;

    uint8_t key[32];
    uint8_t secret_bytes[RADIO_DH_FIELD_SIZE];
    if (!radio_export_mpz_fixed(shared_secret, secret_bytes, sizeof(secret_bytes)))
        return false;

    sha256_hash(secret_bytes, sizeof(secret_bytes), key);

    const uint8_t *nonce = radio_private_reassembly;
    const uint8_t *ciphertext = &radio_private_reassembly[RADIO_PRIVATE_NONCE_SIZE];
    size_t ciphertext_length = radio_private_reassembly_length - RADIO_PRIVATE_OVERHEAD;
    const uint8_t *tag = &radio_private_reassembly[RADIO_PRIVATE_NONCE_SIZE + ciphertext_length];

    static uint8_t opened[RADIO_PRIVATE_MESSAGE_MAX];

    /* A wrong key, a tampered byte or a letter meant for someone else all
     * end here: the tag will not match, and nothing is recorded. */
    if (chacha20poly1305_decrypt(key,
                                 nonce,
                                 ciphertext,
                                 ciphertext_length,
                                 tag,
                                 opened) != 0)
        return false;

    opened[ciphertext_length] = '\0';

    char line[RADIO_MESSAGE_MAX + 32];
    if (snprintf(line, sizeof(line), "%08lX: %s",
                 (unsigned long)request->source, (char *)opened) >= (int)sizeof(line))
        return false;

    if (!radio_append_text_line(ftp, RADIO_PRIVATE_MESSAGES_FILE, line))
        return false;

    /* Acknowledge with the letter's own sequence number, so the author can
     * tell this exact letter from any other it may have sent. */
    radio_packet_t acknowledgement;
    if (!radio_packet_create(&acknowledgement,
                             global_address,
                             request->source,
                             RADIO_CMD_ACK,
                             RADIO_FLAG_ACK,
                             request->sequence))
        return false;

    /* Answer through the neighbour that is the author, not by broadcasting:
     * only that one node is waiting for this acknowledgement. */
    uint16_t back_to_author = 0xFFFF;
    radio_neighbor_t neighbours[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbour_count = 0;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) &&
        !neighbor_file_overflow)
        radio_parse_neighbor_file(neighbours, &neighbour_count);

    for (uint8_t i = 0; i < neighbour_count; ++i)
    {
        if (neighbours[i].global_address == request->source)
        {
            back_to_author = neighbours[i].local_address;
            break;
        }
    }

    return radio_send_packet(radio, &acknowledgement, back_to_author, 0);
}

/* -------------------------------------------------------------------------
 * Post to the whole mesh.
 *
 * There is no broadcast that reaches further than one radio range, so "send
 * to everyone" means "hand it to everyone you know, and let everyone do the
 * same". The record is written here before it is sent, so the author keeps
 * its own post without waiting for anyone else.
 * ------------------------------------------------------------------------- */
bool Send_Public_Message(const char *plain_text,
                        uint32_t global_address,
                        e32_t *radio,
                        ftp_client_t *ftp)
{
    if (radio == NULL || ftp == NULL || plain_text == NULL ||
        global_address == 0 || global_address == RADIO_BROADCAST_ADDRESS)
        return false;

    size_t text_length = strlen(plain_text);

    if (text_length == 0 || text_length > RADIO_MESSAGE_MAX)
        return false;

    /* Keep our own post first, so the discussion is complete even if no
     * neighbour ever acknowledges. */
    char line[RADIO_MESSAGE_MAX + 32];
    if (snprintf(line, sizeof(line), "%08lX: %s",
                 (unsigned long)global_address, plain_text) >= (int)sizeof(line))
        return false;

    if (!radio_append_text_line(ftp, RADIO_DISCUSSION_FILE, line))
        return false;

    /* Who to hand it to. */
    radio_neighbor_t neighbours[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbour_count = 0;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (!ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) ||
        neighbor_file_overflow ||
        !radio_parse_neighbor_file(neighbours, &neighbour_count))
        return false;

    memcpy(radio_message_payload, plain_text, text_length);

    uint16_t sequence = ++radio_message_sequence;
    uint8_t handed_to = 0;

    /* One two-hop route per neighbour: us, then that neighbour. The message
     * is sent to every neighbour under the SAME sequence number, which is
     * what lets the acknowledgements below be counted against one post. */
    for (uint8_t i = 0; i < neighbour_count; ++i)
    {
        if (neighbours[i].global_address == global_address)
            continue;

        uint32_t route[2] = { global_address, neighbours[i].global_address };

        if (!radio_send_fragmented_message(radio,
                                           global_address,
                                           neighbours[i].global_address,
                                           route,
                                           2,
                                           neighbours[i].local_address,
                                           RADIO_CMD_PUBLIC_MESSAGE,
                                           sequence,
                                           0,
                                           radio_message_payload,
                                           text_length))
            return false;

        ++handed_to;
    }

    if (handed_to == 0)
        return true; /* we are the only node that knows about this post */

    /* Count acknowledgements. Every neighbour must answer for the post to be
     * called complete; a silent one means the data did not make the trip. */
    uint8_t acknowledged = 0;
    uint32_t acknowledged_from[RADIO_NEIGHBOR_COUNT_MAX] = {0};

    absolute_time_t timeout = make_timeout_time_ms(RADIO_MESSAGE_RESPONSE_TIMEOUT_MS);

    while (!time_reached(timeout) && acknowledged < handed_to)
    {
        radio_packet_t response;

        if (radio_receive_packet(radio, &response) &&
            response.command == RADIO_CMD_ACK &&
            (response.flags & RADIO_FLAG_ACK) &&
            response.sequence == sequence &&
            response.destination == global_address)
        {
            /* Count each neighbour once, however many acknowledgements it
             * happens to send. */
            bool already_counted = false;
            for (uint8_t i = 0; i < acknowledged; ++i)
            {
                if (acknowledged_from[i] == response.source)
                {
                    already_counted = true;
                    break;
                }
            }

            if (!already_counted && acknowledged < RADIO_NEIGHBOR_COUNT_MAX)
            {
                acknowledged_from[acknowledged++] = response.source;
            }
        }

        sleep_ms(1);
    }

    return acknowledged >= handed_to;
}

/* --- storage: "append one line to a text file on the server" -------------
 * Both message handlers need this, and it is the same three steps as every
 * other ledger edit in this file: download, extend, upload. A missing file is
 * not an error - it just means nothing has been recorded yet. */
static void radio_text_file_cb(uint8_t *data, uint16_t length)
{
    size_t available = sizeof(radio_text_file) - radio_text_file_length - 1;

    if (length > available)
    {
        length = (uint16_t)available;
        radio_text_file_overflow = true;
        return;
    }

    memcpy(&radio_text_file[radio_text_file_length], data, length);
    radio_text_file_length += length;
    radio_text_file[radio_text_file_length] = '\0';
}

/* line must not contain a newline: the files are line-based, and one record
 * per line is what the hosted pages parse. */
static bool radio_append_text_line(ftp_client_t *ftp,
                                   const char *file_name,
                                   const char *line)
{
    if (ftp == NULL || file_name == NULL || line == NULL || line[0] == '\0')
        return false;

    if (strchr(line, '\n') != NULL || strchr(line, '\r') != NULL)
        return false;

    radio_text_file_length = 0;
    radio_text_file_overflow = false;
    radio_text_file[0] = '\0';

    /* A failed download means an empty file, which is legitimate here. */
    (void)ftp_download(ftp, file_name, radio_text_file_cb);

    if (radio_text_file_overflow)
        return false;

    size_t line_length = strlen(line);

    /* Refuse rather than overflow: a half-written line in the ledger would
     * corrupt every later read of the file. */
    if (radio_text_file_length + line_length + 2u > sizeof(radio_text_file) - 1u)
        return false;

    if (radio_text_file_length > 0 && radio_text_file[radio_text_file_length - 1u] != '\n')
        radio_text_file[radio_text_file_length++] = '\n';

    memcpy(&radio_text_file[radio_text_file_length], line, line_length);
    radio_text_file_length += line_length;
    radio_text_file[radio_text_file_length++] = '\n';
    radio_text_file[radio_text_file_length] = '\0';

    return ftp_upload(ftp, file_name, (uint8_t *)radio_text_file,
                      (uint32_t)radio_text_file_length);
}

/* --- fragmenting ---------------------------------------------------------
 * A message is longer than one radio frame, so it is cut into pieces that
 * carry their offset. Every piece of one message shares the same sequence
 * number, which is what lets a receiver reject interleaved traffic.
 * ------------------------------------------------------------------------- */
static bool radio_send_fragmented_message(e32_t *device,
                                          uint32_t source,
                                          uint32_t destination,
                                          const uint32_t *route,
                                          uint8_t route_length,
                                          uint16_t first_hop_local_address,
                                          uint16_t command,
                                          uint16_t sequence,
                                          uint8_t flags,
                                          const uint8_t *payload,
                                          size_t payload_length)
{
    if (device == NULL || route == NULL || payload == NULL ||
        payload_length == 0 || payload_length > RADIO_MESSAGE_MAX ||
        route_length == 0 || route_length > RADIO_MAX_ROUTE_ADDRESSES)
        return false;

    for (size_t offset = 0; offset < payload_length;)
    {
        size_t remaining = payload_length - offset;
        uint16_t piece = (uint16_t)(remaining > RADIO_MESSAGE_FRAGMENT_DATA_SIZE
                                    ? RADIO_MESSAGE_FRAGMENT_DATA_SIZE
                                    : remaining);

        uint8_t data[RADIO_MAX_DATA];
        radio_write_u16_be(data, (uint16_t)payload_length);
        radio_write_u16_be(&data[2], (uint16_t)offset);
        memcpy(&data[RADIO_MESSAGE_FRAGMENT_HEADER_SIZE],
               &payload[offset],
               piece);

        radio_packet_t packet;
        if (!radio_packet_create(&packet,
                                 source,
                                 destination,
                                 command,
                                 flags | RADIO_FLAG_FRAGMENT | RADIO_FLAG_ACK_REQUEST,
                                 sequence) ||
            !radio_packet_set_path(&packet, route, route_length) ||
            !radio_packet_set_data(&packet,
                                   data,
                                   (uint16_t)(RADIO_MESSAGE_FRAGMENT_HEADER_SIZE + piece)) ||
            !radio_send_packet(device, &packet, first_hop_local_address, 0))
            return false;

        offset += piece;
    }

    return true;
}

/* Pull one fragment out of a packet and check its header. Returns false when
 * the fragment is unusable, so the caller can simply drop the packet. */
static bool radio_read_message_fragment(const radio_packet_t *packet,
                                        uint32_t *total_length,
                                        uint32_t *offset,
                                        const uint8_t **piece,
                                        uint32_t *piece_length)
{
    if (packet == NULL || packet->length <= RADIO_MESSAGE_FRAGMENT_HEADER_SIZE)
        return false;

    *total_length = radio_read_u16_be_value(packet->data);
    *offset = radio_read_u16_be_value(&packet->data[2]);

    if (*total_length == 0 || *total_length > RADIO_MESSAGE_MAX ||
        *offset >= *total_length)
        return false;

    *piece = &packet->data[RADIO_MESSAGE_FRAGMENT_HEADER_SIZE];
    *piece_length = (uint32_t)(packet->length - RADIO_MESSAGE_FRAGMENT_HEADER_SIZE);

    return *offset + *piece_length <= *total_length;
}

/* -------------------------------------------------------------------------
 * Answer a public post.
 *
 * Every node does the same three things: record it, admit it, and pass it on.
 * The record step is guarded by the (author, sequence) cache, which is what
 * makes the wave cover the mesh exactly once instead of bouncing forever -
 * the acknowledgement is sent either way, so a node that already has the post
 * still proves to the sender that the data arrived.
 * ------------------------------------------------------------------------- */
bool Respond_To_Public_Message(uint32_t global_address,
                              e32_t *radio,
                              ftp_client_t *ftp,
                              const radio_packet_t *request)
{
    if (radio == NULL || ftp == NULL || request == NULL ||
        request->command != RADIO_CMD_PUBLIC_MESSAGE ||
        request->source == 0 ||
        request->destination != global_address ||
        (request->flags & RADIO_FLAG_FRAGMENT) == 0)
        return false;

    uint32_t total_length = 0;
    uint32_t offset = 0;
    const uint8_t *piece = NULL;
    uint32_t piece_length = 0;

    if (!radio_read_message_fragment(request, &total_length, &offset, &piece, &piece_length))
        return false;

    if (!radio_public_reassembly_active ||
        radio_public_reassembly_source != request->source ||
        radio_public_reassembly_sequence != request->sequence)
    {
        if (offset != 0)
            return false;

        radio_public_reassembly_source = request->source;
        radio_public_reassembly_sequence = request->sequence;
        radio_public_reassembly_length = 0;
        radio_public_reassembly_active = true;
    }

    if (offset != radio_public_reassembly_length)
        return false;

    if (radio_public_reassembly_length + piece_length > RADIO_MESSAGE_MAX)
    {
        radio_public_reassembly_active = false;
        return false;
    }

    memcpy(&radio_public_reassembly[radio_public_reassembly_length],
           piece,
           piece_length);
    radio_public_reassembly_length += piece_length;

    if (radio_public_reassembly_length < total_length)
        return true;

    radio_public_reassembly_active = false;

    /* Have we already recorded this exact post? */
    bool already_recorded = false;

    for (size_t i = 0; i < RADIO_PUBLIC_MESSAGE_CACHE_SIZE; ++i)
    {
        if (radio_public_message_seen[i].author == request->source &&
            radio_public_message_seen[i].sequence == request->sequence)
        {
            already_recorded = true;
            break;
        }
    }

    radio_neighbor_t neighbours[RADIO_NEIGHBOR_COUNT_MAX];
    uint8_t neighbour_count = 0;

    neighbor_file_length = 0;
    neighbor_file_overflow = false;
    if (ftp_download(ftp, "local_neighbors.txt", radio_neighbor_file_cb) &&
        !neighbor_file_overflow)
        radio_parse_neighbor_file(neighbours, &neighbour_count);

    if (!already_recorded)
    {
        char line[RADIO_MESSAGE_MAX + 32];

        if (snprintf(line, sizeof(line), "%08lX: %s",
                     (unsigned long)request->source,
                     (char *)radio_public_reassembly) >= (int)sizeof(line))
            return false;

        /* The post is only remembered once it is safely on the server: if
         * this fails we leave the cache untouched, so a later copy gets
         * another chance to be recorded. */
        if (!radio_append_text_line(ftp, RADIO_DISCUSSION_FILE, line))
            return false;

        radio_public_message_seen[radio_public_message_seen_next].author = request->source;
        radio_public_message_seen[radio_public_message_seen_next].sequence = request->sequence;
        radio_public_message_seen_next =
            (radio_public_message_seen_next + 1u) % RADIO_PUBLIC_MESSAGE_CACHE_SIZE;

        /* Pass it on. The author is skipped: it already has the post, and
         * sending it back would be the start of an endless loop. */
        for (uint8_t i = 0; i < neighbour_count; ++i)
        {
            if (neighbours[i].global_address == global_address ||
                neighbours[i].global_address == request->source)
                continue;

            uint32_t route[2] = { global_address, neighbours[i].global_address };

            if (!radio_send_fragmented_message(radio,
                                               request->source,
                                               neighbours[i].global_address,
                                               route,
                                               2,
                                               neighbours[i].local_address,
                                               RADIO_CMD_PUBLIC_MESSAGE,
                                               request->sequence,
                                               0,
                                               radio_public_reassembly,
                                               radio_public_reassembly_length))
                return false;
        }
    }

    /* Acknowledge in every case, recorded or not: the sender only wants to
     * know that the post reached this node. */
    radio_packet_t acknowledgement;
    if (!radio_packet_create(&acknowledgement,
                             global_address,
                             request->source,
                             RADIO_CMD_ACK,
                             RADIO_FLAG_ACK,
                             request->sequence))
        return false;

    uint16_t back_to_author = 0xFFFF;

    for (uint8_t i = 0; i < neighbour_count; ++i)
    {
        if (neighbours[i].global_address == request->source)
        {
            back_to_author = neighbours[i].local_address;
            break;
        }
    }

    return radio_send_packet(radio, &acknowledgement, back_to_author, 0);
}
