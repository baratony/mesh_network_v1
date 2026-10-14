/* ==========================================================================
 * radio.h -- public interface of the MESH PROTOCOL layer (radio.c)
 *
 * This is the top of the three-layer stack:
 *   ebyte_e32.h          raw radio bytes in/out (physical, 16-bit addressing)
 *   radio_packet_protocol.h   message framing + global addresses (this layer's wire)
 *   radio.h / radio.c    WHAT the messages mean: neighbour discovery, address
 *                        negotiation, the global connection graph, the RSA key
 *                        ledger and the Diffie-Hellman key exchange.
 *
 * Everything here works on three shared resources and needs all three to do
 * anything:
 *   - the E32 radio      (send/receive packets to physical neighbours)
 *   - an FTP server      (the persistent per-node ledger: local_neighbors.txt,
 *                         global_connections.bin, global_rsa_key_list)
 *   - the node's RSA key (to sign/verify what it sends and receives)
 *
 * Naming convention used throughout: functions starting with Request_/Relay_
 * SEND something on behalf of this node; functions starting with Respond_ handle
 * a packet this node just RECEIVED. That split is exactly how the mesh
 * propagates information one hop at a time.
 * ==========================================================================*/
#ifndef RADIO_H
#define RADIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ebyte_e32.h"
#include "radio_packet_protocol.h"
#include "Ethernet_FTP/ftp_client.h"
#include "Cryptographic_Functions/Cryptographic_Functions.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One row of local_neighbors.txt, i.e. one physical neighbour as this node
 * knows it: its unique 32-bit ID plus the 16-bit radio address that neighbour
 * agreed to answer to. This pair is the bridge between the two layers. */
typedef struct
{
    uint32_t global_address;
    uint16_t local_address;
} radio_neighbor_t;

/* Hard cap on how many physical neighbours a node tracks. It bounds every
 * stack array in radio.c, so raising it also raises stack usage. */
#define RADIO_NEIGHBOR_COUNT_MAX 8

/* -------------------------------------------------------------------------
 * THE LEDGER (local state kept on the FTP server)
 *
 * local_neighbors.txt is the node's private record of who is physically in
 * range. It is the first thing created at boot and is read by almost every
 * handler below, because they all need to know which 16-bit radio address to
 * use for a given 32-bit global address.
 * ------------------------------------------------------------------------- */

/* Decode the file already sitting in radio.c's download buffer. */
bool radio_parse_neighbor_file(radio_neighbor_t *neighbors,
                               uint8_t *neighbor_count);

/* Fetch the file from FTP into that buffer (callback accumulates the bytes). */
bool radio_download_neighbor_file(ftp_client_t *ftp);

/* Boot-time branch in second_core_code(): no usable neighbour list means this
 * Pico has never joined a mesh, so it must run the full join sequence. */
bool radio_is_new_node(ftp_client_t *ftp);

/* The lookup every send needs: given a target's global address, which local
 * radio address do we put in e32_send_fixed()? Also used to validate that a
 * reply really came from a neighbour we know. */
bool radio_find_neighbor_local_address(ftp_client_t *ftp,
                                       uint32_t global_address,
                                       uint16_t *local_address);

/* -------------------------------------------------------------------------
 * LOCAL ADDRESS NEGOTIATION (16-bit layer)
 *
 * The E32 radio can only address 16 bits, and two physically adjacent nodes
 * must not share one, or their packets would be swapped. So each node picks a
 * free number after asking its neighbours what they are using.
 * ------------------------------------------------------------------------- */

/* Ask every neighbour for its neighbour list, collect all local addresses in
 * use, then pick an unused random one. Returns 0 if none is free. */
uint16_t Generate_Local_Adress(uint32_t global_address,
                               e32_t *radio,
                               ftp_client_t *ftp);

/* -------------------------------------------------------------------------
 * NEIGHBOUR LIST EXCHANGE
 *
 * Used twice: once by Generate_Local_Adress to learn which radio addresses
 * are taken, and once by the PONG/keep-alive path so a node can report its
 * current neighbourhood. request = the packet we received, hence "Respond_".
 * ------------------------------------------------------------------------- */
bool Respond_To_Connections_Request(uint32_t global_address,
                                    e32_t *radio,
                                    ftp_client_t *ftp,
                                    const radio_packet_t *request);

/* -------------------------------------------------------------------------
 * THE GLOBAL CONNECTION GRAPH (global_connections.bin)
 *
 * An adjacency list of the whole mesh, replicated on every node's FTP server
 * as rows of 9 uint32: [self, neighbour, neighbour, ..., 0-padded]. No node
 * knows the whole mesh; each one merges what it hears from its neighbours and
 * republishes. These two functions move that file across a hop.
 * ------------------------------------------------------------------------- */

/* Join-sequence step: ask the OLDEST neighbour (the one that joined first,
 * so it has the most complete view) for the whole graph and upload it. */
bool Request_Global_Connections(uint32_t global_address,
                                e32_t *radio,
                                ftp_client_t *ftp);

/* The other half: this node is being asked, so it streams its own copy of
 * the file out in RADIO_MAX_DATA-sized chunks with sequence numbers. */
bool Respond_To_Global_Connections_Request(uint32_t global_address,
                                          e32_t *radio,
                                          ftp_client_t *ftp,
                                          const radio_packet_t *request);

/* -------------------------------------------------------------------------
 * THE RSA KEY LEDGER (global_rsa_key_list)
 *
 * Every node signs the packets it sends with its own RSA private key. For
 * another node to check that signature it needs the sender's public modulus,
 * which it can only get from the shared ledger. Same chunked transfer as the
 * graph, plus a CRC-32 of the whole file because a wrong key silently breaks
 * every later signature check.
 * ------------------------------------------------------------------------- */
bool Request_Global_RSA_Keys(uint32_t global_address,
                             e32_t *radio,
                             ftp_client_t *ftp,
                             const radio_packet_t *request);

/* Serving side of the ledger transfer. */
bool Respond_To_Global_RSA_Keys_Request(uint32_t global_address,
                                       e32_t *radio,
                                       ftp_client_t *ftp,
                                       const radio_packet_t *request);

/* Breadth-first search over the adjacency list above, used to build the
 * multi-hop route a Diffie-Hellman packet must follow. Returns the address
 * chain in path[] and its length; bounded by RADIO_GLOBAL_ROUTE_MAX_JUMPS. */
bool Find_Shortest_Global_Route(uint32_t source,
                                uint32_t destination,
                                ftp_client_t *ftp,
                                uint32_t *path,
                                uint8_t *path_length);

/* -------------------------------------------------------------------------
 * GRAPH PROPAGATION (how the mesh learns about changes)
 *
 * There is no central authority. When a node joins or leaves, it tells its
 * neighbours, and each neighbour relays to its own neighbours. The caches in
 * radio.c (radio_node_removal_cache) stop that wave from bouncing back and
 * forth forever.
 * ------------------------------------------------------------------------- */

/* Tell every neighbour "node X left", so they can delete its row. */
bool Relay_Node_Removal(uint32_t global_address,
                        e32_t *radio,
                        ftp_client_t *ftp);

/* Tell every neighbour "node X joined, its neighbours are A,B,C", which is
 * the only place a brand-new node can publish itself to the graph. */
bool Relay_New_Node(uint32_t global_address,
                    e32_t *radio,
                    ftp_client_t *ftp);

/* Receiving side: merge the announced node into our copy of the graph, then
 * forward the announcement onwards (but not back to the origin). */
bool Respond_To_New_Node(uint32_t global_address,
                        e32_t *radio,
                        ftp_client_t *ftp,
                        const radio_packet_t *request);

/* Publish our own 2048-bit RSA public modulus to every neighbour, so the
 * ledger can eventually contain the key of every node in the mesh. */
bool Relay_RSA_Public_Key(uint32_t global_address,
                         mpz_t public_modulo,
                         e32_t *radio,
                         ftp_client_t *ftp);

/* Receiving side: store the key if we do not have it yet, then relay it. */
bool Respond_To_RSA_Key_Relay(uint32_t global_address,
                             e32_t *radio,
                             ftp_client_t *ftp,
                             const radio_packet_t *request);

/* -------------------------------------------------------------------------
 * DIFFIE-HELLMAN KEY EXCHANGE ACROSS A MULTI-HOP ROUTE
 *
 * Purpose in the grand scheme: two nodes that are NOT physically adjacent
 * still want to exchange encrypted DATA packets. They cannot hand each other
 * a secret directly, so they run a classic DH exchange along the shortest
 * route found by Find_Shortest_Global_Route. The derived secret becomes the
 * ChaCha20-Poly1305 key used by handle_data_packet() in mesh_network_v1.c.
 *
 * Every message on this path is RSA-signed by the sender and verified with the
 * public key from the ledger above, so a packet cannot be replayed or forged.
 * The payload is bigger than one radio frame, so it is split into fragments
 * and reassembled by the state variables in radio.c.
 * ------------------------------------------------------------------------- */

/* We received the other node's g^a mod p: verify it, pick our own exponent b,
 * reply with g^b mod p and a hash of the shared secret. */
bool Respond_To_DH_Exchange_Request(uint32_t global_address,
                                    e32_t *radio_device,
                                    ftp_client_t *ftp,
                                    const radio_packet_t *request,
                                    mpz_t private_rsa_exponent,
                                    mpz_t rsa_modulus,
                                    mpz_t shared_secret);

/* We started the exchange (Create_DH_Exchange_Packet) and the other node
 * answered: recompute the shared secret with our stored b, compare its hash,
 * then send CONFIRMED or FAILED back along the same route. */
bool Respond_To_DH_Exchange_Response(uint32_t global_address,
                                     e32_t *radio_device,
                                     ftp_client_t *ftp,
                                     const radio_packet_t *response,
                                     mpz_t private_rsa_exponent,
                                     mpz_t rsa_modulus,
                                     mpz_t shared_secret);

/* Final step on the origin's side: verify and report the outcome, and clear
 * the pending-exchange state so a new one may start. */
bool Respond_To_DH_Exchange_Result(uint32_t global_address,
                                   ftp_client_t *ftp,
                                   const radio_packet_t *result);

/* --- local-address bookkeeping, receiving side --------------------------- */

/* A neighbour told us its radio address: store/update it in our file. */
bool Respond_To_Local_Address(uint32_t global_address,
                              e32_t *radio,
                              ftp_client_t *ftp,
                              const radio_packet_t *request);

/* A neighbour is leaving: drop its row from our neighbour file. */
bool Respond_To_Local_Address_Removal(uint32_t global_address,
                                      e32_t *radio,
                                      ftp_client_t *ftp,
                                      const radio_packet_t *request);

/* A node somewhere in the mesh announced it is gone: clean the graph, our
 * own neighbour file, and relay the news. */
bool Respond_To_Node_Removal(uint32_t global_address,
                             e32_t *radio,
                             ftp_client_t *ftp,
                             const radio_packet_t *request);

/* Alternative to dispatch_packet() in mesh_network_v1.c: an internal command
 * router kept in radio.c. The main program uses its own switch instead, so
 * this one is currently unused but documents the same mapping. */
bool Handle_Radio_Packet(uint32_t global_address,
                         e32_t *radio,
                         ftp_client_t *ftp,
                         const radio_packet_t *packet,
                         mpz_t private_rsa_exponent,
                         mpz_t rsa_modulus,
                         mpz_t shared_secret);

/* -------------------------------------------------------------------------
 * BOOT-TIME JOIN SEQUENCE (called only from join_mesh_as_new_node)
 * ------------------------------------------------------------------------- */

/* Step 1: broadcast a PING and record every PONG as a physical neighbour,
 * writing the result to local_neighbors.txt. */
void Find_Neighbors(uint32_t Global_Adress, e32_t *radio, ftp_client_t *ftp);

/* Receiving side of the PING: answer with our own 16-bit radio address so
 * the pinger can add us to its neighbour file. */
void Ping_Response(uint32_t Global_Adress,
                   uint16_t Local_Adress,
                   e32_t *radio,
                   ftp_client_t *ftp,
                   radio_packet_t sender_packet);

/* Step 3 of the join sequence: publish the local address we just chose to
 * every neighbour, so they can address us with the E32. */
bool Send_Local_Adress_To_Neighbors(uint32_t global_address,
                                    uint16_t local_address,
                                    e32_t *radio,
                                    ftp_client_t *ftp);

/* Counterpart used when a node is being removed from the mesh. */
bool Remove_Local_Address_From_Neighbors(uint32_t global_address,
                                         e32_t *radio,
                                         ftp_client_t *ftp);

/* Step 1 of a DH exchange, run by the node that WANTS a secret with a
 * distant node: generate p and g^a mod p, sign it, and fragment it onto the
 * route. The private value is parked in dh_pending_* until the reply arrives. */
bool Create_DH_Exchange_Packet(uint32_t target_global_address,
                               uint32_t personal_global_address,
                               const uint32_t *route,
                               uint8_t *route_length,
                               uint16_t first_hop_local_address,
                               mpz_t private_rsa_exponent,
                               mpz_t rsa_modulus);

/* The one and only E32 device, defined in radio.c and shared with Core 1.
 * Declared here so handlers can take &radio without the caller threading it
 * through every call. */
extern e32_t radio;

#ifdef __cplusplus
}
#endif

#endif /* RADIO_H */
