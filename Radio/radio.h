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

uint16_t Generate_Local_Adress(uint32_t global_address,
                               e32_t *radio,
                               ftp_client_t *ftp);

bool Respond_To_Connections_Request(uint32_t global_address,
                                    e32_t *radio,
                                    ftp_client_t *ftp,
                                    const radio_packet_t *request);

bool Request_Global_Connections(uint32_t global_address,
                                e32_t *radio,
                                ftp_client_t *ftp,
                                const radio_packet_t *request);

bool Respond_To_Global_Connections_Request(uint32_t global_address,
                                          e32_t *radio,
                                          ftp_client_t *ftp,
                                          const radio_packet_t *request);

bool Request_Global_RSA_Keys(uint32_t global_address,
                             e32_t *radio,
                             ftp_client_t *ftp,
                             const radio_packet_t *request);

bool Respond_To_Global_RSA_Keys_Request(uint32_t global_address,
                                       e32_t *radio,
                                       ftp_client_t *ftp,
                                       const radio_packet_t *request);

bool Find_Shortest_Global_Route(uint32_t source,
                                uint32_t destination,
                                uint32_t *path,
                                uint8_t *path_length,
                                const uint32_t *known_nodes,
                                size_t known_node_count);

bool Relay_Node_Removal(uint32_t global_address,
                        e32_t *radio,
                        ftp_client_t *ftp);

bool Relay_New_Node(uint32_t global_address,
                    e32_t *radio,
                    ftp_client_t *ftp,
                    const radio_packet_t *request);

bool Respond_To_New_Node(uint32_t global_address,
                        e32_t *radio,
                        ftp_client_t *ftp,
                        const radio_packet_t *request);

bool Relay_RSA_Public_Key(uint32_t global_address,
                         e32_t *radio,
                         ftp_client_t *ftp,
                         const radio_packet_t *request);

bool Respond_To_RSA_Key_Relay(uint32_t global_address,
                             e32_t *radio,
                             ftp_client_t *ftp,
                             const radio_packet_t *request);

bool Respond_To_DH_Exchange_Request(uint32_t global_address,
                                    e32_t *radio_device,
                                    ftp_client_t *ftp,
                                    const radio_packet_t *request,
                                    mpz_t private_rsa_exponent,
                                    mpz_t rsa_modulus,
                                    mpz_t shared_secret);

bool Respond_To_DH_Exchange_Response(uint32_t global_address,
                                     e32_t *radio_device,
                                     ftp_client_t *ftp,
                                     const radio_packet_t *request,
                                     mpz_t private_rsa_exponent,
                                     mpz_t rsa_modulus,
                                     mpz_t shared_secret);

bool Respond_To_DH_Exchange_Result(uint32_t global_address,
                                   ftp_client_t *ftp,
                                   const radio_packet_t *result);

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

bool Handle_Radio_Packet(uint32_t global_address,
                         e32_t *radio,
                         ftp_client_t *ftp,
                         const radio_packet_t *packet,
                         mpz_t private_rsa_exponent,
                         mpz_t rsa_modulus,
                         mpz_t shared_secret);

void Find_Neighbors(uint32_t Global_Adress, e32_t *radio, ftp_client_t *ftp);

void Ping_Response(uint32_t Global_Adress,
                   uint16_t Local_Adress,
                   e32_t *radio,
                   ftp_client_t *ftp,
                   radio_packet_t sender_packet);

bool Send_Local_Adress_To_Neighbors(uint32_t global_address,
                                    uint16_t local_address,
                                    e32_t *radio,
                                    ftp_client_t *ftp);

bool Remove_Local_Address_From_Neighbors(uint32_t global_address,
                                         e32_t *radio,
                                         ftp_client_t *ftp);

bool Create_DH_Exchange_Packet(uint32_t target_global_address,
                               uint32_t personal_global_address,
                               const uint32_t *route,
                               uint8_t *route_length,
                               uint16_t first_hop_local_address,
                               mpz_t private_rsa_exponent,
                               mpz_t rsa_modulus);

extern e32_t radio;

#ifdef __cplusplus
}
#endif

#endif /* RADIO_H */
