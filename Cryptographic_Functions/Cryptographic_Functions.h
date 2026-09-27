#ifndef CRYPTOGRAPHIC_FUNCTIONS_H
#define CRYPTOGRAPHIC_FUNCTIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mini-gmp.h"

#ifdef __cplusplus
extern "C" {
#endif

void rosc_setup(void);

void generate_random_seed(mpz_t result, int bit_length);
void generate_random_number(mpz_t seed, mpz_t random_number,
                            int length_of_random_number,
                            int length_of_seed);
void generate_random_prime_number(mpz_t random_start, mpz_t rsa_num);

bool RSA_safe_prime_check(mpz_t prime_one, mpz_t prime_two);
bool RSA_key_generation(mpz_t p, mpz_t q, mpz_t public_modulo,
                        mpz_t private_key);
void RSA_encrypt(mpz_t message, mpz_t e_key, mpz_t public_modulo,
                 mpz_t cipher_text);
void RSA_decrypt(mpz_t message, mpz_t d_key, mpz_t public_modulo,
                 mpz_t cipher_text);
bool RSA_test(int message);

void DH_Generate_Private_Number(mpz_t private_number);
void DH_Generate_Sending_Number(mpz_t sending_number, mpz_t g, mpz_t n,
                                mpz_t a);
void DH_Shared_Secret(mpz_t shared_secret, mpz_t received_number, mpz_t n,
                      mpz_t a);
bool DH_Test(void);

void sha256_hash(const uint8_t *input, size_t input_len, uint8_t output[32]);

int chacha20poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *ciphertext, uint8_t tag[16]);
int chacha20poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             const uint8_t tag[16], uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif