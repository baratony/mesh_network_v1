#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pico/stdlib.h"
#include "mini-gmp.h"
#include "hardware/structs/rosc.h"
#include "hardware/regs/rosc.h"
#include "hardware/clocks.h"
#include "hardware/vreg.h"
#include "chacha20_drng.h"
#include "mbedtls/sha256.h"

// ======================================================
// ROSC setup
// Same method Cornell uses to speed up the oscillator
// ======================================================
void rosc_setup(void) {
    volatile uint32_t *rosc_div =
        (uint32_t *)(ROSC_BASE + ROSC_DIV_OFFSET);

    volatile uint32_t *rosc_ctl =
        (uint32_t *)(ROSC_BASE + ROSC_CTRL_OFFSET);

    volatile uint32_t *rosc_freqA =
        (uint32_t *)(ROSC_BASE + ROSC_FREQA_OFFSET);

    volatile uint32_t *rosc_freqB =
        (uint32_t *)(ROSC_BASE + ROSC_FREQB_OFFSET);

    // Divider = 1
    *rosc_div = ROSC_DIV_VALUE_PASS + 1;

    // Increase oscillator frequency
    *rosc_ctl = ROSC_CTRL_FREQ_RANGE_VALUE_HIGH;

    // Max drive strength
    *rosc_freqA =
        (ROSC_FREQA_PASSWD_VALUE_PASS << 16) | 0xFFFF;

    *rosc_freqB =
        (ROSC_FREQB_PASSWD_VALUE_PASS << 16) | 0xFFFF;
};


// ======================================================
// Generate list of random numbers
//
// bit_length = how long you want your seed to be
// ======================================================

void generate_random_seed(mpz_t result, int bit_length) {


    mpz_set_ui(result, 0);

    for (int i = 0; i < (bit_length/32); i++) {

        uint32_t random = 0;

        volatile uint32_t *rnd_reg =
            (uint32_t *)(ROSC_BASE + ROSC_RANDOMBIT_OFFSET);

        for (int k = 0; k < 32; k++) {

            uint32_t bit1;
            uint32_t bit2;

            // Von Neumann extractor
            while (1) {

                bit1 = 0x1 & (*rnd_reg);

                asm("nop");
                asm("nop");
                asm("nop");
                asm("nop");

                bit2 = 0x1 & (*rnd_reg);

                // Only use bits if different
                if (bit1 != bit2) {
                    break;
                }
            }

            random = (random << 1) | bit1;
        }

        srand(random);

        mpz_mul_2exp(result, result, 32);
        mpz_add_ui(result, result, rand());

    }
};


void generate_random_number(mpz_t seed, mpz_t random_number, int length_of_random_number, int length_of_seed) {

    struct chacha20_drng *rng;
    chacha20_drng_init(&rng);

    uint8_t seed_bytes[length_of_seed / 8];
    uint8_t random_buffer[length_of_random_number / 8];
    size_t count;

    memset(seed_bytes, 0, sizeof(seed_bytes));

    mpz_export(
    seed_bytes,
    &count,
    1,
    1,
    1,
    0,
    seed
);

    chacha20_drng_seed(rng, seed_bytes, sizeof(seed_bytes));
    chacha20_drng_random_bytes(rng, random_buffer, sizeof(random_buffer));

    mpz_import(random_number, sizeof(random_buffer), 1, 1, 0, 0, random_buffer);
    chacha20_drng_free(rng);

};

void generate_random_prime_number(mpz_t random_start, mpz_t rsa_num) {
    int is_prime;
    static const unsigned int small_primes[] = {
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
    37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97
    };    


    int num_primes = sizeof(small_primes) / sizeof(small_primes[0]);
    uint32_t iterations = 1;
    /* copy the start value into rsa_num */
    mpz_set(rsa_num, random_start);

    /* Make sure we start with an odd candidate. */
    if (mpz_even_p(rsa_num)) {
        mpz_add_ui(rsa_num, rsa_num, 1);
    }

    while (1) {

        for (int i = 0; i < num_primes; i++)
        {
            if (mpz_tdiv_ui(rsa_num, small_primes[i]) == 0)
            {
                mpz_add_ui(rsa_num, rsa_num, 2);
                break;
            }
        }

        is_prime = mpz_probab_prime_p(rsa_num, 5);

        /* if probable prime, we're close done */
        if (is_prime > 0) {
        
            printf("Found Prime\n");
            break;

        }

        if (iterations % 50 == 0) {
            printf("50 Canidates tested\n");
            iterations = 0;
        }

        /* otherwise try next odd candidate */
        iterations++; 
        mpz_add_ui(rsa_num, rsa_num, 2);
    }
};

bool RSA_safe_prime_check(mpz_t prime_one, mpz_t prime_two) {

    mpz_t n;
    mpz_t diff;
    mpz_t threshold;

    mpz_init(n);
    mpz_init(diff);
    mpz_init(threshold);

    // n = p*q
    mpz_mul(n, prime_one, prime_two);

    // nlen = bit length of n
    int nlen = mpz_sizeinbase(n, 2);

    // diff = |p-q|
    mpz_sub(diff, prime_one, prime_two);
    mpz_abs(diff, diff);


    // threshold = 2^(nlen/2 - 100)
    mpz_set_ui(threshold, 1);
    mpz_mul_2exp(threshold, threshold, (nlen / 2) - 100);

    bool result = (mpz_cmp(diff, threshold) < 0);

    mpz_clear(n);
    mpz_clear(diff);
    mpz_clear(threshold);

    printf("Safe Check Completed\n");
    return result;
};

void RSA_encrypt(mpz_t Message, mpz_t EKey, mpz_t Public_Modulo, mpz_t Cipher_Text) {

//    C = M^E mod(N)
    mpz_powm(Cipher_Text, Message, EKey, Public_Modulo);

};

void RSA_decrypt(mpz_t Message, mpz_t DKey, mpz_t Public_Modulo, mpz_t Cipher_Text) {
    
//  M = C^d mod(N)
    mpz_powm(Message, Cipher_Text, DKey, Public_Modulo);

};

bool RSA_key_generation(mpz_t p, mpz_t q, mpz_t Public_Modulo, mpz_t Private_Key) {
    mpz_t qd;
    mpz_t pd;
    mpz_t phi;
    mpz_t d;
    mpz_t e;

    mpz_init(qd);
    mpz_init(pd);
    mpz_init(phi);
    mpz_init(d);
    mpz_init(e);

    // Set e = 65537
    mpz_set_ui(e, 65537);

    // Get p-1 and q-1
    mpz_sub_ui(qd, q, 1);
    mpz_sub_ui(pd, p, 1);
    // Get the totient function(phi) using (p-1)(q-1)
    mpz_mul(phi, qd, pd);
    mpz_mul(Public_Modulo, p, q);

    // e x d = 1 (mod (phi of n)) --> e = 65537 there is a 1 in 32768 chance that e is not coprime with phi of n
    if (!mpz_invert(Private_Key, e, phi)) {
        printf("Phi and e are not coprime please regenerate your primes.\n");
        return 1;
    };

    mpz_clear(qd);
    mpz_clear(pd);
    mpz_clear(phi);
    mpz_clear(e);
    mpz_clear(d);

    printf("Succesfully generated key pairs.\n");
    return 0;
};

bool RSA_test(int m) {
    mpz_t seed, rn, rsan1, rsan2, PM, SK, e, M, CT, NM;
    int safe;

    mpz_init(seed);
    mpz_init(rn);
    mpz_init(rsan1);
    mpz_init(rsan2);
    mpz_init(PM);
    mpz_init(SK);
    mpz_init(e);
    mpz_init(M);
    mpz_init(CT);
    mpz_init(NM);

    mpz_set_ui(M, m);
    mpz_set_ui(e, 65537);

    printf("Starting RSA test.\n");

    // Generate 2 random Primes
    generate_random_seed(seed, 256);
    generate_random_number(seed, rn, 1028, 256);
    generate_random_prime_number(rn, rsan1);
    printf("First Prime Generated.\n"); 

    while (true) {

        generate_random_seed(seed, 256);
        generate_random_number(seed, rn, 1028, 256);
        generate_random_prime_number(rn, rsan2);

        // Generate Private/Public Key pair
        bool is_safe = RSA_safe_prime_check(rsan1, rsan2);
        bool suc_key_gen = RSA_key_generation(rsan1, rsan2, PM, SK);

        if (!is_safe && !suc_key_gen) {
            printf("Second Prime Generated.\n");
            printf("Primes are Valid.\n");
            break;
        }

        printf("Primes Invalid. Generating New Primes.\n");
    };

    // Encrypt and decrypt the message
    RSA_encrypt(M, e, PM, CT);
    printf("Message Encrypted.\n");

    RSA_decrypt(NM, SK, PM, CT);
    printf("Message Decrypted.\n");

    mpz_clear(SK);
    mpz_clear(e);
    mpz_clear(CT);
    mpz_clear(seed);
    mpz_clear(rn);
    mpz_clear(rsan1);
    mpz_clear(rsan2);
    mpz_clear(PM);

    size_t buffer_len = mpz_sizeinbase(NM, 10) + 2;
    char *buffer = malloc(buffer_len);
    if (!buffer) {
        printf("Out of memory building RSA output string.\n");
        mpz_clear(M);
        mpz_clear(NM);
        return 1;
    }

    mpz_get_str(buffer, 10, NM);
    printf("New Message after RSA process: %s\n", buffer);
    free(buffer);

    if (mpz_cmp(M, NM) == 0) {
        printf("RSA test is successful.\n");
        mpz_clear(M);
        mpz_clear(NM);
        return 0;
    }

    printf("New Message did not mactch orginal.\n");
    mpz_clear(M);
    mpz_clear(NM);
    return 1;
};


void DH_Generate_Private_Number(mpz_t Private_Number) {
    mpz_t seed;
    mpz_init(seed);

    printf("Generating Private Number of DHKE.\n");
    generate_random_seed(seed, 128);
    generate_random_number(seed, Private_Number, 256, 128);  // Default private number bit length is 256 bits created from a 128 bit seed.
    printf("DH private number generated.\n");

    mpz_clear(seed);
};

void DH_Generate_Sending_Number(mpz_t Sending_Number, mpz_t g, mpz_t N, mpz_t a) {
    //    Sending_Number = g^a mod(N)
    mpz_powm(Sending_Number, g, a, N);   // Identical to the RSA_Encrypt/Decrypt functions
};

void DH_Shared_Secret(mpz_t Shared_Secret, mpz_t Recieved_Number, mpz_t N, mpz_t a) {
    //    Recieving_Number = g^a mod(N)
    mpz_powm(Shared_Secret, Recieved_Number, a, N); 
}

bool DH_Test() {
    mpz_t a, b, N, g, sending_number_a, sending_number_b, shared_secret_a, shared_secret_b, seed, rn;
    mpz_init(a);
    mpz_init(b);
    mpz_init(N);
    mpz_init(g);

    mpz_init(sending_number_a);
    mpz_init(sending_number_b);

    mpz_init(shared_secret_a);
    mpz_init(shared_secret_b);

    mpz_init(seed);
    mpz_init(rn);

    mpz_set_ui(g, 2); // Set generator two, the generator does not have to be a large number

    // Generate a and b
    DH_Generate_Private_Number(a);
    DH_Generate_Private_Number(b);
    // Finished Generating a and b

    // Generate N, N is Usually a sophie Germain Prime but it is only a test so N is not a Sophie Germain Prime. 
    generate_random_seed(seed, 256);
    generate_random_number(seed, rn, 1028, 256);
    generate_random_prime_number(rn, N);
    mpz_clear(seed);
    mpz_clear(rn);
    // Finished Generating N

    DH_Generate_Sending_Number(sending_number_a, g, N, a);
    DH_Generate_Sending_Number(sending_number_b, g, N, b);

    DH_Shared_Secret(shared_secret_a, sending_number_b, N, a);
    DH_Shared_Secret(shared_secret_b, sending_number_a, N, b);

    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(N);
    mpz_clear(g);
    mpz_clear(sending_number_a);
    mpz_clear(sending_number_b);

    if (mpz_cmp(shared_secret_a, shared_secret_b) == 0) {
        printf("DH test is successful!\n");
        mpz_clear(shared_secret_a);
        mpz_clear(shared_secret_b);
        return 0;
    }

    printf("Shared Secrets did not match, DH test failed.\n");
    mpz_clear(shared_secret_a);
    mpz_clear(shared_secret_b);
    return 1;
};


void sha256_hash(
    const uint8_t *input,
    size_t input_len,
    uint8_t output[32]
)
{
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, input, input_len);
    mbedtls_sha256_finish(&ctx, output);

    mbedtls_sha256_free(&ctx);
};


int chacha20poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
)
{
    mbedtls_chachapoly_context ctx;

    mbedtls_chachapoly_init(&ctx);

    int result = mbedtls_chachapoly_setkey(&ctx, key);

    if (result != 0) {
        mbedtls_chachapoly_free(&ctx);
        return result;
    }

    result = mbedtls_chachapoly_encrypt_and_tag(
        &ctx,
        plaintext_len,
        nonce,
        NULL,       // No AAD for now
        0,
        plaintext,
        ciphertext,
        tag
    );

    mbedtls_chachapoly_free(&ctx);

    return result;
};

int chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext
)
{
    mbedtls_chachapoly_context ctx;

    mbedtls_chachapoly_init(&ctx);

    int result = mbedtls_chachapoly_setkey(&ctx, key);

    if (result != 0) {
        mbedtls_chachapoly_free(&ctx);
        return result;
    }

    result = mbedtls_chachapoly_auth_decrypt(
        &ctx,
        ciphertext_len,
        nonce,
        NULL,       // No AAD
        0,
        tag,
        ciphertext,
        plaintext
    );

    mbedtls_chachapoly_free(&ctx);

    return result;
};


// ======================================================
// MAIN
// ======================================================
int main() {

    vreg_set_voltage(VREG_VOLTAGE_1_30);
    set_sys_clock_khz(400000, true);

    stdio_init_all();
    rosc_setup();
    sleep_ms(9000);

    bool RSA_Suc = RSA_test(190);
    bool DH_Suc = DH_Test();
    sleep_ms(100);

    while (true) {
        tight_loop_contents();
    }
}
