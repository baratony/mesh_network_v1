/*
 * Copyright (C) 2016 - 2017, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "chacha20_drng.h"

#define MAJVERSION 1   /* API / ABI incompatible changes,
			* functional changes that require consumer
			* to be updated (as long as this number is
			* zero, the API is not considered stable
			* and can change without a bump of the
			* major version). */
#define MINVERSION 3   /* API compatible, ABI may change,
			* functional enhancements only, consumer
			* can be left unchanged if enhancements are
			* not considered. */
#define PATCHLEVEL 2   /* API / ABI compatible, no functional
			* changes, no enhancements, bug fixes
			* only. */

#define CHACHA20_DRNG_ALIGNMENT	8	/* allow u8 to u32 conversions */

#if __GNUC__ >= 4
# define DSO_PUBLIC __attribute__ ((visibility ("default")))
#else
# define DSO_PUBLIC
#endif

/*********************************** Helper ***********************************/

#define min(x, y) ((x < y) ? x : y)
#define __aligned(x) __attribute__((aligned(x)))

static inline void memset_secure(void *s, int c, uint32_t n)
{
	memset(s, c, n);
	__asm__ __volatile__("" : : "r" (s) : "memory");
}


static inline uint32_t rol32(uint32_t x, int n)
{
	return ( (x << (n&(32-1))) | (x >> ((32-n)&(32-1))) );
}

static inline uint32_t ror32(uint32_t x, int n)
{
	return ( (x >> (n&(32-1))) | (x << ((32-n)&(32-1))) );
}

/* Byte swap for 32-bit and 64-bit integers. */
static inline uint32_t _bswap32(uint32_t x)
{
	return ((rol32(x, 8) & 0x00ff00ffL) | (ror32(x, 8) & 0xff00ff00L));
}

/* Endian dependent byte swap operations.  */
#if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__
# define le_bswap32(x) _bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define le_bswap32(x) ((uint32_t)(x))
#else
#error "Endianess not defined"
#endif

static inline void drng_chacha20_bswap32(uint32_t *ptr, uint32_t words)
{
	uint32_t i;

	/* Byte-swap data which is an LE representation */
	for (i = 0; i < words; i++) {
		*ptr = le_bswap32(*ptr);
		ptr++;
	}
}

/******************************* ChaCha20 Block *******************************/

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_KEY_SIZE_WORDS (CHACHA20_KEY_SIZE / sizeof(uint32_t))

/* State according to RFC 7539 section 2.3 */
struct chacha20_state {
	uint32_t constants[4];
	union {
		uint32_t u[CHACHA20_KEY_SIZE_WORDS];
		uint8_t  b[CHACHA20_KEY_SIZE];
	} key;
	uint32_t counter;
	uint32_t nonce[3];
};

#define CHACHA20_BLOCK_SIZE sizeof(struct chacha20_state)
#define CHACHA20_BLOCK_SIZE_WORDS (CHACHA20_BLOCK_SIZE / sizeof(uint32_t))

/* ChaCha20 block function according to RFC 7539 section 2.3 */
static void chacha20_block(uint32_t *state, uint32_t *stream)
{
	uint32_t i, ws[CHACHA20_BLOCK_SIZE_WORDS], *out = stream;

	for (i = 0; i < CHACHA20_BLOCK_SIZE_WORDS; i++)
		ws[i] = state[i];

	for (i = 0; i < 10; i++) {
		/* Quarterround 1 */
		ws[0]  += ws[4];  ws[12] = rol32(ws[12] ^ ws[0],  16);
		ws[8]  += ws[12]; ws[4]  = rol32(ws[4]  ^ ws[8],  12);
		ws[0]  += ws[4];  ws[12] = rol32(ws[12] ^ ws[0],   8);
		ws[8]  += ws[12]; ws[4]  = rol32(ws[4]  ^ ws[8],   7);

		/* Quarterround 2 */
		ws[1]  += ws[5];  ws[13] = rol32(ws[13] ^ ws[1],  16);
		ws[9]  += ws[13]; ws[5]  = rol32(ws[5]  ^ ws[9],  12);
		ws[1]  += ws[5];  ws[13] = rol32(ws[13] ^ ws[1],   8);
		ws[9]  += ws[13]; ws[5]  = rol32(ws[5]  ^ ws[9],   7);

		/* Quarterround 3 */
		ws[2]  += ws[6];  ws[14] = rol32(ws[14] ^ ws[2],  16);
		ws[10] += ws[14]; ws[6]  = rol32(ws[6]  ^ ws[10], 12);
		ws[2]  += ws[6];  ws[14] = rol32(ws[14] ^ ws[2],   8);
		ws[10] += ws[14]; ws[6]  = rol32(ws[6]  ^ ws[10],  7);

		/* Quarterround 4 */
		ws[3]  += ws[7];  ws[15] = rol32(ws[15] ^ ws[3],  16);
		ws[11] += ws[15]; ws[7]  = rol32(ws[7]  ^ ws[11], 12);
		ws[3]  += ws[7];  ws[15] = rol32(ws[15] ^ ws[3],   8);
		ws[11] += ws[15]; ws[7]  = rol32(ws[7]  ^ ws[11],  7);

		/* Quarterround 5 */
		ws[0]  += ws[5];  ws[15] = rol32(ws[15] ^ ws[0],  16);
		ws[10] += ws[15]; ws[5]  = rol32(ws[5]  ^ ws[10], 12);
		ws[0]  += ws[5];  ws[15] = rol32(ws[15] ^ ws[0],   8);
		ws[10] += ws[15]; ws[5]  = rol32(ws[5]  ^ ws[10],  7);

		/* Quarterround 6 */
		ws[1]  += ws[6];  ws[12] = rol32(ws[12] ^ ws[1],  16);
		ws[11] += ws[12]; ws[6]  = rol32(ws[6]  ^ ws[11], 12);
		ws[1]  += ws[6];  ws[12] = rol32(ws[12] ^ ws[1],   8);
		ws[11] += ws[12]; ws[6]  = rol32(ws[6]  ^ ws[11],  7);

		/* Quarterround 7 */
		ws[2]  += ws[7];  ws[13] = rol32(ws[13] ^ ws[2],  16);
		ws[8]  += ws[13]; ws[7]  = rol32(ws[7]  ^ ws[8],  12);
		ws[2]  += ws[7];  ws[13] = rol32(ws[13] ^ ws[2],   8);
		ws[8]  += ws[13]; ws[7]  = rol32(ws[7]  ^ ws[8],   7);

		/* Quarterround 8 */
		ws[3]  += ws[4];  ws[14] = rol32(ws[14] ^ ws[3],  16);
		ws[9]  += ws[14]; ws[4]  = rol32(ws[4]  ^ ws[9],  12);
		ws[3]  += ws[4];  ws[14] = rol32(ws[14] ^ ws[3],   8);
		ws[9]  += ws[14]; ws[4]  = rol32(ws[4]  ^ ws[9],   7);
	}

	for (i = 0; i < CHACHA20_BLOCK_SIZE_WORDS; i++)
		out[i] = le_bswap32(ws[i] + state[i]);

	state[12]++;
}

static inline int drng_chacha20_selftest_one(struct chacha20_state *state,
					     uint32_t *expected)
{
	uint32_t result[CHACHA20_BLOCK_SIZE_WORDS];

	chacha20_block(&state->constants[0], result);

	return memcmp(expected, result, CHACHA20_BLOCK_SIZE);
}

static int drng_chacha20_selftest(void)
{
	struct chacha20_state chacha20;
	uint32_t expected[CHACHA20_BLOCK_SIZE_WORDS];

	/* Test vector according to RFC 7539 section 2.3.2 */
	chacha20.constants[0] = 0x61707865; chacha20.constants[1] = 0x3320646e;
	chacha20.constants[2] = 0x79622d32; chacha20.constants[3] = 0x6b206574;
	chacha20.key.u[0]     = 0x03020100; chacha20.key.u[1]     = 0x07060504;
	chacha20.key.u[2]     = 0x0b0a0908; chacha20.key.u[3]     = 0x0f0e0d0c;
	chacha20.key.u[4]     = 0x13121110; chacha20.key.u[5]     = 0x17161514;
	chacha20.key.u[6]     = 0x1b1a1918; chacha20.key.u[7]     = 0x1f1e1d1c;
	chacha20.counter      = 0x00000001; chacha20.nonce[0]     = 0x09000000;
	chacha20.nonce[1]     = 0x4a000000; chacha20.nonce[2]     = 0x00000000;

	expected[0] = 0xe4e7f110;  expected[1] = 0x15593bd1;
	expected[2] = 0x1fdd0f50;  expected[3] = 0xc47120a3;
	expected[4] = 0xc7f4d1c7;  expected[5] = 0x0368c033;
	expected[6] = 0x9aaa2204;  expected[7] = 0x4e6cd4c3;
	expected[8] = 0x466482d2;  expected[9] = 0x09aa9f07;
	expected[10] = 0x05d7c214; expected[11] = 0xa2028bd9;
	expected[12] = 0xd19c12b5; expected[13] = 0xb94e16de;
	expected[14] = 0xe883d0cb; expected[15] = 0x4e3c50a2;

	drng_chacha20_bswap32(expected, CHACHA20_BLOCK_SIZE_WORDS);

	return drng_chacha20_selftest_one(&chacha20, &expected[0]);
}



/******************************* ChaCha20 DRNG *******************************/

struct chacha20_drng {
	struct chacha20_state chacha20;
	time_t last_seeded;
	uint64_t generated_bytes;
};

/**
 * Update of the ChaCha20 state by generating one ChaCha20 block which is
 * equal to the state of the ChaCha20. The generated block is XORed into
 * the key part of the state. This shall ensure backtracking resistance as well
 * as a proper mix of the ChaCha20 state once the key is injected.
 */
static inline void drng_chacha20_update(struct chacha20_state *chacha20,
					uint32_t *buf, uint32_t used_words)
{
	uint32_t i, tmp[CHACHA20_BLOCK_SIZE_WORDS];

	if (CHACHA20_BLOCK_SIZE_WORDS - used_words < CHACHA20_KEY_SIZE_WORDS) {
		chacha20_block(&chacha20->constants[0], tmp);
		for (i = 0; i < CHACHA20_KEY_SIZE_WORDS; i++)
			chacha20->key.u[i] ^= le_bswap32(tmp[i]);
		memset_secure(tmp, 0, sizeof(tmp));
	} else {
		for (i = 0; i < CHACHA20_KEY_SIZE_WORDS; i++)
			chacha20->key.u[i] ^= le_bswap32(buf[i + used_words]);
	}

	/* Deterministic increment of nonce as required in RFC 7539 chapter 4 */
	chacha20->nonce[0]++;
	if (chacha20->nonce[0] == 0){
		chacha20->nonce[1]++;
		if (chacha20->nonce[1] == 0)
			chacha20->nonce[2]++;
	}

	/* Leave counter untouched as it is start value is undefined in RFC */
}

/**
 * Seed the ChaCha20 DRNG by injecting the input data into the key part of
 * the ChaCha20 state. If the input data is longer than the ChaCha20 key size,
 * perform a ChaCha20 operation after processing of key size input data.
 * This operation shall spread out the entropy into the ChaCha20 state before
 * new entropy is injected into the key part.
 *
 * The approach taken here is logically similar to a CBC-MAC: The input data
 * is processed chunk-wise. Each chunk is encrypted, the output is XORed with
 * the next chunk of the input and then encrypted again. I.e. the
 * ChaCha20 CBC-MAC of the seed data is injected into the DRNG state.
 */
static int drng_chacha20_seed(struct chacha20_state *chacha20,
			      const uint8_t *inbuf, uint32_t inbuflen)
{
	while (inbuflen) {
		uint32_t i, todo = min(inbuflen, CHACHA20_KEY_SIZE);

		for (i = 0; i < todo; i++)
			chacha20->key.b[i] ^= inbuf[i];

		/* Break potential dependencies between the inbuf key blocks */
		drng_chacha20_update(chacha20, NULL, CHACHA20_BLOCK_SIZE_WORDS);
		inbuf += todo;
		inbuflen -= todo;
	}

	return 0;
}

/**
 * Chacha20 DRNG generation of random numbers: the stream output of ChaCha20
 * is the random number. After the completion of the generation of the
 * stream, the entire ChaCha20 state is updated.
 *
 * Note, as the ChaCha20 implements a 32 bit counter, we must ensure
 * that this function is only invoked for at most 2^32 - 1 ChaCha20 blocks
 * before a reseed or an update happens. This is ensured by the variable
 * outbuflen which is a 32 bit integer defining the number of bytes to be
 * generated by the ChaCha20 DRNG. At the end of this function, an update
 * operation is invoked which implies that the 32 bit counter will never be
 * overflown in this implementation.
 */
static int drng_chacha20_generate(struct chacha20_state *chacha20,
				  uint8_t *outbuf, uint32_t outbuflen)
{
	uint32_t aligned_buf[(CHACHA20_BLOCK_SIZE / sizeof(uint32_t))];
	uint32_t used = CHACHA20_BLOCK_SIZE_WORDS;
	int zeroize_buf = 0;

	while (outbuflen >= CHACHA20_BLOCK_SIZE) {
		if ((unsigned long)outbuf & (sizeof(aligned_buf[0]) - 1)) {
			chacha20_block(&chacha20->constants[0], aligned_buf);
			memcpy(outbuf, aligned_buf, CHACHA20_BLOCK_SIZE);
			zeroize_buf = 1;
		} else {
			chacha20_block(&chacha20->constants[0],
				       (uint32_t *)outbuf);
		}

		outbuf += CHACHA20_BLOCK_SIZE;
		outbuflen -= CHACHA20_BLOCK_SIZE;
	}

	if (outbuflen) {
		chacha20_block(&chacha20->constants[0], aligned_buf);
		memcpy(outbuf, aligned_buf, outbuflen);
		used = ((outbuflen + sizeof(aligned_buf[0]) - 1) /
			sizeof(aligned_buf[0]));
		zeroize_buf = 1;
	}

	drng_chacha20_update(chacha20, aligned_buf, used);

	if (zeroize_buf)
		memset_secure(aligned_buf, 0, sizeof(aligned_buf));

	return 0;
}

static int drng_chacha20_rng_selftest(struct chacha20_drng *drng)
{
	int ret;
	uint8_t outbuf[CHACHA20_KEY_SIZE * 2] __aligned(sizeof(uint32_t));
	uint8_t seed[CHACHA20_KEY_SIZE * 2] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	};

	/*
	 * Expected result when ChaCha20 DRNG state is zero:
	 *	* constants are set to "expand 32-byte k"
	 *	* remaining state is 0
	 * and pulling one ChaCha20 DRNG block.
	 */
	static const uint8_t expected_block[CHACHA20_KEY_SIZE] = {
		0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
		0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
		0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
		0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7 };

	/*
	 * Expected result when ChaCha20 DRNG state is zero:
	 *	* constants are set to "expand 32-byte k"
	 *	* remaining state is 0
	 * followed by a reseed with
	 *	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	 *	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	 *	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	 *	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	 *	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	 *	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	 *	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	 *	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
	 * and pulling two ChaCha20 DRNG blocks.
	 */
	static const uint8_t expected_twoblocks[CHACHA20_KEY_SIZE * 2] = {
		0xe3, 0xb0, 0x8a, 0xcc, 0x34, 0xc3, 0x17, 0x0e,
		0xc3, 0xd8, 0xc3, 0x40, 0xe7, 0x73, 0xe9, 0x0d,
		0xd1, 0x62, 0xa3, 0x5d, 0x7d, 0xf2, 0xf1, 0x4a,
		0x24, 0x42, 0xb7, 0x1e, 0xb0, 0x05, 0x17, 0x07,
		0xb9, 0x35, 0x10, 0x69, 0x8b, 0x46, 0xfb, 0x51,
		0xe9, 0x91, 0x3f, 0x46, 0xf2, 0x4d, 0xea, 0xd0,
		0x81, 0xc1, 0x1b, 0xa9, 0x5d, 0x52, 0x91, 0x5f,
		0xcd, 0xdc, 0xc6, 0xd6, 0xc3, 0x7c, 0x50, 0x23 };

	/*
	 * Expected result when ChaCha20 DRNG state is zero:
	 *	* constants are set to "expand 32-byte k"
	 *	* remaining state is 0
	 * followed by a reseed with
	 *	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	 *	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	 *	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	 *	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	 *	0x20
	 * and pulling one ChaCha20 DRNG block plus four byte.
	 */
	static const uint8_t expected_block_nonaligned[CHACHA20_KEY_SIZE + 4] = {
		0x9c, 0xfc, 0x5e, 0x31, 0x21, 0x62, 0x11, 0x85,
		0xd3, 0x77, 0xd3, 0x69, 0x0f, 0xa8, 0x16, 0x55,
		0xb4, 0x4c, 0xf6, 0x52, 0xf3, 0xa8, 0x37, 0x99,
		0x38, 0x76, 0xa0, 0x66, 0xec, 0xbb, 0xce, 0xa9,
		0x9c, 0x95, 0xa1, 0xfd };

	drng_chacha20_bswap32((uint32_t *)seed,
			      sizeof(seed) / sizeof(uint32_t));

	/* Generate with zero state */
	ret = drng_chacha20_generate(&drng->chacha20, outbuf,
				     sizeof(expected_block));

	if (ret)
		return ret;
	if (memcmp(outbuf, expected_block, sizeof(expected_block)))
		return -EFAULT;

	/* Clear state of DRNG */
	memset(&drng->chacha20.key.u[0], 0, 48);

	/* Reseed with 2 blocks */
	ret = drng_chacha20_seed(&drng->chacha20, seed,
				 sizeof(expected_twoblocks));
	if (ret)
		return ret;

	ret = drng_chacha20_generate(&drng->chacha20, outbuf,
				     sizeof(expected_twoblocks));
	if (ret)
		return ret;
	if (memcmp(outbuf, expected_twoblocks, sizeof(expected_twoblocks)))
		return -EFAULT;

	/* Clear state of DRNG */
	memset(&drng->chacha20.key.u[0], 0, 48);

	/* Reseed with 1 block and one byte */
	ret = drng_chacha20_seed(&drng->chacha20, seed,
				 sizeof(expected_block_nonaligned));
	if (ret)
		return ret;
	ret = drng_chacha20_generate(&drng->chacha20, outbuf,
				     sizeof(expected_block_nonaligned));
	if (ret)
		return ret;
	if (memcmp(outbuf, expected_block_nonaligned,
		   sizeof(expected_block_nonaligned)))
		return -EFAULT;

	return 0;
}

static void drng_chacha20_dealloc(struct chacha20_drng *drng)
{
	memset_secure(drng, 0, sizeof(*drng));
	free(drng);
}

/**
 * Allocation of the DRBG state
 */
static int drng_chacha20_alloc(struct chacha20_drng **out)
{
	struct chacha20_drng *drng;
	int ret = 0;

	if (drng_chacha20_selftest()) {
		return -EFAULT;
	}

	/* Use malloc instead of posix_memalign for embedded portability.
	 * On most systems malloc provides adequate alignment anyway. */
	drng = (struct chacha20_drng *)malloc(sizeof(*drng));
	if (!drng) {
		return -ENOMEM;
	}

	memset(drng, 0, sizeof(*drng));

	/* String "expand 32-byte k" */
	drng->chacha20.constants[0] = 0x61707865;
	drng->chacha20.constants[1] = 0x3320646e;
	drng->chacha20.constants[2] = 0x79622d32;
	drng->chacha20.constants[3] = 0x6b206574;

	/* Initialize key/counter/nonce to zero */
	memset(&drng->chacha20.key.u[0], 0, sizeof(drng->chacha20.key.u));
	drng->chacha20.counter = 0;
	drng->chacha20.nonce[0] = drng->chacha20.nonce[1] = drng->chacha20.nonce[2] = 0;

	drng->last_seeded = time(NULL);
	drng->generated_bytes = 0;

	*out = drng;

	return ret;
}

/* Public API wrappers ---------------------------------------------------- */

int drng_chacha20_init(struct chacha20_drng **out)
{
	if (!out)
		return -EINVAL;
	return drng_chacha20_alloc(out);
}

void drng_chacha20_destroy(struct chacha20_drng *drng)
{
	if (!drng)
		return;
	drng_chacha20_dealloc(drng);
}

int drng_chacha20_reseed(struct chacha20_drng *drng, const uint8_t *inbuf,
						 uint32_t inbuflen)
{
	if (!drng || (!inbuf && inbuflen))
		return -EINVAL;

	/* Mix an available timestamp into the key to add some variability.
	 * On embedded targets (Raspberry Pi Pico) clock_gettime may be
	 * unavailable, so use time(NULL) and other local state as fallback.
	 */
	{
		time_t now = time(NULL);
		uint64_t t = ((uint64_t)now << 32) ^ (uint64_t)drng->generated_bytes ^ (uint64_t)(uintptr_t)drng;
		drng->chacha20.key.u[0] ^= (uint32_t)(t & 0xffffffffUL);
		drng->chacha20.key.u[1] ^= (uint32_t)((t >> 32) & 0xffffffffUL);
	}

	if (inbuf && inbuflen)
		drng_chacha20_seed(&drng->chacha20, inbuf, inbuflen);

	drng->last_seeded = time(NULL);
	drng->generated_bytes = 0;

	return 0;
}

int drng_chacha20_get(struct chacha20_drng *drng, uint8_t *outbuf,
					  uint32_t outbuflen)
{
	if (!drng || (!outbuf && outbuflen))
		return -EINVAL;

	/* Mix available timestamp/state into key before each request. Use
	 * time(NULL) and internal counters so code builds on bare-metal.
	 */
	{
		time_t now = time(NULL);
		uint64_t t = ((uint64_t)now << 32) ^ (uint64_t)drng->generated_bytes ^ (uint64_t)(uintptr_t)drng;
		for (unsigned i = 0; i < sizeof(uint64_t); i++) {
			drng->chacha20.key.b[i % CHACHA20_KEY_SIZE] ^= (uint8_t)(t & 0xff);
			t >>= 8;
		}
	}

	drng_chacha20_generate(&drng->chacha20, outbuf, outbuflen);

	drng->generated_bytes += outbuflen;

	return 0;
}

int drng_chacha20_versionstring(char *buf, size_t buflen)
{
	if (!buf || !buflen)
		return -EINVAL;
	return snprintf(buf, buflen, "chacha20 DRNG %d.%d.%d",
					MAJVERSION, MINVERSION, PATCHLEVEL);
}

uint32_t drng_chacha20_version(void)
{
	return (MAJVERSION * 1000000) + (MINVERSION * 1000) + (PATCHLEVEL);
}

/* Convenience simple API the user asked for */
int chacha20_drng_init(struct chacha20_drng **drng)
{
	return drng_chacha20_init(drng);
}

void chacha20_drng_free(struct chacha20_drng *drng)
{
	drng_chacha20_destroy(drng);
}

int chacha20_drng_seed(struct chacha20_drng *drng, const uint8_t *seed,
					   uint32_t seedlen)
{
	if (!drng || !seed)
		return -EINVAL;
	return drng_chacha20_reseed(drng, seed, seedlen);
}

uint32_t chacha20_drng_random_u32(struct chacha20_drng *drng)
{
	uint8_t out[4] = {0};
	if (!drng)
		return 0;
	drng_chacha20_get(drng, out, sizeof(out));
	uint32_t v;
	memcpy(&v, out, sizeof(v));
	return v;
}

int chacha20_drng_random_bytes(struct chacha20_drng *drng, uint8_t *buf,
                               uint32_t buflen)
{
	if (!drng || !buf || buflen == 0)
		return -EINVAL;
	return drng_chacha20_get(drng, buf, buflen);
}
