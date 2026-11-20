/*
 * Test-only harness: runs the ZKNOX C signer (nist16.c) natively with a
 * caller-supplied randombytes() stream, so that its output can be compared
 * byte for byte with the noble signer fed the same stream.
 *
 *   fixed_rng_harness <seed hex> <random stream hex> <message hex>
 *
 * prints pk=..., sk=..., sm=... (hex). Never link this randombytes() into
 * anything else: it replays the given bytes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"

static unsigned char rb[4096];
static size_t rb_len, rb_pos;

int randombytes(unsigned char *x, unsigned long long n)
{
	if (rb_pos + n > rb_len)
		return -1;
	memcpy(x, rb + rb_pos, n);
	rb_pos += n;
	return 0;
}

static size_t unhex(const char *s, unsigned char *out, size_t max)
{
	size_t n = strlen(s) / 2;
	if (n > max)
		exit(10);
	for (size_t i = 0; i < n; i++)
		if (sscanf(s + 2 * i, "%2hhx", out + i) != 1)
			exit(11);
	return n;
}

static void phex(const char *k, const unsigned char *b, size_t n)
{
	printf("%s=", k);
	for (size_t i = 0; i < n; i++)
		printf("%02x", b[i]);
	printf("\n");
}

int main(int argc, char **argv)
{
	static unsigned char seed[256], msg[1024], sm[4096];
	static unsigned char pk[ZKNOX_CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
	unsigned long long smlen;
	size_t seedlen, mlen;

	if (argc != 4)
		return 9;
	seedlen = unhex(argv[1], seed, sizeof seed);
	rb_len = unhex(argv[2], rb, sizeof rb);
	mlen = unhex(argv[3], msg, sizeof msg);
	if (zknox_crypto_sign_keypair_from_seed(pk, sk, seed, seedlen) != 0)
		return 1;
	if (zknox_crypto_sign(sm, &smlen, msg, mlen, sk) != 0)
		return 2;
	phex("pk", pk, sizeof pk);
	phex("sk", sk, sizeof sk);
	phex("sm", sm, (size_t)smlen);
	return 0;
}
