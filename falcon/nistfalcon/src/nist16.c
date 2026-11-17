/*
 * Wrapper for implementing the NIST API for the PQC standardization
 * process.
 */

#include <stddef.h>
#include <string.h>

#include "api.h"
#include "inner.h"

#include <stdio.h>
#define NONCELEN 40

/*
 * If stack usage is an issue, define TEMPALLOC to static in order to
 * allocate temporaries in the data section instead of the stack. This
 * would make the crypto_sign_keypair(), crypto_sign(), and
 * crypto_sign_open() functions not reentrant and not thread-safe, so
 * this should be done only for testing purposes.
 */
#define TEMPALLOC

/*
 * randombytes() is provided by randombytes_os.c (OS CSPRNG) in the
 * WASM and Go builds, and by katrng.c (seeded NIST DRBG) in the KAT
 * generators only. It returns 0 on success.
 */
int randombytes(unsigned char *x, unsigned long long xlen);

/*
 * Largest message length accepted by zknox_crypto_sign(): the signed
 * message (2 + NONCELEN + mlen + signature) must fit in a size_t. On
 * wasm32, size_t is 32 bits while mlen is 64 bits.
 */
#define MAX_MLEN ((unsigned long long)(SIZE_MAX - 2 - NONCELEN - ZKNOX_CRYPTO_BYTES))

int zknox_crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
	TEMPALLOC unsigned char seed[48];
	int ret;

	/*
	 * Generate key pair from a fresh 48-byte seed drawn from
	 * randombytes(), then derive it exactly as the seeded variant does.
	 */
	if (randombytes(seed, sizeof seed) != 0)
	{
		Zf(secure_zero)(seed, sizeof seed);
		return -1;
	}
	ret = zknox_crypto_sign_keypair_from_seed(pk, sk, seed, sizeof seed);
	Zf(secure_zero)(seed, sizeof seed);
	return ret;
}

int zknox_crypto_sign_keypair_from_seed(unsigned char *pk, unsigned char *sk,
										const unsigned char *seed, size_t seedlen)
{
	TEMPALLOC union
	{
		uint8_t b[FALCON_KEYGEN_TEMP_9];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[512], g[512], F[512];
	TEMPALLOC uint16_t h[512];
	TEMPALLOC inner_shake256_context rng;
	size_t u, v;
	int ret;

	/*
	 * Seed must be at least 32 bytes.
	 */
	if (seedlen < 32)
	{
		return -1;
	}

	ret = -1;

	/*
	 * Generate key pair from the provided seed.
	 */
	inner_shake256_init(&rng);
	inner_shake256_inject(&rng, seed, seedlen);
	inner_shake256_flip(&rng);
	Zf(keygen)(&rng, f, g, F, NULL, h, 9, tmp.b);
	Zf(to_ntt)(h, 9);

	/*
	 * Encode private key.
	 */
	sk[0] = 0x50 + 9;
	u = 1;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u,
						   f, 9, Zf(max_fg_bits)[9]);
	if (v == 0)
	{
		goto cleanup;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u,
						   g, 9, Zf(max_fg_bits)[9]);
	if (v == 0)
	{
		goto cleanup;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u,
						   F, 9, Zf(max_FG_bits)[9]);
	if (v == 0)
	{
		goto cleanup;
	}
	u += v;
	if (u != CRYPTO_SECRETKEYBYTES)
	{
		goto cleanup;
	}

	/*
	 * Encode public key.
	 */
	pk[0] = 0x00 + 9;
	v = Zf(modq_encode16)(pk + 1, ZKNOX_CRYPTO_PUBLICKEYBYTES - 1, h, 9);

	if (v != ZKNOX_CRYPTO_PUBLICKEYBYTES - 1)
	{
		goto cleanup;
	}

	ret = 0;

cleanup:
	/*
	 * Wipe the secret key material from the stack.
	 */
	Zf(secure_zero)(&tmp, sizeof tmp);
	Zf(secure_zero)(f, sizeof f);
	Zf(secure_zero)(g, sizeof g);
	Zf(secure_zero)(F, sizeof F);
	Zf(secure_zero)(&rng, sizeof rng);
	if (ret != 0)
	{
		Zf(secure_zero)(sk, CRYPTO_SECRETKEYBYTES);
	}
	return ret;
}

int zknox_crypto_sign(unsigned char *sm, unsigned long long *smlen,
					  const unsigned char *m, unsigned long long mlen,
					  const unsigned char *sk)
{
	TEMPALLOC union
	{
		uint8_t b[72 * 512];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[512], g[512], F[512], G[512];
	TEMPALLOC union
	{
		int16_t sig[512];
		uint16_t hm[512];
	} r;
	TEMPALLOC unsigned char seed[48], nonce[NONCELEN];
	TEMPALLOC unsigned char esig[ZKNOX_CRYPTO_BYTES - 2 - sizeof nonce];
#if ETHFALCON
	TEMPALLOC inner_keccak256_prng_ctx kc;
#endif
	TEMPALLOC inner_shake256_context sc;
	size_t u, v, sig_len;
	int ret;

	/*
	 * Reject lengths that do not fit in a size_t (wasm32: 32-bit
	 * size_t, 64-bit mlen) before anything is truncated.
	 */
	if (mlen > MAX_MLEN)
	{
		return -1;
	}

	ret = -1;

	/*
	 * Decode the private key.
	 */
	if (sk[0] != 0x50 + 9)
	{
		goto cleanup;
	}
	u = 1;
	v = Zf(trim_i8_decode)(f, 9, Zf(max_fg_bits)[9],
						   sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0)
	{
		goto cleanup;
	}
	u += v;
	v = Zf(trim_i8_decode)(g, 9, Zf(max_fg_bits)[9],
						   sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0)
	{
		goto cleanup;
	}
	u += v;
	v = Zf(trim_i8_decode)(F, 9, Zf(max_FG_bits)[9],
						   sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0)
	{
		goto cleanup;
	}
	u += v;
	if (u != CRYPTO_SECRETKEYBYTES)
	{
		goto cleanup;
	}
	if (!Zf(complete_private)(G, f, g, F, 9, tmp.b))
	{
		goto cleanup;
	}

	/*
	 * Create a random nonce (40 bytes).
	 */
	if (randombytes(nonce, sizeof nonce) != 0)
	{
		goto cleanup;
	}

	/*
	 * Hash message nonce + message into a vector.
	 */
#if ETHFALCON
	if (inner_keccak256_init(&kc) != 0
		|| inner_keccak256_inject(&kc, nonce, sizeof nonce) != 0
		|| inner_keccak256_inject(&kc, m, (size_t)mlen) != 0
		|| inner_keccak256_flip(&kc) != 0
		|| Zf(keccak_hash_to_point_vartime)(&kc, r.hm, 9) != 0)
	{
		goto cleanup;
	}
#else
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, nonce, sizeof nonce);
	inner_shake256_inject(&sc, m, (size_t)mlen);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, r.hm, 9);
#endif

	/*
	 * Initialize a RNG.
	 */
	if (randombytes(seed, sizeof seed) != 0)
	{
		goto cleanup;
	}
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, seed, sizeof seed);
	inner_shake256_flip(&sc);

	/*
	 * Compute the signature.
	 */
	Zf(sign_dyn)(r.sig, &sc, f, g, F, G, r.hm, 9, tmp.b);

	/*
	 * Encode the signature and bundle it with the message. Format is:
	 *   signature length     2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   signature            slen bytes
	 */
	esig[0] = 0x20 + 9;
	sig_len = Zf(comp_encode16)(esig + 1, sizeof(esig) - 1, r.sig, 9);
	if (sig_len == 0)
	{
		goto cleanup;
	}
	sig_len++;
	memmove(sm + 2 + sizeof nonce, m, (size_t)mlen);
	sm[0] = (unsigned char)(sig_len >> 8);
	sm[1] = (unsigned char)sig_len;
	memcpy(sm + 2, nonce, sizeof nonce);
	memcpy(sm + 2 + (sizeof nonce) + (size_t)mlen, esig, sig_len);
	*smlen = 2 + (sizeof nonce) + mlen + sig_len;
	ret = 0;

cleanup:
	/*
	 * Wipe the private key, the expanded key, the sampler seed and
	 * the sampler state from the stack.
	 */
	Zf(secure_zero)(&tmp, sizeof tmp);
	Zf(secure_zero)(f, sizeof f);
	Zf(secure_zero)(g, sizeof g);
	Zf(secure_zero)(F, sizeof F);
	Zf(secure_zero)(G, sizeof G);
	Zf(secure_zero)(&r, sizeof r);
	Zf(secure_zero)(seed, sizeof seed);
	Zf(secure_zero)(&sc, sizeof sc);
#if ETHFALCON
	Zf(secure_zero)(&kc, sizeof kc);
#endif
	return ret;
}

static void to_monty(uint16_t *h, unsigned logn)
{
	// 4091 = 2^16 mod 12289
	size_t n = (size_t)1 << logn;
	for (size_t i = 0; i < n; i++)
	{
		h[i] = (uint16_t)((uint32_t)h[i] * 4091u % 12289u);
	}
}

int zknox_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
						   const unsigned char *sm, unsigned long long smlen,
						   const unsigned char *pk)
{
	TEMPALLOC union
	{
		uint8_t b[2 * 512];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	const unsigned char *esig;
	TEMPALLOC uint16_t h[512], hm[512];
	TEMPALLOC int16_t sig[512];
#if ETHFALCON
	TEMPALLOC inner_keccak256_prng_ctx kc;
#else
	TEMPALLOC inner_shake256_context sc;
#endif
	size_t sig_len, msg_len;

	/*
	 * Reject lengths that do not fit in a size_t (wasm32: 32-bit
	 * size_t, 64-bit smlen).
	 */
	if (smlen > (unsigned long long)SIZE_MAX)
	{
		return -1;
	}

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + 9)
	{
		return -1;
	}
	if (Zf(modq_decode16)(h, 9, pk + 1, ZKNOX_CRYPTO_PUBLICKEYBYTES - 1) != ZKNOX_CRYPTO_PUBLICKEYBYTES - 1)
	{
		return -1;
	}
	to_monty(h, 9);

	/*
	 * Find nonce, signature, message length.
	 */
	if (smlen < 2 + NONCELEN)
	{
		return -1;
	}
	sig_len = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (sig_len > (smlen - 2 - NONCELEN))
	{
		return -1;
	}
	msg_len = smlen - 2 - NONCELEN - sig_len;

	/*
	 * Decode signature.
	 */
	esig = sm + 2 + NONCELEN + msg_len;
	if (sig_len < 1 || esig[0] != 0x20 + 9)
	{
		return -1;
	}
	if (Zf(comp_decode16)(sig, 9,
						  esig + 1, sig_len - 1) != sig_len - 1)
	{
		return -1;
	}
	/*
	 * Hash nonce +	 message into a vector.
	 */
#if ETHFALCON
	if (inner_keccak256_init(&kc) != 0
		|| inner_keccak256_inject(&kc, sm + 2, NONCELEN + msg_len) != 0
		|| inner_keccak256_flip(&kc) != 0
		|| Zf(keccak_hash_to_point_vartime)(&kc, hm, 9) != 0)
	{
		return -1;
	}
#else
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, sm + 2, NONCELEN + msg_len);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, hm, 9);
#endif

	/*
	 * Verify signature.
	 */
	if (!Zf(verify_raw)(hm, sig, h, 9, tmp.b))
	{
		return -1;
	}
	/*
	 * Return plaintext.
	 */
	memmove(m, sm + 2 + NONCELEN, msg_len);
	*mlen = msg_len;
	return 0;
}
