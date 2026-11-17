/*
 * Wrapper for implementing the NIST API for the PQC standardization
 * process.
 */

#include <stddef.h>
#include <string.h>	

#include "api.h"
#include "inner.h"

#include<stdio.h>
#define NONCELEN   40

/*
 * If stack usage is an issue, define TEMPALLOC to static in order to
 * allocate temporaries in the data section instead of the stack. This
 * would make the crypto_sign_keypair(), crypto_sign(), and
 * crypto_sign_open() functions not reentrant and not thread-safe, so
 * this should be done only for testing purposes.
 */
#define TEMPALLOC

/*
 * randombytes() is provided by randombytes_os.c (OS CSPRNG) or, in the
 * KAT generators only, by katrng.c. It returns 0 on success.
 */
int randombytes(unsigned char *x, unsigned long long xlen);

/*
 * Signature length field: header + s1 (1 + 1024 bytes), header + s2
 * (1 + 1024 bytes), hint (2 bytes).
 */
#define EPERVIER_SIG_LEN (2 * (1 + 1024) + 2)

/*
 * Largest message length accepted by zknox_crypto_sign_epervier(): the
 * signed message must fit in a size_t (wasm32: 32-bit size_t).
 */
#define MAX_MLEN ((unsigned long long)(SIZE_MAX - ZKNOX_CRYPTO_BYTES_EPERVIER))

int
zknox_pk_epervier(unsigned char *pk)
{
	// zknox_crypto_sign_keypair() already outputs h in NTT form (not in
	// Montgomery representation), which is the EPERVIER public key.
	// This only checks and re-encodes it; the address hash is not
	// computed here.
	TEMPALLOC uint16_t h[512];
	size_t v;

	// Decode h
	 if (pk[0] != 0x00 + 9) {
		return -1;
	}
	if (Zf(modq_decode16)(h, 9, pk + 1, ZKNOX_CRYPTO_PUBLICKEYBYTES - 1)
		!= ZKNOX_CRYPTO_PUBLICKEYBYTES - 1)
	{
		return -1;
	}

	/*
	 * Re-encode public key.
	 */
	pk[0] = 0x00 + 9;
	v = Zf(modq_encode16)(pk + 1, ZKNOX_CRYPTO_PUBLICKEYBYTES - 1, h, 9);
	
	if (v != ZKNOX_CRYPTO_PUBLICKEYBYTES - 1) {
		return -1;
	}

	return 0;
}

int
zknox_crypto_sign_epervier(unsigned char *sm, unsigned long long *smlen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk)
{
	TEMPALLOC union {
		uint8_t b[72 * 512];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[512], g[512], F[512], G[512];
	TEMPALLOC union {
		uint16_t hm[512];
	} r;
	TEMPALLOC int16_t s1[512];
	TEMPALLOC int16_t s2[512];
	TEMPALLOC int16_t hint;

	TEMPALLOC unsigned char seed[48], nonce[NONCELEN];
	TEMPALLOC unsigned char esig[ZKNOX_CRYPTO_BYTES_EPERVIER - sizeof nonce - 2];
	TEMPALLOC inner_shake256_context sc;
	size_t u, v, sig_len, s2_len;
	int ret;

	/*
	 * Reject lengths that do not fit in a size_t.
	 */
	if (mlen > MAX_MLEN) {
		return -1;
	}
	ret = -1;

	/*
	 * Decode the private key.
	 */
	if (sk[0] != 0x50 + 9) {
		goto cleanup;
	}
	u = 1;
	v = Zf(trim_i8_decode)(f, 9, Zf(max_fg_bits)[9],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		goto cleanup;
	}
	u += v;
	v = Zf(trim_i8_decode)(g, 9, Zf(max_fg_bits)[9],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		goto cleanup;
	}
	u += v;
	v = Zf(trim_i8_decode)(F, 9, Zf(max_FG_bits)[9],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		goto cleanup;
	}
	u += v;
	if (u != CRYPTO_SECRETKEYBYTES) {
		goto cleanup;
	}
	if (!Zf(complete_private)(G, f, g, F, 9, tmp.b)) {
		goto cleanup;
	}

	/*
	 * Create a random nonce (40 bytes).
	 */
	if (randombytes(nonce, sizeof nonce) != 0) {
		goto cleanup;
	}

	/*
	 * Hash message nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, nonce, sizeof nonce);
	inner_shake256_inject(&sc, m, (size_t)mlen);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, r.hm, 9);


	/*
	 * Initialize a RNG.
	 */
	if (randombytes(seed, sizeof seed) != 0) {
		goto cleanup;
	}
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, seed, sizeof seed);
	inner_shake256_flip(&sc);


	/*
	 * Compute the signature.
	 * s2 must be invertible.
	 */
 
	do {
		Zf(sign_dyn)(s2, &sc, f, g, F, G, r.hm, 9, tmp.b);
		memcpy(s1, tmp.b, 512 * sizeof *s1);
	} while (!Zf(is_invertible)(s2, 9, tmp.b));

	/*
	 * Encode the signature and bundle it with the message. Format is:
	 *   signature length     2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   s1			          slen bytes
	 *   s2			          slen bytes
	 */

	esig[0] = 0x20 + 9;
	sig_len = Zf(comp_encode16)(esig + 1, 1024, s1, 9);
	if (sig_len == 0) {
		goto cleanup;
	}
	sig_len ++;
	esig[sig_len] = 0x20 + 9;
	s2_len = Zf(comp_encode16)(esig + sig_len + 1, 1024, s2, 9);
	if (s2_len == 0) {
		goto cleanup;
	}
	sig_len += s2_len;
	sig_len ++;

	// hint computation for Solidity: uint16_t = 2 bytes
	hint = Zf(hint_epervier)(s2, 9);
	sig_len +=2;

	memmove(sm + 2 + sizeof nonce, m, (size_t)mlen);
	sm[0] = (unsigned char)(sig_len >> 8);
	sm[1] = (unsigned char)sig_len;
	memcpy(sm + 2, nonce, sizeof nonce);
	memcpy(sm + 2 + (sizeof nonce) + (size_t)mlen, esig, sig_len-2);
	sm[2 + (sizeof nonce) + (size_t)mlen + sig_len-2] = (unsigned char)(hint >> 8);
	sm[2 + (sizeof nonce) + (size_t)mlen + sig_len-1] = (unsigned char)hint;
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
	Zf(secure_zero)(seed, sizeof seed);
	Zf(secure_zero)(&sc, sizeof sc);
	return ret;
}

int
zknox_crypto_sign_open_epervier(unsigned char *m, unsigned long long *mlen,
	const unsigned char *sm, unsigned long long smlen,
	const unsigned char *pk)
{
	// NB: this function does not utilize the hint.
	// The hint is useful for the Solidity version.
	TEMPALLOC union {
		uint8_t b[2 * 512];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	const unsigned char *esig;
	TEMPALLOC uint16_t h[512], h2[512], hm[512];
	TEMPALLOC int16_t s1[512], s2[512];
	TEMPALLOC inner_shake256_context sc;
	size_t sig_len, msg_len;

	/*
	 * Reject lengths that do not fit in a size_t.
	 */
	if (smlen > (unsigned long long)SIZE_MAX) {
		return -1;
	}

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + 9) {
		return -1;
	}
	if (Zf(modq_decode16)(h, 9, pk + 1, ZKNOX_CRYPTO_PUBLICKEYBYTES - 1)
		!= ZKNOX_CRYPTO_PUBLICKEYBYTES - 1)
	{
		return -1;
	}

	/*
	 * Find nonce, signature, message length.
	 */
	 if (smlen < 2 + NONCELEN) {
		return -1;
	}
	sig_len = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (sig_len > (smlen - 2 - NONCELEN)) {
		return -1;
	}
	msg_len = smlen - 2 - NONCELEN - sig_len;
	/*
	 * Decode signature.
	 */
	/*
	 * The signature has a fixed length: header + s1, header + s2, and
	 * the 2-byte hint. Check it before reading esig[].
	 */
	if (sig_len != EPERVIER_SIG_LEN) {
		return -1;
	}
	esig = sm + 2 + NONCELEN + msg_len;
	if (esig[0] != 0x20 + 9 || esig[1025] != 0x20 + 9) {
		return -1;
	}

	if (Zf(comp_decode16)(s1, 9,
		esig + 1, 1024) != 1024)
	{
		return -1;
	}
	if (Zf(comp_decode16)(s2, 9,
		esig+1+1024+1, 1024) != 1024)
	{
		return -1;
	}
	
	/*
	 * Hash nonce +	 message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, sm + 2, NONCELEN + msg_len);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, hm, 9);

	if (!Zf(verify_recover_epervier)(h2, hm, s1, s2, 9, tmp.b)) {
		return -1;
	}
	// We check that the recovered public key matches with the input pk.
	// In epervier, we would implement pk = H(NTT(h)) in order to have a smaller pk.
	// Zf(to_ntt_monty)(h2, 9);
	for (uint16_t i = 0 ; i < 512 ; i++){
		if (h[i] != h2[i]) {
			return -1;
		}
	}

	/*
	 * Return plaintext.
	 */
	memmove(m, sm + 2 + NONCELEN, msg_len);
	*mlen = msg_len;
	return 0;
}
