/*
 * Regression tests for the ZKNOX C signer (falcon/nistfalcon/src).
 *
 * Built twice by the Makefile:
 *   build/test_zknox      SHAKE256 hash-to-point (FALCON, as falcon.js)
 *   build/test_zknox_eth  Keccak-CTR hash-to-point (-DETHFALCON)
 * Both link randombytes_os.c (OS CSPRNG), never katrng.c.
 *
 * Covered:
 *   - randombytes() is not constant; seedless keygen and signing draw
 *     fresh randomness (audit C-1);
 *   - comp_encode16()/comp_decode16() round-trip on -6144..+6144 and
 *     reject non-canonical words (audit M-1);
 *   - the Keccak PRNG absorbs any input length and matches a Python
 *     reference (pycryptodome) beyond the old 4096-byte cap; a
 *     long-message ETHFALCON signature verifies and is not valid for
 *     the empty message (audit M-2);
 *   - zknox_pk_epervier() keeps the NTT key unchanged; EPERVIER
 *     sign/open round-trips and open rejects any other signature
 *     length (audit M-3, L-7).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "inner.h"

int randombytes(unsigned char *x, unsigned long long xlen);

static int failures = 0;

#define CHECK(cond, msg) do { \
		if (cond) { \
			printf("  ok    %s\n", msg); \
		} else { \
			printf("  FAIL  %s (%s:%d)\n", msg, __FILE__, __LINE__); \
			failures ++; \
		} \
	} while (0)

#define NONCELEN 40

/* ==================================================================== */
/* C-1: randomness */

static void
test_randomness(void)
{
	unsigned char a[64], b[64];
	unsigned char pk1[ZKNOX_CRYPTO_PUBLICKEYBYTES], sk1[CRYPTO_SECRETKEYBYTES];
	unsigned char pk2[ZKNOX_CRYPTO_PUBLICKEYBYTES], sk2[CRYPTO_SECRETKEYBYTES];
	unsigned char msg[32];
	unsigned char sm1[sizeof msg + ZKNOX_CRYPTO_BYTES];
	unsigned char sm2[sizeof msg + ZKNOX_CRYPTO_BYTES];
	unsigned char m1[sizeof sm1];
	unsigned long long smlen1, smlen2, mlen1;

	printf("C-1 randomness\n");
	memset(a, 0, sizeof a);
	memset(b, 0, sizeof b);
	CHECK(randombytes(a, sizeof a) == 0 && randombytes(b, sizeof b) == 0,
		"randombytes() succeeds");
	CHECK(memcmp(a, b, sizeof a) != 0, "two randombytes() calls differ");
	CHECK(randombytes(a, 0) == 0, "randombytes() accepts length 0");

	CHECK(zknox_crypto_sign_keypair(pk1, sk1) == 0
		&& zknox_crypto_sign_keypair(pk2, sk2) == 0,
		"seedless keygen succeeds");
	CHECK(memcmp(sk1, sk2, sizeof sk1) != 0, "seedless keygen gives fresh keys");

	memset(msg, 0x42, sizeof msg);
	CHECK(zknox_crypto_sign(sm1, &smlen1, msg, sizeof msg, sk1) == 0
		&& zknox_crypto_sign(sm2, &smlen2, msg, sizeof msg, sk1) == 0,
		"signing succeeds");
	CHECK(memcmp(sm1 + 2, sm2 + 2, NONCELEN) != 0,
		"same key and message: salts differ");
	CHECK(smlen1 != smlen2 || memcmp(sm1, sm2, (size_t)smlen1) != 0,
		"same key and message: signatures differ");
	CHECK(zknox_crypto_sign_open(m1, &mlen1, sm1, smlen1, pk1) == 0
		&& zknox_crypto_sign_open(m1, &mlen1, sm2, smlen2, pk1) == 0,
		"both signatures verify");
}

/* ==================================================================== */
/* M-1: 16-bit signature codec */

static void
put16(unsigned char *p, unsigned w)
{
	p[0] = (unsigned char)(w >> 8);
	p[1] = (unsigned char)w;
}

static void
test_codec16(void)
{
	int16_t x[512], y[512];
	unsigned char buf[1024];
	int v, ok;
	size_t u;

	printf("M-1 comp_encode16 / comp_decode16\n");

	/* Round-trip every value in -6144..+6144. */
	ok = 1;
	for (v = -6144; v <= 6144; v += 512) {
		for (u = 0; u < 512; u ++) {
			int z = v + (int)u;
			x[u] = (int16_t)(z > 6144 ? 6144 : z);
		}
		if (Zf(comp_encode16)(buf, sizeof buf, x, 9) != 1024
			|| Zf(comp_decode16)(y, 9, buf, sizeof buf) != 1024
			|| memcmp(x, y, sizeof x) != 0)
		{
			ok = 0;
		}
	}
	CHECK(ok, "round-trip for all coefficients in -6144..6144");

	/* Spot values around the centring threshold. */
	memset(x, 0, sizeof x);
	x[0] = 3000; x[1] = -3000; x[2] = 2047; x[3] = 6144; x[4] = -6144;
	x[5] = -1; x[6] = 1;
	CHECK(Zf(comp_encode16)(buf, sizeof buf, x, 9) == 1024
		&& Zf(comp_decode16)(y, 9, buf, sizeof buf) == 1024
		&& memcmp(x, y, sizeof x) == 0,
		"round-trip for 3000, -3000, 2047, 6144, -6144, -1, 1");

	/* Encoder rejects values that would not round-trip. */
	memset(x, 0, sizeof x);
	x[7] = 6145;
	CHECK(Zf(comp_encode16)(buf, sizeof buf, x, 9) == 0, "encode rejects 6145");
	x[7] = -6145;
	CHECK(Zf(comp_encode16)(buf, sizeof buf, x, 9) == 0, "encode rejects -6145");

	/* Decoder centring at q/2. */
	memset(buf, 0, sizeof buf);
	put16(buf + 0, 6144);
	put16(buf + 2, 6145);
	put16(buf + 4, 12288);
	put16(buf + 6, 2047);
	CHECK(Zf(comp_decode16)(y, 9, buf, sizeof buf) == 1024
		&& y[0] == 6144 && y[1] == -6144 && y[2] == -1 && y[3] == 2047,
		"decode centres at q/2 (6144 -> 6144, 6145 -> -6144, 12288 -> -1)");

	/* Decoder rejects non-canonical words. */
	memset(buf, 0, sizeof buf);
	put16(buf + 10, 12289);
	CHECK(Zf(comp_decode16)(y, 9, buf, sizeof buf) == 0, "decode rejects 12289 (= q)");
	put16(buf + 10, 0x8000);
	CHECK(Zf(comp_decode16)(y, 9, buf, sizeof buf) == 0, "decode rejects 0x8000");
	put16(buf + 10, 0xFFFF);
	CHECK(Zf(comp_decode16)(y, 9, buf, sizeof buf) == 0, "decode rejects 0xFFFF");
	put16(buf + 10, 65536 - 5);
	CHECK(Zf(comp_decode16)(y, 9, buf, sizeof buf) == 0,
		"decode rejects two's complement -5 (0xFFFB)");
}

/*
 * A signature with a negative s2 coefficient re-encoded as 65536 + x
 * (instead of x + q) must be rejected by zknox_crypto_sign_open().
 */
static void
test_open_noncanonical(void)
{
	unsigned char pk[ZKNOX_CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
	unsigned char msg[48];
	unsigned char sm[sizeof msg + ZKNOX_CRYPTO_BYTES], m1[sizeof sm];
	unsigned long long smlen, mlen1;
	unsigned char *s2;
	size_t u;
	int found;

	printf("M-1 zknox_crypto_sign_open rejects non-canonical s2\n");
	memset(msg, 0x17, sizeof msg);
	if (zknox_crypto_sign_keypair(pk, sk) != 0
		|| zknox_crypto_sign(sm, &smlen, msg, sizeof msg, sk) != 0)
	{
		CHECK(0, "keygen and sign");
		return;
	}
	CHECK(zknox_crypto_sign_open(m1, &mlen1, sm, smlen, pk) == 0,
		"honest signature verifies");
	s2 = sm + 2 + NONCELEN + sizeof msg + 1;
	found = 0;
	for (u = 0; u < 512; u ++) {
		unsigned w = ((unsigned)s2[2 * u] << 8) | s2[2 * u + 1];
		if (w > 6144) {
			/* w = x + q with x < 0; write 65536 + x instead. */
			put16(s2 + 2 * u, (unsigned)(65536 - (12289 - w)));
			found = 1;
			break;
		}
	}
	CHECK(found, "signature has a negative coefficient");
	CHECK(zknox_crypto_sign_open(m1, &mlen1, sm, smlen, pk) != 0,
		"re-encoded (65536 + x) signature is rejected");
}

/* ==================================================================== */
/* M-2: Keccak PRNG without input cap */

static const unsigned char kat_4096[64] = {
	0xa4, 0xf1, 0x04, 0xb0, 0xe9, 0x33, 0xbb, 0x94, 0x2a, 0x93, 0x15, 0xa5,
	0xff, 0xdf, 0x0b, 0x9a, 0xca, 0x85, 0xe6, 0x62, 0xf8, 0xcd, 0x85, 0xf2,
	0x7e, 0xd2, 0x67, 0xb3, 0x20, 0xa3, 0xee, 0xa4, 0x40, 0xf6, 0x87, 0xca,
	0xaf, 0xea, 0x26, 0xb8, 0xd6, 0x69, 0x05, 0x1e, 0x11, 0x6e, 0xcd, 0xa4,
	0x1c, 0x93, 0x52, 0xf0, 0x71, 0xbe, 0xac, 0x99, 0x6c, 0x3b, 0xc9, 0x4a,
	0xa5, 0xe2, 0xc6, 0x0c
};
static const unsigned char kat_5000[64] = {
	0x8e, 0xb5, 0x68, 0x20, 0x31, 0x3d, 0x11, 0x27, 0x9c, 0x3b, 0xa7, 0xe7,
	0x22, 0x9e, 0x6f, 0xb0, 0xcd, 0x0e, 0xb1, 0x7a, 0x74, 0x8d, 0x69, 0xab,
	0x05, 0x2c, 0x87, 0xd4, 0x06, 0x27, 0xfb, 0x72, 0x01, 0x24, 0xca, 0x53,
	0xf6, 0x5b, 0x8b, 0xb6, 0x48, 0x60, 0x9d, 0xc8, 0x23, 0x05, 0x48, 0xdc,
	0xe4, 0xe3, 0xd4, 0x7e, 0x1c, 0x63, 0x91, 0xf4, 0x10, 0x65, 0x1e, 0x68,
	0x0b, 0xe6, 0x4a, 0x4e
};
static const unsigned char kat_70000[64] = {
	0x3b, 0xc9, 0x3c, 0xdb, 0xe1, 0x69, 0xb3, 0xd6, 0x20, 0xe1, 0x53, 0x40,
	0x0d, 0x75, 0xdc, 0x60, 0x5d, 0x3b, 0x73, 0xf3, 0x6d, 0xca, 0x9b, 0xe3,
	0x11, 0x4c, 0xba, 0x99, 0x9e, 0xd3, 0x6e, 0xe7, 0xfc, 0x6c, 0x79, 0xa6,
	0x40, 0x7f, 0x9d, 0xa3, 0x7e, 0x88, 0xbc, 0x0d, 0x12, 0xee, 0x4b, 0xed,
	0xcf, 0x4d, 0xc2, 0xce, 0x9b, 0xa1, 0xb4, 0xbb, 0x12, 0x7c, 0x1c, 0xe9,
	0xd6, 0xa3, 0xd4, 0x40
};

/*
 * Absorb data[0..len-1] in pieces of 'step' bytes (0: one inject), then
 * extract 64 bytes in uneven pieces.
 */
static int
keccak_prng_run(const unsigned char *data, size_t len, size_t step,
	unsigned char *out)
{
	inner_keccak256_prng_ctx kc;
	size_t off;

	if (inner_keccak256_init(&kc) != 0) {
		return -1;
	}
	if (step == 0) {
		step = len;
	}
	for (off = 0; off < len; off += step) {
		size_t n = (len - off) < step ? (len - off) : step;
		if (inner_keccak256_inject(&kc, data + off, n) != 0) {
			return -1;
		}
	}
	if (inner_keccak256_flip(&kc) != 0
		|| inner_keccak256_extract(&kc, out, 1) != 0
		|| inner_keccak256_extract(&kc, out + 1, 5) != 0
		|| inner_keccak256_extract(&kc, out + 6, 26) != 0
		|| inner_keccak256_extract(&kc, out + 32, 32) != 0)
	{
		return -1;
	}
	/* No inject after flip. */
	if (inner_keccak256_inject(&kc, data, 1) == 0) {
		return -1;
	}
	return 0;
}

static void
test_keccak_prng(void)
{
	unsigned char *data, out[64];
	size_t u;

	printf("M-2 Keccak PRNG absorbs any length\n");
	data = malloc(70000);
	if (data == NULL) {
		CHECK(0, "malloc");
		return;
	}
	for (u = 0; u < 70000; u ++) {
		data[u] = (unsigned char)(u * 7 + 3);
	}
	CHECK(keccak_prng_run(data, 4096, 0, out) == 0
		&& memcmp(out, kat_4096, 64) == 0,
		"4096-byte input matches reference");
	CHECK(keccak_prng_run(data, 5000, 0, out) == 0
		&& memcmp(out, kat_5000, 64) == 0,
		"5000-byte input matches reference (was rejected with -3)");
	CHECK(keccak_prng_run(data, 5000, 40, out) == 0
		&& memcmp(out, kat_5000, 64) == 0,
		"5000-byte input in 40-byte injects matches reference");
	CHECK(keccak_prng_run(data, 70000, 0, out) == 0
		&& memcmp(out, kat_70000, 64) == 0,
		"70000-byte input (> 16-bit length) matches reference");
	CHECK(keccak_prng_run(data, 70000, 137, out) == 0
		&& memcmp(out, kat_70000, 64) == 0,
		"70000-byte input in 137-byte injects matches reference");
	free(data);
}

/*
 * Sign a long message; it must verify, and the same salt and signature
 * must not verify for the empty message.
 */
static void
test_long_message(void)
{
	unsigned char pk[ZKNOX_CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
	size_t mlen = 5000;
	unsigned char *msg, *sm, *m1, *sm0;
	unsigned long long smlen, mlen1, smlen0;
	size_t sig_len, u;

#if ETHFALCON
	printf("M-2 long message (ETHFALCON, Keccak-CTR)\n");
#else
	printf("M-2 long message (FALCON, SHAKE256)\n");
#endif
	msg = malloc(mlen);
	sm = malloc(mlen + ZKNOX_CRYPTO_BYTES);
	m1 = malloc(mlen + ZKNOX_CRYPTO_BYTES);
	sm0 = malloc(ZKNOX_CRYPTO_BYTES);
	if (msg == NULL || sm == NULL || m1 == NULL || sm0 == NULL) {
		CHECK(0, "malloc");
		return;
	}
	for (u = 0; u < mlen; u ++) {
		msg[u] = (unsigned char)(u * 13 + 1);
	}
	CHECK(zknox_crypto_sign_keypair(pk, sk) == 0, "keygen");
	CHECK(zknox_crypto_sign(sm, &smlen, msg, mlen, sk) == 0,
		"sign a 5000-byte message");
	CHECK(zknox_crypto_sign_open(m1, &mlen1, sm, smlen, pk) == 0
		&& mlen1 == mlen && memcmp(m1, msg, mlen) == 0,
		"5000-byte signature verifies and returns the message");

	/* Same salt and signature, empty message. */
	sig_len = ((size_t)sm[0] << 8) | sm[1];
	memcpy(sm0, sm, 2 + NONCELEN);
	memcpy(sm0 + 2 + NONCELEN, sm + 2 + NONCELEN + mlen, sig_len);
	smlen0 = 2 + NONCELEN + sig_len;
	CHECK(zknox_crypto_sign_open(m1, &mlen1, sm0, smlen0, pk) != 0,
		"5000-byte signature does not verify for the empty message");

	/* Flip one message byte past the old 4096-byte cap. */
	sm[2 + NONCELEN + 4500] ^= 1;
	CHECK(zknox_crypto_sign_open(m1, &mlen1, sm, smlen, pk) != 0,
		"modified byte 4500 is detected");

	free(msg);
	free(sm);
	free(m1);
	free(sm0);
}

/* ==================================================================== */
/* M-3 / L-7: EPERVIER */

#if !ETHFALCON
static void
test_epervier(void)
{
	unsigned char pk[ZKNOX_CRYPTO_PUBLICKEYBYTES], pk2[ZKNOX_CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned char msg[33];
	unsigned char sm[sizeof msg + ZKNOX_CRYPTO_BYTES_EPERVIER];
	unsigned char m1[sizeof sm];
	unsigned char *shortsm;
	unsigned long long smlen, mlen1;

	printf("M-3 / L-7 EPERVIER\n");
	memset(msg, 0x5a, sizeof msg);
	CHECK(zknox_crypto_sign_keypair(pk, sk) == 0, "keygen");
	memcpy(pk2, pk, sizeof pk);
	CHECK(zknox_pk_epervier(pk2) == 0 && memcmp(pk, pk2, sizeof pk) == 0,
		"zknox_pk_epervier keeps the NTT key (no second NTT)");
	CHECK(zknox_crypto_sign_epervier(sm, &smlen, msg, sizeof msg, sk) == 0,
		"sign");
	CHECK(smlen == 2 + NONCELEN + sizeof msg + 2 * (1 + 1024) + 2,
		"signature length is 2 * 1025 + 2");
	CHECK(zknox_crypto_sign_open_epervier(m1, &mlen1, sm, smlen, pk) == 0
		&& mlen1 == sizeof msg && memcmp(m1, msg, sizeof msg) == 0,
		"signature verifies");

	/* sig_len field one byte too short: rejected. */
	sm[1] --;
	CHECK(zknox_crypto_sign_open_epervier(m1, &mlen1, sm, smlen, pk) != 0,
		"sig_len = 2051 is rejected");
	sm[1] ++;

	/*
	 * 43-byte input claiming a 1-byte signature: was read out of
	 * bounds. Allocated exactly so that ASan would catch a read.
	 */
	shortsm = malloc(43);
	if (shortsm != NULL) {
		memset(shortsm, 0, 43);
		shortsm[1] = 1;
		shortsm[42] = 0x20 + 9;
		CHECK(zknox_crypto_sign_open_epervier(m1, &mlen1, shortsm, 43, pk) != 0,
			"43-byte signed message is rejected");
		free(shortsm);
	}
}
#endif

int
main(void)
{
	test_randomness();
	test_codec16();
	test_open_noncanonical();
	test_keccak_prng();
	test_long_message();
#if !ETHFALCON
	test_epervier();
#endif
	if (failures != 0) {
		printf("%d check(s) FAILED\n", failures);
		return 1;
	}
	printf("all checks passed\n");
	return 0;
}
