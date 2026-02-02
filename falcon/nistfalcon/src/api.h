#define CRYPTO_SECRETKEYBYTES 1281
#define CRYPTO_PUBLICKEYBYTES 897
#define ZKNOX_CRYPTO_PUBLICKEYBYTES 1025

#define CRYPTO_BYTES 690
#define ZKNOX_CRYPTO_BYTES 1067			 // 2 +     (1024 + 1) + 40     for header, s2, salt
#define ZKNOX_CRYPTO_BYTES_EPERVIER 2094 // 2 + 2 * (1024 + 1) + 40 + 2 for header, s1,s2,salt, hint
#define CRYPTO_ALGNAME "Falcon-512"

// FALCON
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
				const unsigned char *m, unsigned long long mlen,
				const unsigned char *sk);

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
					 const unsigned char *sm, unsigned long long smlen,
					 const unsigned char *pk);

// ZKNOX FALCON
int zknox_crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int zknox_crypto_sign(unsigned char *sm, unsigned long long *smlen,
					  const unsigned char *m, unsigned long long mlen,
					  const unsigned char *sk);

int zknox_crypto_sign_open(unsigned char *m, unsigned long long *mlen,
						   const unsigned char *sm, unsigned long long smlen,
						   const unsigned char *pk);

// ZKNOX EPERVIER
int zknox_pk_epervier(unsigned char *pk);

int zknox_crypto_sign_epervier(unsigned char *sm, unsigned long long *smlen,
							   const unsigned char *m, unsigned long long mlen,
							   const unsigned char *sk);

int zknox_crypto_sign_open_epervier(unsigned char *m, unsigned long long *mlen,
									const unsigned char *sm, unsigned long long smlen,
									const unsigned char *pk);
