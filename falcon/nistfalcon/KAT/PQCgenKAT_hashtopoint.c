
//
//  PQCgenKAT_hashtopoint.c
//
//  Created by Simon Masson
//  Copyright © 2026 ZKNOX. All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "katrng.h"
#include "api.h"
#include "inner.h"

#define MAX_MARKER_LEN 50
#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

int FindMarker(FILE *infile, const char *marker);
int ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

char AlgName[] = "My Alg Name";

#define STR(x) STR_(x)
#define STR_(x) #x

int main()
{
#ifdef ALGNAME
    char *fn_req, *fn_rsp;
#else
    char fn_req[32], fn_rsp[32];
#endif
    FILE *fp_req, *fp_rsp;
    unsigned char *m;
    unsigned long long mlen;
    int count;
    int done;
    int ret_val;

    /*
     * Temporary buffers made static to save space on constrained
     * systems (e.g. ARM Cortex M4).
     */
    static unsigned char seed[48];
    static unsigned char entropy_input[48];
    static unsigned char msg[3300];
    // randombytes modifies the nonce
    static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    static unsigned char nonce[40]; // NONCELEN=40
    static inner_shake256_context sc;
    static uint16_t hm[512];

    // Create the REQUEST file
#ifdef ALGNAME
    fn_req = "PQChashtopointKAT_" STR(ALGNAME) ".req";
#else
    sprintf(fn_req, "PQChashtopointKAT_%d.req", CRYPTO_SECRETKEYBYTES);
#endif
    if ((fp_req = fopen(fn_req, "w")) == NULL)
    {
        printf("Couldn't open <%s> for write\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
#ifdef ALGNAME
    fn_rsp = "PQChashtopointKAT_" STR(ALGNAME) ".rsp";
#else
    sprintf(fn_rsp, "PQChashtopointKAT_%d.rsp", CRYPTO_SECRETKEYBYTES);
#endif
    if ((fp_rsp = fopen(fn_rsp, "w")) == NULL)
    {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    for (int i = 0; i < 48; i++)
        entropy_input[i] = i;

    randombytes_init(entropy_input, NULL, 256);
    for (int i = 0; i < 100; i++)
    {
        fprintf(fp_req, "count = %d\n", i);
        randombytes(seed, 48);
        fprintBstr(fp_req, "seed = ", seed, 48);
        mlen = 33 * (i + 1);
        fprintf(fp_req, "mlen = %llu\n", mlen);
        randombytes(msg, mlen);
        fprintBstr(fp_req, "msg = ", msg, mlen);
        fprintf(fp_req, "salt = \n");
        fprintf(fp_req, "hash =\n\n");
    }
    fclose(fp_req);

    // Create the RESPONSE file based on what's in the REQUEST file
    if ((fp_req = fopen(fn_req, "r")) == NULL)
    {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }

    fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);
    done = 0;
    do
    {
        if (FindMarker(fp_req, "count = "))
        {
            if (fscanf(fp_req, "%d", &count) != 1)
            {
                abort();
            }
        }
        else
        {
            done = 1;
            break;
        }
        fprintf(fp_rsp, "count = %d\n", count);

        if (!ReadHex(fp_req, seed, 48, "seed = "))
        {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "seed = ", seed, 48);

        randombytes_init(seed, NULL, 256);

        if (FindMarker(fp_req, "mlen = "))
        {
            if (fscanf(fp_req, "%llu", &mlen) != 1)
            {
                abort();
            }
        }
        else
        {
            printf("ERROR: unable to read 'mlen' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintf(fp_rsp, "mlen = %llu\n", mlen);

        m = (unsigned char *)calloc(mlen, sizeof(unsigned char));

        if (!ReadHex(fp_req, m, (int)mlen, "msg = "))
        {
            printf("ERROR: unable to read 'msg' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "msg = ", m, mlen);

        // Generate the public/private keypair so that randombytes has the same behavior as in the tests of signature
        if ((ret_val = crypto_sign_keypair(pk, sk)) != 0)
        {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        // Compute the hashtopoint
        /*
         * Create a random nonce (40 bytes).
         */
        randombytes(nonce, sizeof nonce);

        /*
         * Hash message nonce + message into a vector.
         */
        inner_shake256_init(&sc);
        inner_shake256_inject(&sc, nonce, sizeof nonce);
        inner_shake256_inject(&sc, m, mlen);
        inner_shake256_flip(&sc);
        Zf(hash_to_point_vartime)(&sc, hm, 9);

        fprintf(fp_rsp, "salt = ");
        for (size_t i = 0; i < sizeof nonce; i++)
        {
            fprintf(fp_rsp, "%02X", nonce[i]);
        }
        fprintf(fp_rsp, "\n");
        fprintf(fp_rsp, "hash = [");
        for (int i = 0; i < 512; i++)
        {
            fprintf(fp_rsp, "%u, ", hm[i]);
        }
        fprintf(fp_rsp, "]\n\n");
        free(m);

    } while (!done);

    fclose(fp_req);
    fclose(fp_rsp);

    return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int FindMarker(FILE *infile, const char *marker)
{
    char line[MAX_MARKER_LEN];
    int i, len;
    int curr_line;

    len = (int)strlen(marker);
    if (len > MAX_MARKER_LEN - 1)
        len = MAX_MARKER_LEN - 1;

    for (i = 0; i < len; i++)
    {
        curr_line = fgetc(infile);
        line[i] = curr_line;
        if (curr_line == EOF)
            return 0;
    }
    line[len] = '\0';

    while (1)
    {
        if (!strncmp(line, marker, len))
            return 1;

        for (i = 0; i < len - 1; i++)
            line[i] = line[i + 1];
        curr_line = fgetc(infile);
        line[len - 1] = curr_line;
        if (curr_line == EOF)
            return 0;
        line[len] = '\0';
    }

    // shouldn't get here
    return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
    int i, ch, started;
    unsigned char ich;

    if (Length == 0)
    {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;
    if (FindMarker(infile, str))
        while ((ch = fgetc(infile)) != EOF)
        {
            if (!isxdigit(ch))
            {
                if (!started)
                {
                    if (ch == '\n')
                        break;
                    else
                        continue;
                }
                else
                    break;
            }
            started = 1;
            if ((ch >= '0') && (ch <= '9'))
                ich = ch - '0';
            else if ((ch >= 'A') && (ch <= 'F'))
                ich = ch - 'A' + 10;
            else if ((ch >= 'a') && (ch <= 'f'))
                ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;

            for (i = 0; i < Length - 1; i++)
                A[i] = (A[i] << 4) | (A[i + 1] >> 4);
            A[Length - 1] = (A[Length - 1] << 4) | ich;
        }
    else
        return 0;

    return 1;
}

void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
    unsigned long long i;

    fprintf(fp, "%s", S);

    for (i = 0; i < L; i++)
        fprintf(fp, "%02X", A[i]);

    if (L == 0)
        fprintf(fp, "00");

    fprintf(fp, "\n");
}
