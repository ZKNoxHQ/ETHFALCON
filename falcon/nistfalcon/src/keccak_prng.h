#include <stdint.h>
#include <string.h>
#include "keccak256.h"

#define KECCAK256_OUTPUT 32
#define MAX_BUFFER_SIZE 4096 // Adjust based on your needs

typedef struct
{
    uint8_t buffer[MAX_BUFFER_SIZE]; // Input buffer
    size_t buffer_len;               // Length of data in input buffer
    uint8_t state[KECCAK256_OUTPUT]; // Current state
    uint64_t counter;                // Output counter
    int finalized;                   // Flag indicating if state is finalized

    // New output buffer fields
    uint8_t out_buffer[KECCAK256_OUTPUT]; // Buffer for unused random bytes
    size_t out_buffer_pos;                // Current position in output buffer
    size_t out_buffer_len;                // Number of valid bytes in output buffer
} inner_keccak256_prng_ctx;

int inner_keccak256_init(inner_keccak256_prng_ctx *ctx);
int inner_keccak256_inject(inner_keccak256_prng_ctx *ctx, const uint8_t *data, size_t len);
int inner_keccak256_flip(inner_keccak256_prng_ctx *ctx);
int inner_keccak256_extract(inner_keccak256_prng_ctx *ctx, uint8_t *out, size_t outlen);
