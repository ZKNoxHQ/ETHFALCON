/*
 * randombytes() backed by the operating system CSPRNG.
 *
 * This file replaces katrng.c (the NIST KAT AES-256-CTR-DRBG) in every
 * build that produces real keys and signatures: the WASM module
 * (falcon.js) and the Go library (libfalcon.a). katrng.c must only be
 * linked into the KAT generator binaries, which seed it explicitly with
 * randombytes_init(); it must never be linked together with this file.
 *
 * Sources:
 *   - Emscripten: getentropy(), which Emscripten maps to WASI random_get,
 *     i.e. crypto.getRandomValues() in browsers and in Node.js (or
 *     crypto.randomFillSync() on old Node.js). If no CSPRNG is
 *     available, the JavaScript runtime throws: the call aborts, it never
 *     returns predictable bytes.
 *   - Linux: getrandom(2), blocking until the kernel pool is initialised,
 *     retried on EINTR and on short reads.
 *   - macOS / BSD: getentropy(), at most 256 bytes per call.
 *
 * There is no fallback: on failure the output buffer is cleared and a
 * non-zero value is returned, and callers must abort the operation.
 */

#if defined(__linux__) && !defined(__EMSCRIPTEN__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif
#if (defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) \
	|| defined(__NetBSD__) || defined(__DragonFly__)) && !defined(_BSD_SOURCE)
#define _BSD_SOURCE
#endif

#include <stddef.h>
#include <string.h>
#include <errno.h>

#if defined(__EMSCRIPTEN__)
#include <unistd.h>
#define RB_USE_GETENTROPY 1
#elif defined(__linux__)
#include <sys/types.h>
#include <sys/random.h>
#define RB_USE_GETRANDOM 1
#elif defined(__APPLE__)
#include <unistd.h>
#include <sys/random.h>
#define RB_USE_GETENTROPY 1
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) \
	|| defined(__DragonFly__)
#include <unistd.h>
#define RB_USE_GETENTROPY 1
#else
#error "randombytes_os.c: no OS CSPRNG known for this platform"
#endif

#define RB_SUCCESS   0
#define RB_FAILURE  -1

/*
 * getentropy() is limited to 256 bytes per call.
 */
#define RB_GETENTROPY_MAX 256

/*
 * Fill x[0..xlen-1] with bytes from the OS CSPRNG. Returns 0 on success,
 * -1 on failure (in which case x[] is cleared).
 */
int
randombytes(unsigned char *x, unsigned long long xlen)
{
	unsigned char *p;
	size_t len;

	if (xlen == 0) {
		return RB_SUCCESS;
	}
	if (x == NULL || xlen > (unsigned long long)(size_t)-1) {
		return RB_FAILURE;
	}
	p = x;
	len = (size_t)xlen;
	while (len > 0) {
#if defined(RB_USE_GETRANDOM)
		ssize_t r;
		size_t chunk;

		chunk = len < 33554431 ? len : 33554431;
		r = getrandom(p, chunk, 0);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			memset(x, 0, (size_t)xlen);
			return RB_FAILURE;
		}
		if (r == 0 || (size_t)r > chunk) {
			memset(x, 0, (size_t)xlen);
			return RB_FAILURE;
		}
		p += (size_t)r;
		len -= (size_t)r;
#else
		size_t chunk;

		chunk = len < RB_GETENTROPY_MAX ? len : RB_GETENTROPY_MAX;
		if (getentropy(p, chunk) != 0) {
			memset(x, 0, (size_t)xlen);
			return RB_FAILURE;
		}
		p += chunk;
		len -= chunk;
#endif
	}
	return RB_SUCCESS;
}
