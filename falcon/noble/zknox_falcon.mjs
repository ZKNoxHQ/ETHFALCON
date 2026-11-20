// zknox_falcon.mjs -- FALCON-512 signer for ETHFALCON built on @noble/post-quantum.
//
// Drop-in replacement for the Emscripten build of the C signer (falcon/falcon.js,
// nistfalcon/src/nist16.c): same keys, same byte formats, same signing algorithm.
//
//   publicKey  1025 bytes  0x09 || NTT(h)[i] as 512 big-endian 16-bit words
//   secretKey  1281 bytes  standard NIST round-3 encoding 0x59 || f || g || F
//   signed msg            sig_len (2 bytes BE, = 1025) || salt (40) || msg || 0x29 || s2[i] mod q (512 x BE16)
//
// Keys and signatures produced here are byte-identical to the C ones for the same
// inputs (see test_zknox_falcon.mjs). Only the NIST (SHAKE256) hash-to-point is
// supported: noble does not expose a hook for the Keccak hash-to-point of ETHFALCON,
// nor s1 for EPERVIER, so this replaces falcon.js (built without -DETHFALCON) only.
//
// Key generation seed: MUST be 48 bytes. The C binding absorbs the whole seed into
// SHAKE256 and accepts any length >= 32, noble only accepts 48 bytes. For a 48-byte
// seed both give the same key; for any other length no 48-byte seed reproduces the
// C key. See README.md.

import { falcon512 } from '@noble/post-quantum/falcon.js';
import { shake256 } from '@noble/hashes/sha3.js';

const Q = 12289;
const N = 512;
const LOGN = 9;
const L2BOUND = 34034726; // l2bound[9], common.c
const NONCE_BYTES = 40;
const PK_HEADER = 0x00 + LOGN;
const ESIG_HEADER = 0x20 + LOGN;
const DETACHED_HEADER = 0x30 + LOGN; // noble detached signature header
const N_INV = 12265; // 512^-1 mod q

export const SEED_BYTES = 48;
export const PUBLICKEY_BYTES = 1 + 2 * N; // 1025, ZKNOX_CRYPTO_PUBLICKEYBYTES
export const NIST_PUBLICKEY_BYTES = 1 + (14 * N) / 8; // 897, CRYPTO_PUBLICKEYBYTES
export const SECRETKEY_BYTES = 1281; // CRYPTO_SECRETKEYBYTES
export const ESIG_BYTES = 1 + 2 * N; // 1025: header + s2
export { NONCE_BYTES };

// ---------------------------------------------------------------------------
// NTT mod q, same transform as mq_NTT / mq_iNTT in vrfy.c, in plain (non-Montgomery)
// representation: W[k] = 7^rev10(k), IW[k] = 7^-rev10(k) mod q.

const modpow = (b, e) => {
  let r = 1;
  b %= Q;
  for (; e > 0; e >>= 1, b = (b * b) % Q) if (e & 1) r = (r * b) % Q;
  return r;
};
const rev10 = (k) => {
  let r = 0;
  for (let i = 0; i < 10; i++) r |= ((k >> i) & 1) << (9 - i);
  return r;
};
const W = new Uint16Array(N);
const IW = new Uint16Array(N);
for (let k = 0; k < N; k++) {
  W[k] = modpow(7, rev10(k));
  IW[k] = modpow(7, 2048 - rev10(k));
}

/** Forward NTT (in place) of a polynomial with coefficients in [0, q). */
export function ntt(a) {
  let t = N;
  for (let m = 1; m < N; m <<= 1) {
    const ht = t >> 1;
    for (let i = 0, j1 = 0; i < m; i++, j1 += t) {
      const s = W[m + i];
      for (let j = j1; j < j1 + ht; j++) {
        const u = a[j];
        const v = (a[j + ht] * s) % Q;
        a[j] = (u + v) % Q;
        a[j + ht] = (u - v + Q) % Q;
      }
    }
    t = ht;
  }
  return a;
}

/** Inverse NTT (in place). */
export function intt(a) {
  let t = 1;
  for (let m = N; m > 1; m >>= 1) {
    const hm = m >> 1;
    const dt = t << 1;
    for (let i = 0, j1 = 0; i < hm; i++, j1 += dt) {
      const s = IW[hm + i];
      for (let j = j1; j < j1 + t; j++) {
        const u = a[j];
        const v = a[j + t];
        a[j] = (u + v) % Q;
        a[j + t] = (((u - v + Q) % Q) * s) % Q;
      }
    }
    t = dt;
  }
  for (let i = 0; i < N; i++) a[i] = (a[i] * N_INV) % Q;
  return a;
}

// ---------------------------------------------------------------------------
// Encodings (codec.c)

const abytes = (b, len, name) => {
  if (!(b instanceof Uint8Array)) throw new TypeError(`"${name}" expected Uint8Array`);
  if (len !== undefined && b.length !== len)
    throw new Error(`"${name}" expected ${len} bytes, got ${b.length}`);
};

// modq_decode (14-bit, NIST public key body)
function decode14(buf) {
  const x = new Uint16Array(N);
  let acc = 0;
  let accLen = 0;
  let v = 0;
  for (let u = 0; u < N; ) {
    acc = ((acc << 8) | buf[v++]) & 0xffffff;
    accLen += 8;
    if (accLen >= 14) {
      accLen -= 14;
      const w = (acc >>> accLen) & 0x3fff;
      if (w >= Q) throw new Error('public key coefficient >= q');
      x[u++] = w;
    }
  }
  if (acc & ((1 << accLen) - 1)) throw new Error('non-zero padding in public key');
  return x;
}

// modq_encode (14-bit)
function encode14(x) {
  const out = new Uint8Array((14 * N) / 8);
  let acc = 0;
  let accLen = 0;
  let o = 0;
  for (let u = 0; u < N; u++) {
    acc = ((acc << 14) | x[u]) & 0x3fffff;
    accLen += 14;
    while (accLen >= 8) {
      accLen -= 8;
      out[o++] = (acc >>> accLen) & 0xff;
    }
  }
  return out;
}

// modq_decode16: 512 big-endian words, each < q
function decode16modq(buf) {
  const x = new Uint16Array(N);
  for (let u = 0; u < N; u++) {
    const w = (buf[2 * u] << 8) | buf[2 * u + 1];
    if (w >= Q) throw new Error('coefficient >= q');
    x[u] = w;
  }
  return x;
}

function encode16(x) {
  const out = new Uint8Array(2 * N);
  for (let u = 0; u < N; u++) {
    out[2 * u] = x[u] >> 8;
    out[2 * u + 1] = x[u] & 0xff;
  }
  return out;
}

// comp_encode16: s2[i] mod q as BE16, only -6144..6144 round-trips
function compEncode16(s) {
  const w = new Uint16Array(N);
  for (let u = 0; u < N; u++) {
    if (s[u] > 6144 || s[u] < -6144) throw new Error('s2 coefficient out of range');
    w[u] = s[u] < 0 ? s[u] + Q : s[u];
  }
  return encode16(w);
}

// comp_decode16: canonical words (< q), centred at q/2
function compDecode16(buf) {
  const w = decode16modq(buf);
  const s = new Int16Array(N);
  for (let u = 0; u < N; u++) s[u] = w[u] > 6144 ? w[u] - Q : w[u];
  return s;
}

// comp_decode: Falcon compressed s2 (Algorithm 18), strict. Used to unpack noble's output.
function compDecode(buf) {
  const x = new Int16Array(N);
  let acc = 0;
  let accLen = 0;
  let v = 0;
  for (let u = 0; u < N; u++) {
    if (v >= buf.length) throw new Error('truncated compressed s2');
    acc = ((acc << 8) | buf[v++]) & 0xffffff;
    const b = acc >>> accLen;
    const sign = b & 128;
    let m = b & 127;
    for (;;) {
      if (accLen === 0) {
        if (v >= buf.length) throw new Error('truncated compressed s2');
        acc = ((acc << 8) | buf[v++]) & 0xffffff;
        accLen = 8;
      }
      accLen--;
      if ((acc >>> accLen) & 1) break;
      m += 128;
      if (m > 2047) throw new Error('compressed s2 coefficient too large');
    }
    if (sign && m === 0) throw new Error('"-0" in compressed s2');
    x[u] = sign ? -m : m;
  }
  if (acc & ((1 << accLen) - 1)) throw new Error('non-zero padding in compressed s2');
  if (v !== buf.length) throw new Error('trailing bytes after compressed s2');
  return x;
}

// ---------------------------------------------------------------------------
// Public key conversions

/** NIST 897-byte public key (0x09 || h, 14-bit packed) -> ZKNOX 1025-byte key (0x09 || NTT(h)). */
export function nistPublicKeyToZknox(pk) {
  abytes(pk, NIST_PUBLICKEY_BYTES, 'publicKey');
  if (pk[0] !== PK_HEADER) throw new Error('bad public key header');
  const h = ntt(decode14(pk.subarray(1)));
  const out = new Uint8Array(PUBLICKEY_BYTES);
  out[0] = PK_HEADER;
  out.set(encode16(h), 1);
  return out;
}

/** ZKNOX 1025-byte public key -> NIST 897-byte public key (usable with noble's falcon512.verify). */
export function zknoxPublicKeyToNist(pk) {
  abytes(pk, PUBLICKEY_BYTES, 'publicKey');
  if (pk[0] !== PK_HEADER) throw new Error('bad public key header');
  const h = intt(decode16modq(pk.subarray(1)));
  const out = new Uint8Array(NIST_PUBLICKEY_BYTES);
  out[0] = PK_HEADER;
  out.set(encode14(h), 1);
  return out;
}

// ---------------------------------------------------------------------------
// Signer API (mirrors zknox_crypto_sign_keypair[_from_seed] / zknox_crypto_sign / zknox_crypto_sign_open)

/**
 * Generate a key pair. Without a seed, draws a fresh 48-byte seed from the CSPRNG
 * (as zknox_crypto_sign_keypair). With a seed, it must be exactly 48 bytes; the
 * result equals zknox_crypto_sign_keypair_from_seed(seed, 48).
 * @returns {{ publicKey: Uint8Array, secretKey: Uint8Array }} ZKNOX public key (1025 B), secret key (1281 B)
 */
export function keygen(seed) {
  if (seed !== undefined) {
    abytes(seed, undefined, 'seed');
    if (seed.length !== SEED_BYTES)
      throw new Error(
        `seed must be exactly ${SEED_BYTES} bytes, got ${seed.length}: noble only accepts 48-byte ` +
          'seeds, and the C binding hashes the whole seed (SHAKE256), so a key derived by ' +
          'zknox_crypto_sign_keypair_from_seed from a seed of another length cannot be re-derived ' +
          'here. Import its 1281-byte secret key instead (see falcon/noble/README.md).'
      );
  }
  const { publicKey, secretKey } = falcon512.keygen(seed);
  return { publicKey: nistPublicKeyToZknox(publicKey), secretKey };
}

/** ZKNOX public key (1025 B) of a secret key. */
export function getPublicKey(secretKey) {
  abytes(secretKey, SECRETKEY_BYTES, 'secretKey');
  return nistPublicKeyToZknox(falcon512.getPublicKey(secretKey));
}

/**
 * Sign a message. Output has the zknox_crypto_sign layout:
 *   sig_len (2 BE) || salt (40) || msg || 0x29 || s2 (512 x BE16 mod q)
 * @param {Uint8Array} msg raw message (it is hashed with the salt, do not pre-hash)
 * @param {Uint8Array} secretKey 1281-byte secret key (from keygen or from the C signer)
 * @param {object} [opts] forwarded to noble: { random } is a (len) => Uint8Array hook called
 *   with 40 (salt) then 48 (sampler seed), in the same order as the C randombytes() calls;
 *   { extraEntropy } as in noble. Default: CSPRNG.
 */
export function sign(msg, secretKey, opts = {}) {
  abytes(msg, undefined, 'msg');
  abytes(secretKey, SECRETKEY_BYTES, 'secretKey');
  const sig = falcon512.sign(msg, secretKey, opts); // 0x39 || salt || compressed s2
  if (sig[0] !== DETACHED_HEADER) throw new Error('unexpected noble signature header');
  const salt = sig.subarray(1, 1 + NONCE_BYTES);
  const s2 = compDecode(sig.subarray(1 + NONCE_BYTES));
  const sm = new Uint8Array(2 + NONCE_BYTES + msg.length + ESIG_BYTES);
  sm[0] = ESIG_BYTES >> 8;
  sm[1] = ESIG_BYTES & 0xff;
  sm.set(salt, 2);
  sm.set(msg, 2 + NONCE_BYTES);
  sm[2 + NONCE_BYTES + msg.length] = ESIG_HEADER;
  sm.set(compEncode16(s2), 3 + NONCE_BYTES + msg.length);
  return sm;
}

/** Split a signed message into { salt, message, s2 } (strict, as zknox_crypto_sign_open). */
export function parseSignedMessage(sm) {
  abytes(sm, undefined, 'signedMessage');
  if (sm.length < 2 + NONCE_BYTES) throw new Error('signed message too short');
  const sigLen = (sm[0] << 8) | sm[1];
  if (sigLen > sm.length - 2 - NONCE_BYTES) throw new Error('bad signature length');
  if (sigLen !== ESIG_BYTES) throw new Error('bad signature length');
  const msgLen = sm.length - 2 - NONCE_BYTES - sigLen;
  const esig = sm.subarray(2 + NONCE_BYTES + msgLen);
  if (esig[0] !== ESIG_HEADER) throw new Error('bad signature header');
  return {
    salt: sm.slice(2, 2 + NONCE_BYTES),
    message: sm.slice(2 + NONCE_BYTES, 2 + NONCE_BYTES + msgLen),
    s2: compDecode16(esig.subarray(1)),
  };
}

// hash_to_point_vartime (NIST): SHAKE256(salt || msg), 16-bit BE samples < 5q, reduced mod q
function hashToPoint(salt, msg) {
  const xof = shake256.create().update(salt).update(msg);
  const c = new Uint16Array(N);
  let u = 0;
  while (u < N) {
    const buf = xof.xof(2 * (N - u));
    for (let i = 0; i < buf.length && u < N; i += 2) {
      const w = (buf[i] << 8) | buf[i + 1];
      if (w < 5 * Q) c[u++] = w % Q;
    }
  }
  return c;
}

// verify_raw with the key already in the NTT domain
function verifyRaw(c, s2, ntth) {
  const t = new Uint16Array(N);
  for (let u = 0; u < N; u++) t[u] = s2[u] < 0 ? s2[u] + Q : s2[u];
  ntt(t);
  for (let u = 0; u < N; u++) t[u] = (t[u] * ntth[u]) % Q;
  intt(t);
  let norm = 0;
  for (let u = 0; u < N; u++) {
    let w = (t[u] - c[u] + Q) % Q; // -s1
    if (w > Q >> 1) w -= Q;
    norm += w * w + s2[u] * s2[u];
  }
  return norm <= L2BOUND;
}

/**
 * Verify a signed message and return the message (as zknox_crypto_sign_open).
 * Throws 'invalid signature' on any failure.
 */
export function open(sm, publicKey) {
  abytes(sm, undefined, 'signedMessage');
  abytes(publicKey, undefined, 'publicKey');
  try {
    if (publicKey.length !== PUBLICKEY_BYTES || publicKey[0] !== PK_HEADER)
      throw new Error('bad public key');
    const ntth = decode16modq(publicKey.subarray(1));
    const { salt, message, s2 } = parseSignedMessage(sm);
    if (!verifyRaw(hashToPoint(salt, message), s2, ntth)) throw new Error('norm too large');
    return message;
  } catch (cause) {
    throw new Error('invalid signature', { cause });
  }
}

/** Boolean form of open(). */
export function verify(sm, publicKey) {
  try {
    open(sm, publicKey);
    return true;
  } catch (e) {
    if (e instanceof TypeError) throw e;
    return false;
  }
}

// ---------------------------------------------------------------------------
// Solidity helpers

/** _ZKNOX_NTT_Compact: 512 16-bit coefficients -> 32 uint256 words (coefficient i at bits 16*(i%16) of word i/16). */
export function compact(coeffs) {
  if (coeffs.length !== N) throw new Error('expected 512 coefficients');
  const words = new Array(32).fill(0n);
  for (let i = 0; i < N; i++) words[i >> 4] |= BigInt(coeffs[i] & 0xffff) << BigInt(16 * (i & 15));
  return words;
}

/**
 * Arguments of ZKNOX_falcon.verify(bytes h, bytes salt, uint256[] s2, uint256[] ntth)
 * for a signed message and a ZKNOX public key.
 */
export function toSolidity(sm, publicKey) {
  abytes(publicKey, PUBLICKEY_BYTES, 'publicKey');
  const { salt, message, s2 } = parseSignedMessage(sm);
  const s2w = Uint16Array.from(s2, (x) => (x < 0 ? x + Q : x));
  return {
    message,
    salt,
    s2: compact(s2w),
    ntth: compact(decode16modq(publicKey.subarray(1))),
  };
}
