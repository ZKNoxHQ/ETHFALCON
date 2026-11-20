// test_zknox_falcon.mjs -- cross-checks the noble signer against the C signer.
//
//   cd falcon/noble && npm ci && npm test
//
// 1. keygen(seed48) == zknox_crypto_sign_keypair_from_seed(seed48)   (falcon.js, WASM)
// 2. the seed-length blocker: 32-byte seeds are accepted by C, rejected by noble
// 3. secret keys from C (any seed length) sign with noble and verify in C
// 4. noble signatures verify in C, C signatures verify in JS, tampering is rejected
// 5. same seed + same randombytes() stream => byte-identical signed message
//    (native build of nist16.c with fixed_rng_harness.c; skipped without gcc)
// 6. the C vector of test/falconKATS.t.sol (test_kats_vector0_from_c) verifies
// 7. public key NIST <-> ZKNOX conversions round-trip and match noble
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { falcon512 } from '@noble/post-quantum/falcon.js';
import { shake256 } from '@noble/hashes/sha3.js';
import * as zf from './zknox_falcon.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const c = await require(join(here, '..', 'falcon.js'))();

const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const eq = (a, b) => a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
const enc = (s) => new TextEncoder().encode(s);
let failures = 0;
const check = (name, ok) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok) failures++;
};
const rand = (tag, len) => shake256(enc(tag), { dkLen: len });

// --- falcon.js (WASM) wrappers ------------------------------------------------
const PK = zf.PUBLICKEY_BYTES, SK = zf.SECRETKEY_BYTES;
function cKeygen(seed) {
  const pk = c._malloc(PK), sk = c._malloc(SK), sp = c._malloc(seed.length);
  c.HEAPU8.set(seed, sp);
  const r = c._zknox_crypto_sign_keypair_from_seed(pk, sk, sp, seed.length);
  const out = r === 0 ? { publicKey: c.HEAPU8.slice(pk, pk + PK), secretKey: c.HEAPU8.slice(sk, sk + SK) } : null;
  c.HEAPU8.fill(0, sk, sk + SK);
  [pk, sk, sp].forEach((p) => c._free(p));
  return out;
}
const readU64 = (p) => Number((BigInt(c.HEAPU32[(p >> 2) + 1]) << 32n) | BigInt(c.HEAPU32[p >> 2]));
function cSign(msg, secretKey) {
  const mp = c._malloc(msg.length || 1), skp = c._malloc(SK);
  const smp = c._malloc(2 + 40 + msg.length + 1067), lp = c._malloc(8);
  c.HEAPU8.set(msg, mp);
  c.HEAPU8.set(secretKey, skp);
  const r = c._zknox_crypto_sign(smp, lp, mp, BigInt(msg.length), skp);
  const sm = r === 0 ? c.HEAPU8.slice(smp, smp + readU64(lp)) : null;
  c.HEAPU8.fill(0, skp, skp + SK);
  [mp, skp, smp, lp].forEach((p) => c._free(p));
  return sm;
}
function cOpen(sm, publicKey) {
  const smp = c._malloc(sm.length), pkp = c._malloc(PK), mp = c._malloc(sm.length), lp = c._malloc(8);
  c.HEAPU8.set(sm, smp);
  c.HEAPU8.set(publicKey, pkp);
  const r = c._zknox_crypto_sign_open(mp, lp, smp, BigInt(sm.length), pkp);
  const msg = r === 0 ? c.HEAPU8.slice(mp, mp + readU64(lp)) : null;
  [smp, pkp, mp, lp].forEach((p) => c._free(p));
  return msg;
}

// --- 1. same keys for 48-byte seeds -------------------------------------------
{
  let same = 0;
  const n = 20;
  for (let i = 0; i < n; i++) {
    const seed = rand(`seed ${i}`, 48);
    const C = cKeygen(seed);
    const J = zf.keygen(seed);
    if (eq(C.publicKey, J.publicKey) && eq(C.secretKey, J.secretKey)) same++;
  }
  check(`keygen: ${same}/${n} 48-byte seeds give byte-identical (pk, sk) in C and noble`, same === n);
}

// --- 2. the blocker: seed length ----------------------------------------------
{
  const seed32 = unhex('deadbeef'.repeat(8)); // the seed used by falcon/test_falcon.js
  const C = cKeygen(seed32);
  check('seed: C accepts the 32-byte seed of test_falcon.js', C !== null);
  let msg = '';
  try {
    falcon512.keygen(seed32);
  } catch (e) {
    msg = e.message;
  }
  check(`seed: noble falcon512.keygen rejects it (${msg})`, msg !== '');
  // No 48-byte input reproduces it: the C seed is absorbed whole by SHAKE256.
  const zeroPad = Uint8Array.from([...seed32, ...new Uint8Array(16)]);
  check('seed: zero-padding the seed to 48 bytes gives a different key', !eq(zf.keygen(zeroPad).secretKey, C.secretKey));
  let threw = false;
  try {
    zf.keygen(seed32);
  } catch {
    threw = true;
  }
  check('seed: zknox_falcon.keygen refuses non-48-byte seeds with an explicit error', threw);

  // Migration: the C secret key itself is fully usable by noble.
  check('seed: getPublicKey(C secret key) == C public key', eq(zf.getPublicKey(C.secretKey), C.publicKey));
  const m = enc('legacy key, signed by noble');
  const sm = zf.sign(m, C.secretKey);
  check('seed: noble signs with the C secret key from a 32-byte seed, C verifies', eq(cOpen(sm, C.publicKey) ?? [], m));
}

// --- 4. cross verification ----------------------------------------------------
{
  const { publicKey, secretKey } = zf.keygen(rand('cross', 48));
  const msgs = [new Uint8Array(0), enc('hello from ZKNOX!'), rand('long msg', 777)];
  let nobleInC = 0, cInJs = 0, rejected = 0;
  for (const m of msgs) {
    const sm = zf.sign(m, secretKey);
    if (eq(cOpen(sm, publicKey) ?? [1], m)) nobleInC++;
    const smC = cSign(m, secretKey);
    if (eq(zf.open(smC, publicKey), m) && zf.verify(smC, publicKey)) cInJs++;
    for (const [s, idx] of [[sm, 2], [sm, 42], [sm, sm.length - 1], [smC, sm.length - 700]]) {
      const bad = s.slice();
      bad[idx] ^= 1;
      if (cOpen(bad, publicKey) === null && !zf.verify(bad, publicKey)) rejected++;
    }
  }
  check(`verify: ${nobleInC}/${msgs.length} noble signatures accepted by C zknox_crypto_sign_open`, nobleInC === msgs.length);
  check(`verify: ${cInJs}/${msgs.length} C signatures accepted by JS open/verify`, cInJs === msgs.length);
  check(`verify: ${rejected}/${4 * msgs.length} tampered signed messages rejected by both`, rejected === 4 * msgs.length);
  const sm1 = zf.sign(msgs[1], secretKey), sm2 = zf.sign(msgs[1], secretKey);
  check('sign: fresh salt per signature', !eq(sm1.subarray(2, 42), sm2.subarray(2, 42)));
  check('sign: signed message length is 2 + 40 + mlen + 1025', sm1.length === 2 + 40 + msgs[1].length + 1025);
}

// --- 5. byte-identical signatures with a fixed randombytes() stream ------------
{
  let gcc = true;
  try {
    execFileSync('gcc', ['--version'], { stdio: 'ignore' });
  } catch {
    gcc = false;
  }
  if (!gcc) console.log('SKIP  native fixed-RNG comparison (gcc not found)');
  else {
    const src = join(here, '..', 'nistfalcon', 'src');
    const bin = join(here, 'build', 'fixed_rng_harness');
    mkdirSync(join(here, 'build'), { recursive: true });
    const files = ['codec', 'common', 'fft', 'fpr', 'keygen', 'rng', 'shake', 'sign', 'vrfy', 'keccak_prng', 'keccak256', 'nist16'];
    execFileSync('gcc', ['-O2', '-w', `-I${src}`, join(here, 'fixed_rng_harness.c'), ...files.map((f) => join(src, `${f}.c`)), '-o', bin]);
    let same = 0;
    const n = 10;
    for (let i = 0; i < n; i++) {
      const seed = rand(`det seed ${i}`, 48);
      const stream = rand(`det rng ${i}`, 40 + 48); // salt, then sampler seed
      const msg = rand(`det msg ${i}`, 1 + 37 * i);
      const out = Object.fromEntries(
        execFileSync(bin, [hex(seed), hex(stream), hex(msg)]).toString().trim().split('\n').map((l) => l.split('='))
      );
      let pos = 0;
      const random = (len) => stream.slice(pos, (pos += len));
      const { publicKey, secretKey } = zf.keygen(seed);
      const sm = zf.sign(msg, secretKey, { random });
      if (out.pk === hex(publicKey) && out.sk === hex(secretKey) && out.sm === hex(sm)) same++;
    }
    check(`sign: ${same}/${n} signed messages byte-identical to the native C signer (same seed, same RNG stream)`, same === n);
  }
}

// --- 6. repo vector: test/falconKATS.t.sol::test_kats_vector0_from_c -----------
{
  const sol = join(here, '..', '..', 'test', 'falconKATS.t.sol');
  if (!existsSync(sol)) console.log('SKIP  falconKATS.t.sol not found');
  else {
    const body = readFileSync(sol, 'utf8').split('function test_kats_vector0_from_c')[1];
    const pk = unhex(body.match(/bytes memory pk=hex"([0-9a-fA-F]+)"/)[1]);
    const sm = unhex(body.match(/bytes memory sm=hex"([0-9a-fA-F]+)"/)[1]);
    let msg = null;
    try {
      msg = zf.open(sm, pk);
    } catch {}
    check(`kat: C vector of falconKATS.t.sol verifies in JS (message ${msg ? msg.length : '-'} bytes)`, msg !== null && msg.length === 33);
    const sol0 = zf.toSolidity(sm, pk);
    check('kat: toSolidity gives 32-word s2 / ntth and a 40-byte salt', sol0.s2.length === 32 && sol0.ntth.length === 32 && sol0.salt.length === 40);
  }
}

// --- 7. public key conversions ------------------------------------------------
{
  const { publicKey: nistPk, secretKey } = falcon512.keygen(rand('conv', 48));
  const zk = zf.nistPublicKeyToZknox(nistPk);
  check('pk: NIST -> ZKNOX -> NIST round-trips', eq(zf.zknoxPublicKeyToNist(zk), nistPk));
  check('pk: ZKNOX key equals the C encoding (getPublicKey)', eq(zk, zf.getPublicKey(secretKey)));
}

console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exitCode = failures ? 1 : 0;
