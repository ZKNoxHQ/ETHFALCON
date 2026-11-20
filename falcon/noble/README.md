# Noble signer for ETHFALCON

`zknox_falcon.mjs` is a FALCON-512 signer built on
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) (`falcon512`). It replaces
the Emscripten build of the C signer (`falcon/falcon.js`, built from `nistfalcon/src/nist16.c`). It
produces the same keys, the same byte formats and the same signatures as the C signer, and the
on-chain `ZKNOX_falcon` verifier accepts them as they are.

```js
import { keygen, sign, open, verify, toSolidity } from './zknox_falcon.mjs';

const { publicKey, secretKey } = keygen(seed48); // seed optional; if given, exactly 48 bytes
const sm = sign(msg, secretKey);                 // sig_len || salt || msg || 0x29 || s2
open(sm, publicKey);                             // -> msg, throws 'invalid signature'
const { message, salt, s2, ntth } = toSolidity(sm, publicKey); // ZKNOX_falcon.verify(message, salt, s2, ntth)
```

| | C / `falcon.js` | `zknox_falcon.mjs` |
|---|---|---|
| keygen (random) | `zknox_crypto_sign_keypair`, 48-byte seed from the OS | `keygen()`, 48-byte seed from the CSPRNG |
| keygen (seeded) | `zknox_crypto_sign_keypair_from_seed`, any seed of **32 bytes or more** | `keygen(seed)`, seed of **exactly 48 bytes** |
| public key | 1025 B: `0x09 ‖ NTT(h)[i]` (BE16) | same |
| secret key | 1281 B NIST encoding `0x59 ‖ f ‖ g ‖ F` | same (interchangeable) |
| signed message | `sig_len(2) ‖ salt(40) ‖ msg ‖ 0x29 ‖ s2[i] mod q (BE16)` | same |
| hash-to-point | SHAKE256 (the build has no `-DETHFALCON`) | SHAKE256 |

## The keygen seed mismatch

The seed mismatch is real, but it is narrower than a different derivation.

**The derivation is the same.** Both implementations absorb the seed into SHAKE256 and run the
same round-3 reference key generation on that stream:

* C (`nist16.c`): `inner_shake256_inject(&rng, seed, seedlen); flip; Zf(keygen)(&rng, ...)`
* noble (`falcon.ts`): `new NTRU(logn, seed)` → `shake256.create().update(seed)`, a port of the same keygen

For a 48-byte seed the keys are byte-identical: 200 out of 200 seeds in a dedicated run, plus 20
in `test_zknox_falcon.mjs`.

**What blocks is the seed length.**

* C accepts any `seedlen >= 32`. `falcon/test_falcon.js` uses a 32-byte seed.
* noble's `falcon512.keygen(seed)` calls `abytes(seed, 48)` and rejects every other length:
  `"seed" expected Uint8Array of length 48, got length=32`.
* No workaround exists in noble's public API. C absorbs the *whole* seed into SHAKE256, so a key
  derived from a 32-byte seed is `keygen(SHAKE256(seed32))`. No 48-byte input reproduces that
  stream (zero-padding, for example, gives a different key; this is tested). noble's `NTRU` class,
  which would take any length, is not exported.

**Who is affected:** only keys created with `zknox_crypto_sign_keypair_from_seed` and a seed that
is not 48 bytes long. These keys are not affected:

* keys from `zknox_crypto_sign_keypair`, which already draws 48 bytes;
* keys that were stored as the 1281-byte secret key.

### Ways forward

1. **Use 48-byte seeds (recommended).** If seeds are derived from a 32-byte master secret, derive
   48 bytes instead, for example `shake256(master, { dkLen: 48 })` or HKDF. C and noble then give
   the same key. This is a new key compared with the old 32-byte derivation.
2. **Existing keys from 32-byte seeds: import the secret key.** Derive the 1281-byte secret key
   once with the C signer. noble signs with it directly, and `getPublicKey(sk)` returns the same
   ZKNOX public key. Both are tested. `keygen()` refuses other seed lengths with an error that
   points here, rather than silently returning a different key.
3. **Upstream (not done here):** ask noble to relax `abytes(seed, 48)` to `seed.length >= 32` in
   the falcon keygen. Nothing else in noble depends on the length. This would give full C seed
   compatibility.
4. **Align the C API (not done here):** make `zknox_crypto_sign_keypair_from_seed` require
   `seedlen == 48`, so that no new non-portable keys can be created. This is a breaking change on
   recently audited code, so it is left to the maintainers.

## What the wrapper does on top of noble

* **Public key:** noble returns the NIST 897-byte key (14-bit packed `h`). The wrapper applies the
  same NTT as `mq_NTT` (`vrfy.c`) and writes the 512 words as BE16.
  `zknoxPublicKeyToNist` / `nistPublicKeyToZknox` convert in both directions.
* **Signature:** noble's detached output is `0x39 ‖ salt ‖ compressed s2`. The wrapper
  decompresses s2 (strict Algorithm 18) and re-encodes it as `comp_encode16` does, with the
  `nist16.c` attached layout.
* **Signing randomness:** noble asks for 40 bytes (salt) then 48 bytes (sampler seed), in the same
  order as the two `randombytes()` calls in `zknox_crypto_sign`. With the same key and the same
  stream, the noble and C signed messages are byte-identical: 10 out of 10 against a native build
  with a replayed RNG (`fixed_rng_harness.c`). Use `sign(msg, sk, { random })` to drive it.
* **Verification:** `open` / `verify` re-implement `zknox_crypto_sign_open` in JS: SHAKE256
  hash-to-point, NTT product with the stored `NTT(h)`, and the `l2bound` norm check. noble's
  `verify` cannot take a key that is already in the NTT domain.
* **Solidity:** `toSolidity(sm, pk)` returns the `ZKNOX_falcon.verify(h, salt, s2, ntth)` arguments
  (`_ZKNOX_NTT_Compact` packing).

## Limitations

* **NIST (SHAKE256) FALCON only, the same as `falcon.js`.** noble has no hook for the Keccak
  hash-to-point of ETHFALCON. It also never exposes `s1`, which EPERVIER needs. These variants
  would need the C/WASM signer or changes in noble.
* **Retry difference.** noble retries signing when the compressed s2 would be too long. C does not
  retry, because its 16-bit encoding has no such limit. Every noble signature is still a valid C
  signature. The case is too rare to change the output in practice.
* **Speed** (Node 22, one core): noble keygen takes about 130 ms (WASM about 13 ms). Signing takes
  about 4 ms (WASM about 3.4 ms). JS verification takes about 0.13 ms.

## Tests

```bash
cd falcon/noble
npm ci
npm test                       # cross-checks against ../falcon.js and a native C build (needs gcc)
node gen_solidity_vectors.mjs  # regenerates ../../test/noble_falcon_vectors.json
forge test --match-contract NobleSigner_Test   # from the repo root: on-chain verification
```

`npm test` covers:

* identical keys for 48-byte seeds, and the 32-byte seed blocker;
* signing with a secret key that C derived from a 32-byte seed;
* noble signatures accepted by C `zknox_crypto_sign_open`, and C signatures accepted by JS;
* tampered messages rejected by both;
* byte-identical signatures against native C with a fixed RNG;
* the C vector from `test/falconKATS.t.sol`;
* public-key conversions.
