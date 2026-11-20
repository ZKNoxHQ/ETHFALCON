// gen_solidity_vectors.mjs -- writes test/noble_falcon_vectors.json, signatures made by the
// noble signer and verified on-chain by test/nobleSigner.t.sol (ZKNOX_falcon.verify).
//
//   cd falcon/noble && node gen_solidity_vectors.mjs
//
// Deterministic: fixed 48-byte keygen seed and fixed salt / sampler-seed stream per vector,
// so re-running reproduces the file byte for byte (and the C signer, fed the same
// randombytes() stream, gives the same signatures: see test_zknox_falcon.mjs).
import { writeFileSync } from 'node:fs';
import { shake256 } from '@noble/hashes/sha3.js';
import * as zf from './zknox_falcon.mjs';

const enc = (s) => new TextEncoder().encode(s);
const hex = (b) => '0x' + Buffer.from(b).toString('hex');
const word = (w) => '0x' + w.toString(16).padStart(64, '0');

const seed = shake256(enc('ethfalcon noble vector seed'), { dkLen: zf.SEED_BYTES });
const { publicKey, secretKey } = zf.keygen(seed);
const messages = [
  new Uint8Array(0),
  enc('hello from ZKNOX!'),
  shake256(enc('ethfalcon noble vector msg 33'), { dkLen: 33 }),
  shake256(enc('ethfalcon noble vector msg 200'), { dkLen: 200 }),
];

const vectors = messages.map((msg, i) => {
  const stream = shake256(enc(`ethfalcon noble vector rng ${i}`), { dkLen: 40 + 48 });
  let pos = 0;
  const sm = zf.sign(msg, secretKey, { random: (len) => stream.slice(pos, (pos += len)) });
  if (!zf.verify(sm, publicKey)) throw new Error(`vector ${i} does not verify`);
  const { message, salt, s2, ntth } = zf.toSolidity(sm, publicKey);
  return { message: hex(message), salt: hex(salt), s2: s2.map(word), ntth: ntth.map(word), sm: hex(sm) };
});

const out = new URL('../../test/noble_falcon_vectors.json', import.meta.url);
writeFileSync(
  out,
  JSON.stringify(
    {
      generator: 'falcon/noble/gen_solidity_vectors.mjs (@noble/post-quantum falcon512, ZKNOX encoding)',
      seed: hex(seed),
      pk: hex(publicKey),
      vectors,
    },
    null,
    1
  ) + '\n'
);
console.log(`wrote ${vectors.length} vectors to ${out.pathname}`);
