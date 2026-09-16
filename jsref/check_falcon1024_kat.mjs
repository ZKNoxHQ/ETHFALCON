// check_falcon1024_kat.mjs -- re-verifies the KAT triples of test/falcon1024_vectors.json
// with @noble/post-quantum falcon1024.verify (detached form 0x3A || salt || compressed s2),
// and checks that a one-bit change in the message is rejected.
//
//   cd jsref && npm ci && node check_falcon1024_kat.mjs
import { falcon1024 } from '@noble/post-quantum/falcon.js';
import { readFileSync } from 'node:fs';

const hex = (s) => Uint8Array.from(Buffer.from(s.slice(2), 'hex'));
const { kat } = JSON.parse(readFileSync(new URL('../test/falcon1024_vectors.json', import.meta.url)));
let ok = 0;
for (const v of kat) {
  const pk = hex(v.pk), sig = hex(v.sig), msg = hex(v.msg);
  if (!falcon1024.verify(sig, msg, pk)) throw new Error(`noble rejects KAT ${v.count}`);
  const bad = msg.slice();
  bad[0] ^= 1;
  if (falcon1024.verify(sig, bad, pk)) throw new Error(`noble accepts tampered KAT ${v.count}`);
  ok++;
}
console.log(`noble falcon1024.verify: ${ok}/${kat.length} KAT accepted, tampered messages rejected`);
