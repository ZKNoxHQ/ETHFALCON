#!/usr/bin/env python3
# gen_falcon1024_vectors.py -- Falcon-1024 verifier vectors for test/falcon1024.t.sol
#
#   python3 pythonref/gen_falcon1024_vectors.py
#
# 1. the 100 NIST round-3 KAT vectors of test/falcon1024-KAT.rsp (sha256 036a0bf5...,
#    Falcon-Round3.zip, vendored by @noble/post-quantum) decoded to the verifier's
#    inputs: salt, message, s2 mod q compacted, ntth = NTT(h) compacted;
# 2. random (salt, message, s2, ntth) with the exact squared norm the verifier must
#    compute, from an independent scalar model (hashlib SHAKE256, scalar NTT loops).
# Writes test/falcon1024_vectors.json. jsref/check_falcon1024_kat.mjs re-verifies the
# same KAT triples with noble's falcon1024.verify.
import hashlib
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from encoding import decompress  # noqa: E402
from model_ntt1024 import ref_fw, ref_inv  # noqa: E402

q, N = 12289, 1024
BOUND = 70265242
HERE = os.path.dirname(os.path.abspath(__file__))
RSP = os.path.join(HERE, "..", "test", "falcon1024-KAT.rsp")
OUT = os.path.join(HERE, "..", "test", "falcon1024_vectors.json")
KAT_SHA256 = "036a0bf5260573cec44977284dfef756cd1143db9961b981bd1fb55828acb20d"


def parse_rsp(path):
    vecs, cur = [], {}
    for line in open(path):
        line = line.strip()
        if " = " in line:
            k, v = line.split(" = ", 1)
            if k == "count" and cur:
                vecs.append(cur)
                cur = {}
            cur[k] = v
    if cur:
        vecs.append(cur)
    return vecs


def decode_pk(pk):
    assert pk[0] == 0x0A, "Falcon-1024 public key header"
    assert len(pk) == 1 + (N * 14 + 7) // 8
    bits = int.from_bytes(pk[1:], "big")
    total = (len(pk) - 1) * 8
    h = [(bits >> (total - 14 * (i + 1))) & 0x3FFF for i in range(N)]
    assert all(x < q for x in h)
    return h


def decode_sm(sm, mlen):
    slen = (sm[0] << 8) | sm[1]
    salt = sm[2:42]
    msg = sm[42 : 42 + mlen]
    esig = sm[42 + mlen :]
    assert slen == len(esig), (slen, len(esig))
    assert esig[0] == 0x2A, "Falcon-1024 compressed signature header"
    s2 = decompress(esig[1:], len(esig) - 1, N)
    assert s2 is not False
    return salt, msg, s2


def hash_to_point(salt, msg):
    out, need = [], 1
    while True:
        stream = hashlib.shake_256(salt + msg).digest(2 * 4096 * need)
        out = []
        for j in range(0, len(stream), 2):
            t = (stream[j] << 8) | stream[j + 1]
            if t < 5 * q:
                out.append(t % q)
                if len(out) == N:
                    return out
        need += 1


def centred_sq(x):
    x %= q
    return x * x if x <= q // 2 else (q - x) * (q - x)


def norm(salt, msg, s2, ntth):
    """s2 and ntth as canonical / raw 16-bit lists"""
    s1 = ref_inv([a * (b % q) % q for a, b in zip(ref_fw(s2), ntth)])
    h = hash_to_point(salt, msg)
    return sum(centred_sq(x) for x in s2) + sum(centred_sq(a - b) for a, b in zip(h, s1))


def compact(p):
    return ["0x" + format(sum(p[16 * c + i] << (16 * i) for i in range(16)), "064x") for c in range(64)]


def main():
    assert hashlib.sha256(open(RSP, "rb").read()).hexdigest() == KAT_SHA256
    kat = []
    for v in parse_rsp(RSP):
        pk = bytes.fromhex(v["pk"])
        sm = bytes.fromhex(v["sm"])
        mlen = int(v["mlen"])
        salt, msg, s2 = decode_sm(sm, mlen)
        assert msg == bytes.fromhex(v["msg"])
        h = decode_pk(pk)
        s2q = [x % q for x in s2]
        ntth = ref_fw(h)
        nrm = norm(salt, msg, s2q, ntth)
        assert nrm <= BOUND, (v["count"], nrm)
        kat.append(
            {
                "count": int(v["count"]),
                "msg": "0x" + msg.hex(),
                "salt": "0x" + salt.hex(),
                "s2": compact(s2q),
                "ntth": compact(ntth),
                "norm": nrm,
                "pk": "0x" + pk.hex(),
                "sig": "0x" + bytes([0x3A]).hex() + salt.hex() + sm[43 + mlen :].hex(),
            }
        )
    print(f"{len(kat)} KAT vectors decoded, all norms <= {BOUND}, max {max(k['norm'] for k in kat)}")

    rng = random.Random(0x1024)
    rnd = []
    for i in range(12):
        salt = bytes(rng.randrange(256) for _ in range(40))
        msg = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 32, 95, 96, 200])))
        amp = [0, 3, 200, 6144, 6144, 6144, 100, 1, 50, 6144, 2000, 6144][i]
        s2 = [rng.randrange(-amp, amp + 1) % q for _ in range(N)]
        if i == 4:
            s2 = [6144 if j & 1 else 6145 for j in range(N)]  # both centring edges
        ntth = [rng.randrange(1 << 16) if i % 3 == 0 else rng.randrange(q) for _ in range(N)]
        if i == 5:
            ntth = [0xFFFF] * N
        rnd.append({"msg": "0x" + msg.hex(), "salt": "0x" + salt.hex(), "s2": compact(s2), "ntth": compact(ntth), "norm": norm(salt, msg, s2, ntth)})
    json.dump({"kat_source": "falcon1024-KAT.rsp (NIST round 3)", "bound": BOUND, "kat": kat, "random": rnd}, open(OUT, "w"), indent=1)
    print(f"{len(rnd)} random cases, wrote {os.path.relpath(OUT)}")


if __name__ == "__main__":
    main()
