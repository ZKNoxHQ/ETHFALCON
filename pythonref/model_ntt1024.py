#!/usr/bin/env python3
# model_ntt1024.py -- lane-by-lane replay of the schedule emitted by gen_ntt1024.py
# (Falcon-1024), checked against a scalar reference and against the vectors of
# @noble/post-quantum in test/ntt1024_vectors.json (jsref/gen_ntt1024_vectors.mjs).
#
#   python3 pythonref/model_ntt1024.py
#
# Every REDC asserts lane locality (x + m q < 2^32) and every lane is checked
# against the maxima printed by `gen_ntt1024.py --schedule`.
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_ntt1024 as G  # noqa: E402

q, N, R = G.q, G.N, G.R
FWK, INVK, INV512 = G.FWK, G.INVK, G.SCHED["inv512"]
LOG = dict(G.SCHED["log"])


def redc(x):
    assert 0 <= x < 1 << 32
    m = ((x & 0xFFFF) * G.QINV) & 0xFFFF
    s = x + m * q
    assert s < 1 << 32, "REDC not lane-local"
    return s >> 16


def barrett(x):
    qh = (x * 21) >> 18
    assert qh < 32 and x * 21 < 1 << 32
    return x - qh * q


def condq(x):
    assert x < 2 * q
    return x - q if x >= q else x


def cond4(x):
    assert x < 8 * q
    return x - 4 * q if x >= 4 * q else x


def ref_fw(a):
    a, t, m = a[:], N, 1
    while m < N:
        t >>= 1
        for i in range(m):
            S = G.FW[m + i]
            for j in range(2 * i * t, 2 * i * t + t):
                U, V = a[j], a[j + t] * S % q
                a[j], a[j + t] = (U + V) % q, (U - V) % q
        m <<= 1
    return a


def ref_inv(a):
    a, t, m = a[:], 1, N
    while m > 1:
        h = m >> 1
        for i in range(h):
            S = G.INV[h + i]
            for j in range(2 * i * t, 2 * i * t + t):
                U, V = a[j], a[j + t]
                a[j], a[j + t] = (U + V) % q, (U - V) * S % q
        t <<= 1
        m >>= 1
    return [x * G.NINV % q for x in a]


def fw_model(a, track):
    """the lane operations of falconNTT1024, one layer at a time"""
    a = a[:]
    t, m, layer = N, 1, 0
    while m < N:
        t >>= 1
        if t == 4:
            a = [barrett(x) for x in a]
            track("fw Barrett before t=4", a)
        k = FWK[layer]
        for i in range(m):
            S = G.FWM[m + i]
            for j in range(2 * i * t, 2 * i * t + t):
                r = redc(a[j + t] * S)
                assert r <= k * q
                a[j], a[j + t] = a[j] + r, a[j] + k * q - r
        track(f"fw t={t} bias {k}q", a)
        m <<= 1
        layer += 1
    a = [barrett(x) for x in a]
    track("fw Barrett final", a)
    return [condq(x) for x in a]


def inv_model(a, track):
    a = a[:]
    t, m, layer = 1, N, 0
    while m > 2:
        h = m >> 1
        k, red = INVK[layer]
        for i in range(h):
            S = G.INVM[h + i]
            for j in range(2 * i * t, 2 * i * t + t):
                U, V = a[j], a[j + t]
                assert U + k * q - V > 0
                s = U + V
                a[j], a[j + t] = cond4(s) if red else s, redc((U + k * q - V) * S)
        track(f"inv t={t} bias {k}q{' sums -4q' if red else ''}", a)
        t <<= 1
        m >>= 1
        layer += 1
    out = a[:]
    for j in range(N // 2):
        U, V = a[j], a[j + N // 2]
        out[j] = redc((U + V) * G.CN)
        out[j + N // 2] = redc((U + INV512 * q - V) * G.DN)
    track(f"inv t=512 bias {INV512}q, x 1/1024", out)
    out = [barrett(x) for x in out]
    track("inv Barrett final", out)
    return [condq(x) for x in out]


def tracker(seen):
    def f(name, a):
        mx = max(a)
        assert mx <= LOG[name], f"{name}: lane {mx} above the generator bound {LOG[name]}"
        seen[name] = max(seen.get(name, 0), mx)

    return f


def unpack(words):
    return [(int(words[i >> 4], 16) >> (16 * (i & 15))) & 0xFFFF for i in range(N)]


def main():
    seen = {}
    tr = tracker(seen)
    here = os.path.dirname(os.path.abspath(__file__))
    vec = json.load(open(os.path.join(here, "..", "test", "ntt1024_vectors.json")))
    for v in vec["vectors"]:
        a = unpack(v["a"])
        assert fw_model(a, tr) == ref_fw(a) == unpack(v["ntt"]), v["name"]
        assert inv_model(a, tr) == ref_inv(a) == unpack(v["intt"]), v["name"]
    print(f"{len(vec['vectors'])} vectors of {vec['source']}: model == scalar reference == noble")
    rng = random.Random(1024)
    for _ in range(20):
        a = [rng.randrange(q) for _ in range(N)]
        assert fw_model(a, tr) == ref_fw(a)
        assert inv_model(a, tr) == ref_inv(a)
        assert inv_model(fw_model(a, tr), tr) == a
    print("20 random polynomials: model == scalar reference, round trip")
    for name, m in G.SCHED["log"]:
        if name in seen:
            print(f"{name:<30} bound {m:>7}  reached {seen[name]:>7}")


if __name__ == "__main__":
    main()
