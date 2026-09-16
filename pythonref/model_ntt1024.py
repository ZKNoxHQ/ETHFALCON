#!/usr/bin/env python3
# model_ntt1024.py -- replays, lane by lane on concrete values, the three schedules of
# pythonref/sched1024.py that gen_ntt1024.py emits (falconNTT1024, falconINTT1024,
# falconProduct1024), and checks
#   - every lane against the per-coefficient bound of the analysis after every step,
#   - every REDC for lane locality, every Barrett for its input range,
#   - the results against a scalar reference and against the @noble/post-quantum vectors of
#     test/ntt1024_vectors.json (jsref/gen_ntt1024_vectors.mjs).
#
#   python3 pythonref/model_ntt1024.py
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sched1024 as S  # noqa: E402

q, N, R = S.q, S.N, S.R


def redc(x):
    assert 0 <= x < 1 << 32
    m = ((x & 0xFFFF) * S.QINV) & 0xFFFF
    s = x + m * q
    assert s < 1 << 32, "REDC not lane-local"
    return s >> 16


def barrett(x):
    assert 0 <= x < S.BLIM
    return x - ((x * 21) >> 18) * q


def ref_fw(a):
    a, t, m = a[:], N, 1
    while m < N:
        t >>= 1
        for i in range(m):
            z = S.FW[m + i]
            for j in range(2 * i * t, 2 * i * t + t):
                U, V = a[j], a[j + t] * z % q
                a[j], a[j + t] = (U + V) % q, (U - V) % q
        m <<= 1
    return a


def ref_inv(a):
    a, t, m = a[:], 1, N
    while m > 1:
        h = m >> 1
        for i in range(h):
            z = S.INV[h + i]
            for j in range(2 * i * t, 2 * i * t + t):
                U, V = a[j], a[j + t]
                a[j], a[j + t] = (U + V) % q, (U - V) * z % q
        t <<= 1
        m >>= 1
    return [x * S.NINV % q for x in a]


def run(steps, biases, a, key=None):
    """concrete replay of a schedule; `biases` in step order as returned by the analysis"""
    a = a[:]
    bi = iter(biases)
    bounds = [q - 1] * N
    for st in steps:
        kind = st[0]
        if kind == "ct":
            t, k = st[1], next(bi)
            m = N // (2 * t)
            for i in range(m):
                z = S.FWM[m + i]
                for j in range(2 * i * t, 2 * i * t + t):
                    r = redc(a[j + t] * z)
                    assert r <= k * q
                    a[j], a[j + t] = a[j] + r, a[j] + k * q - r
        elif kind == "gs":
            t, red, k = st[1], st[2], next(bi)
            h = N // (2 * t)
            for i in range(h):
                z = S.INVM[h + i]
                for j in range(2 * i * t, 2 * i * t + t):
                    U, V = a[j], a[j + t]
                    assert V < k * q
                    s = U + V
                    a[j], a[j + t] = barrett(s) if red else s, redc((U + k * q - V) * z)
        elif kind == "bar":
            a = [barrett(x) for x in a]
        elif kind == "condq":
            assert max(a) < 2 * q
            a = [x - q if x >= q else x for x in a]
        elif kind == "pw16":
            a = [redc(x * y) for x, y in zip(a, key)]
        elif kind == "fold":
            cs, cd, k = st[1], st[2], next(bi)
            H = N // 2
            out = a[:]
            for j in range(H):
                assert a[j + H] < k * q
                out[j] = redc((a[j] + a[j + H]) * cs)
                out[j + H] = redc((a[j] + k * q - a[j + H]) * cd)
            a = out
        S.apply(st, bounds)
        assert all(x <= b for x, b in zip(a, bounds)), f"{kind}: lane above its bound"
    return a


def unpack(words):
    return [(int(words[i >> 4], 16) >> (16 * (i & 15))) & 0xFFFF for i in range(N)]


def main():
    ntt_steps = S.spec_ntt(S.NTT_BARS)
    intt_steps = S.spec_intt(S.INTT_PRE, S.INTT_RED)
    prod_steps = S.spec_product(S.PROD_FWBARS, S.PROD_PRE, S.PROD_RED)
    b_ntt, _, _ = S.analyze(ntt_steps)
    b_intt, _, _ = S.analyze(intt_steps)
    b_prod, _, _ = S.analyze(prod_steps)

    here = os.path.dirname(os.path.abspath(__file__))
    vec = json.load(open(os.path.join(here, "..", "test", "ntt1024_vectors.json")))
    for v in vec["vectors"]:
        a = unpack(v["a"])
        assert run(ntt_steps, b_ntt, a) == ref_fw(a) == unpack(v["ntt"]), v["name"]
        assert run(intt_steps, b_intt, a) == ref_inv(a) == unpack(v["intt"]), v["name"]
    print(f"{len(vec['vectors'])} vectors of {vec['source']}: NTT and INTT replays == scalar reference == noble")

    rng = random.Random(1024)
    for _ in range(8):
        a = [rng.randrange(q) for _ in range(N)]
        assert run(ntt_steps, b_ntt, a) == ref_fw(a)
        assert run(intt_steps, b_intt, a) == ref_inv(a)
    print("8 random polynomials: NTT and INTT replays == scalar reference")

    cases = [([rng.randrange(q) for _ in range(N)], [rng.randrange(1 << 16) for _ in range(N)]) for _ in range(8)]
    cases += [([q - 1] * N, [0xFFFF] * N), ([q - 1] * N, [q - 1] * N), ([0] * N, [0xFFFF] * N)]
    for s2, key in cases:
        lanes = run(prod_steps, b_prod, s2, key)
        ref = ref_inv([x * (y % q) % q for x, y in zip(ref_fw(s2), key)])
        assert all(x <= S.CPL and x % q == r for x, r in zip(lanes, ref))
    print(f"{len(cases)} products (random, saturated, 16-bit keys): replay == INTT(NTT(s2) o h), stored lanes CPL - x >= 0")


if __name__ == "__main__":
    main()
