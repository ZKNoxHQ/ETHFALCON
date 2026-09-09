#!/usr/bin/env python3
# model_ntt8.py -- Python model of the eight-lane Montgomery schedule emitted by
# gen_ntt8.py (Falcon-512, q = 12289), checked against a scalar model of
# ZKNOX_NTT_falcon_packed.sol's transforms (same psirev tables).
#
#   python3 pythonref/model_ntt8.py
#
# Layout: 64 words of eight 32-bit lanes, coefficient 8w + j in lane j of word w.
# Twiddle products of the word-aligned layers are reduced with a lane-local
# Montgomery step, R = 2^16, QINV = -q^-1 mod 2^16 = 12287:
#   m = ((x mod 2^16) * 12287) mod 2^16,   r = (x + m*q) >> 16,   r = x / R (mod q)
# twiddles of those layers stored as w * R mod q. Lane-locality: x + m*q < 2^32.
# Forward biases 2q,2q,2q,3q,3q,4q (lanes < 3q,5q,7q,10q,13q,17q), then a
# Barrett step with M = 21 = floor(2^18/q) brings lanes below 2q for the in-word
# kernel (scalar). Inverse aligned layers keep lanes below 4q: sums conditionally
# reduced by 4q, differences with a 4q bias; the last layer folds 1/512
# (multiplier 128 = R/512 on sums, inv[1]*128 mod q on differences), output < 2q.
import os
import random
import re

q = 12289
R = 1 << 16
QINV = (-pow(q, -1, R)) % R
assert QINV == 12287
NINV = pow(512, -1, q)
assert NINV == 12265

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "..", "src", "ZKNOX_NTT_falcon_packed.sol")).read()
ARRAYS = re.findall(r"uint256\[32\] memory psirev = \[(.*?)\];", SRC, re.S)
assert len(ARRAYS) == 2


def _parse(a):
    w = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", a)]
    assert len(w) == 32
    return [(w[i >> 4] >> (16 * (i & 15))) & 0xFFFF for i in range(512)]


fw, inv = _parse(ARRAYS[0]), _parse(ARRAYS[1])
D1 = (inv[1] * 128) % q  # difference multiplier of the folded last layer
# the pointwise REDC leaves a factor R^-1 on everything: the last layer multiplies by R more
C128R = (128 * R) % q
D1R = (D1 * R) % q


def mont(x):
    return (x * R) % q


def redc(x):
    assert 0 <= x < 1 << 32
    m = ((x & 0xFFFF) * QINV) & 0xFFFF
    s = x + m * q
    assert s < 1 << 32, "REDC not lane-local"
    assert s % R == 0
    r = s >> 16
    assert (r * R) % q == x % q
    return r


def barrett21(x):
    assert 0 <= x < 1 << 23
    qh = (x * 21) >> 18
    assert qh < 32
    r = x - qh * q
    assert 0 <= r < 2 * q
    return r


# ---------- scalar reference (the loops of ZKNOX_NTT_falcon.sol) ----------
def ref_fw(a):
    a = a[:]
    t, m = 512, 1
    while m < 512:
        t >>= 1
        for i in range(m):
            S = fw[m + i]
            for j in range(2 * i * t, 2 * i * t + t):
                U, V = a[j], (a[j + t] * S) % q
                a[j], a[j + t] = (U + V) % q, (U - V) % q
        m <<= 1
    return a


def ref_inv(a):
    a = a[:]
    t, m = 1, 512
    while m > 1:
        h = m >> 1
        for i in range(h):
            S = inv[h + i]
            for j in range(2 * i * t, 2 * i * t + t):
                U, V = a[j], a[j + t]
                a[j], a[j + t] = (U + V) % q, ((U - V) * S) % q
        t <<= 1
        m >>= 1
    return [(x * NINV) % q for x in a]


# ---------- packed helpers ----------
def pack(a):
    return [[a[8 * w + j] for j in range(8)] for w in range(64)]


def bf_ct(U, V, Sm, K):
    s, d = [], []
    for j in range(8):
        r = redc(V[j] * Sm)
        assert r <= K * q, f"reduced product {r} above the {K}q bias"
        s.append(U[j] + r)
        d.append(U[j] + K * q - r)
        assert s[-1] < 1 << 32 and d[-1] < 1 << 32
    return s, d


def cond4q(s):
    return [x - 4 * q if x >= 4 * q else x for x in s]


def bf_gs(U, V, Sm, K, reduce_sum):
    s, d = [], []
    for j in range(8):
        t = U[j] + V[j]
        assert t < 8 * q + 1
        s.append(t)
        x = (U[j] + K * q - V[j]) * Sm
        assert U[j] + K * q - V[j] >= 0
        d.append(redc(x))
        assert d[-1] < 4 * q
    if reduce_sum:
        s = cond4q(s)
    return s, d


MAX = {"fwA": 0, "fwB": 0, "inv": 0}


def fused(a, key):
    """forward on a (canonical), pointwise by key (canonical), inverse; returns lanes < 2q"""
    A = pack(a)
    # pass A: t = 256, 128, 64 (word distance 32, 16, 8), biases 2q, 2q, 2q
    for i in range(8):
        idx = [i + 8 * k for k in range(8)]
        w = [A[x] for x in idx]
        for k in range(4):
            w[k], w[k + 4] = bf_ct(w[k], w[k + 4], mont(fw[1]), 2)
        for k in (0, 1):
            w[k], w[k + 2] = bf_ct(w[k], w[k + 2], mont(fw[2]), 2)
        for k in (4, 5):
            w[k], w[k + 2] = bf_ct(w[k], w[k + 2], mont(fw[3]), 2)
        for k in range(4):
            w[2 * k], w[2 * k + 1] = bf_ct(w[2 * k], w[2 * k + 1], mont(fw[4 + k]), 2)
        for k in range(8):
            A[idx[k]] = w[k]
            MAX["fwA"] = max(MAX["fwA"], max(w[k]))
    # pass B: t = 32, 16, 8 (word distance 4, 2, 1), biases 3q, 3q, 4q
    for b in range(8):
        idx = [8 * b + k for k in range(8)]
        w = [A[x] for x in idx]
        for k in range(4):
            w[k], w[k + 4] = bf_ct(w[k], w[k + 4], mont(fw[8 + b]), 3)
        for k in (0, 1):
            w[k], w[k + 2] = bf_ct(w[k], w[k + 2], mont(fw[16 + 2 * b]), 3)
        for k in (4, 5):
            w[k], w[k + 2] = bf_ct(w[k], w[k + 2], mont(fw[17 + 2 * b]), 3)
        for k in range(4):
            w[2 * k], w[2 * k + 1] = bf_ct(w[2 * k], w[2 * k + 1], mont(fw[32 + 4 * b + k]), 4)
        for k in range(8):
            A[idx[k]] = w[k]
            MAX["fwB"] = max(MAX["fwB"], max(w[k]))
    assert MAX["fwB"] < 17 * q
    # in-word kernel, SWAR on the packed word (no lane variables): Barrett to < 2q,
    # forward t = 4 (bias 2q), t = 2 (2q), t = 1 (3q), Barrett to < 2q, pointwise
    # by the plain key through REDC (result carries R^-1, compensated in the last
    # layer), inverse t = 1 (bias 3q), t = 2 (6q), Barrett to < 2q, t = 4 (2q)
    for w in range(64):
        l = A[w][:]
        S = mont(fw[64 + w])
        for i in range(4):
            v = redc(l[i + 4] * S)
            assert v < 5 * q
            l[i], l[i + 4] = l[i] + v, l[i] + 5 * q - v
        assert max(l) < 22 * q
        for base, S in ((0, mont(fw[128 + 2 * w])), (4, mont(fw[129 + 2 * w]))):
            for i in (base, base + 1):
                v = redc(l[i + 2] * S)
                assert v < 6 * q
                l[i], l[i + 2] = l[i] + v, l[i] + 6 * q - v
        assert max(l) < 28 * q
        l = [barrett21(x) for x in l]
        for k in range(4):
            S = mont(fw[256 + 4 * w + k])
            v = redc(l[2 * k + 1] * S)
            assert v < 2 * q
            l[2 * k], l[2 * k + 1] = l[2 * k] + v, l[2 * k] + 2 * q - v
        assert max(l) < 4 * q
        # pointwise straight from lanes < 4q: lane * field (field < 2^16, not
        # range-checked) < 4q * 65535 < 2^32 - 2^16 q, one REDC: value * R^-1
        l = [redc(l[j] * key[8 * w + j]) for j in range(8)]
        assert max(l) < 5 * q
        # inverse t = 1 (bias 5q)
        for k in range(4):
            S = mont(inv[256 + 4 * w + k])
            a0, b0 = l[2 * k], l[2 * k + 1]
            l[2 * k], l[2 * k + 1] = a0 + b0, redc((a0 + 5 * q - b0) * S)
        assert max(l) < 10 * q
        for base, S in ((0, mont(inv[128 + 2 * w])), (4, mont(inv[129 + 2 * w]))):
            for i in (base, base + 1):
                a0, b0 = l[i], l[i + 2]
                l[i], l[i + 2] = a0 + b0, redc((a0 + 10 * q - b0) * S)
        assert max(l) < 20 * q
        l = [barrett21(x) for x in l]
        S = mont(inv[64 + w])
        for i in range(4):
            a0, b0 = l[i], l[i + 4]
            l[i], l[i + 4] = a0 + b0, redc((a0 + 2 * q - b0) * S)
        assert max(l) < 4 * q
        A[w] = l
    # pass B': t = 8, 16, 32 (word distance 1, 2, 4); biases q, 2q, 4q; sums reduced at t = 32
    for b in range(8):
        idx = [8 * b + k for k in range(8)]
        w = [A[x] for x in idx]
        for k in range(4):
            w[2 * k], w[2 * k + 1] = bf_gs(w[2 * k], w[2 * k + 1], mont(inv[32 + 4 * b + k]), 4, True)
        for k in (0, 1):
            w[k], w[k + 2] = bf_gs(w[k], w[k + 2], mont(inv[16 + 2 * b]), 4, True)
        for k in (4, 5):
            w[k], w[k + 2] = bf_gs(w[k], w[k + 2], mont(inv[17 + 2 * b]), 4, True)
        for k in range(4):
            w[k], w[k + 4] = bf_gs(w[k], w[k + 4], mont(inv[8 + b]), 4, True)
        for k in range(8):
            A[idx[k]] = w[k]
            assert max(w[k]) < 4 * q
    # pass A': t = 64, 128 (biases 4q, sums reduced), then t = 256 folded with 1/512
    out = [0] * 512
    for i in range(8):
        idx = [i + 8 * k for k in range(8)]
        w = [A[x] for x in idx]
        for k in range(4):
            w[2 * k], w[2 * k + 1] = bf_gs(w[2 * k], w[2 * k + 1], mont(inv[4 + k]), 4, True)
        for k in (0, 1):
            w[k], w[k + 2] = bf_gs(w[k], w[k + 2], mont(inv[2]), 4, True)
        for k in (4, 5):
            w[k], w[k + 2] = bf_gs(w[k], w[k + 2], mont(inv[3]), 4, True)
        for k in range(4):
            U, V = w[k], w[k + 4]
            s, d = [], []
            for j in range(8):
                x = (U[j] + V[j]) * C128R
                s.append(redc(x))
                t = U[j] + 4 * q - V[j]
                assert t >= 0
                x = t * D1R
                d.append(redc(x))
                MAX["inv"] = max(MAX["inv"], s[-1], d[-1])
            w[k], w[k + 4] = s, d
        for k in range(8):
            for j in range(8):
                out[8 * idx[k] + j] = w[k][j]
    assert all(x < 3 * q for x in out), "output lanes not below 3q"
    return out


if __name__ == "__main__":
    rng = random.Random(7)
    for trial in range(40):
        a = [q - 1] * 512 if trial == 0 else [rng.randrange(q) for _ in range(512)]
        # keys are not range-checked by the verifier: 16-bit fields, including >= q
        key = [q - 1] * 512 if trial in (0, 1) else ([65535] * 512 if trial == 2 else [rng.randrange(65536 if trial < 6 else q) for _ in range(512)])
        ref = ref_inv([(x * y) % q for x, y in zip(ref_fw(a), key)])
        got = fused(a, key)
        assert [x % q for x in got] == ref, f"mismatch, trial {trial}"
    print("all trials OK; max lane after pass A =", round(MAX["fwA"] / q, 2), "q, after pass B =", round(MAX["fwB"] / q, 2), "q, max output =", round(MAX["inv"] / q, 2), "q; D1 =", D1, "C128R =", C128R, "D1R =", D1R)
