#!/usr/bin/env python3
# model_ntt_fused.py -- Python model of the fused radix-8 schedule emitted by
# gen_ntt_fused.py, checked against a layer by layer model of
# ZKNOX_NTT_falcon_packed.sol (same twiddle tables, read from the Solidity
# source). Every Barrett multiply asserts the lane-locality bound
# (x * M40 < 2^64) and every subtractive branch asserts positivity, so a bias
# schedule that is too small fails here before it fails in Solidity.
#
#   python3 pythonref/model_ntt_fused.py
#
# 30 trials (trial 0 saturated: every coefficient q-1, the worst case for lane
# growth), forward compared mod q, inverse compared exactly (canonical).
# `fused_inv_mul_swar` is the SWAR in-word variant that was measured and
# rejected (generator notes): kept as a second validated schedule.
import os
import random
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "..", "src", "ZKNOX_NTT_falcon_packed.sol")).read()
ARRAYS = re.findall(r"uint256\[32\] memory psirev = \[(.*?)\];", SRC, re.S)
assert len(ARRAYS) == 2


def _parse(a):
    w = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", a)]
    assert len(w) == 32
    return [(w[i >> 4] >> (16 * (i & 15))) & 0xFFFF for i in range(512)]


fw, inv = _parse(ARRAYS[0]), _parse(ARRAYS[1])
q = 12289; NINV = 12265
M40 = 89471204
def barrett(x):  # scalar single-step Barrett with M40
    return x - ((x * M40) >> 40) * q

# ---------- reference: layer-by-layer on 128 "words" (lists of 4 lanes), mirrors _nttFwPacked ----------
def ref_fw(A):  # A: list of 128 lists of 4 ints (canonical)
    A = [w[:] for w in A]
    m = 1; twds = 64
    while twds > 0:
        for i in range(m):
            S = fw[m + i]
            p0 = i * 2 * twds
            for p in range(p0, p0 + twds):
                pt = p + twds
                for j in range(4):
                    U = A[p][j]; V = barrett(A[pt][j] * S)
                    A[pt][j] = U + 4*q - V
                    A[p][j] = U + V
        m *= 2; twds //= 2
    # t = 2
    for w in range(128):
        S = fw[128 + w]
        for j in range(2):
            U = A[w][j]; V = barrett(A[w][j+2] * S)
            A[w][j] = U + V; A[w][j+2] = U + 4*q - V
    # t = 1
    for w in range(128):
        Sa = fw[256 + 2*w]; Sb = fw[257 + 2*w]
        l0,l1,l2,l3 = A[w]
        Va = barrett(l1 * Sa); Vb = barrett(l3 * Sb)
        A[w] = [l0 + Va, l0 + 4*q - Va, l2 + Vb, l2 + 4*q - Vb]
    return A

def ref_inv(A):  # mirrors _nttInvPacked
    A = [w[:] for w in A]
    for w in range(128):
        l0,l1,l2,l3 = A[w]
        Sa = inv[256 + 2*w]; Sb = inv[257 + 2*w]
        s0 = barrett(l0 + l1); d0 = barrett((l0 + 4*q - l1) * Sa)
        s1 = barrett(l2 + l3); d1 = barrett((l2 + 4*q - l3) * Sb)
        A[w] = [s0, d0, s1, d1]
    for w in range(128):
        S = inv[128 + w]
        U = A[w][0:2]; V = A[w][2:4]
        for j in range(2):
            s = barrett(U[j] + V[j]); d = barrett((U[j] + 4*q - V[j]) * S)
            A[w][j] = s; A[w][j+2] = d
    m = 128; twds = 1
    while m > 1:
        h = m // 2
        for i in range(h):
            S = inv[h + i]
            g = i * 2 * twds
            for p in range(g, g + twds):
                pt = p + twds
                for j in range(4):
                    U = A[p][j]; V = A[pt][j]
                    A[p][j] = barrett(U + V)
                    A[pt][j] = barrett((U + 4*q - V) * S)
        m = h; twds *= 2
    for w in range(128):
        for j in range(4):
            A[w][j] = barrett(A[w][j] * NINV)
    return A

# ---------- fused schedule ----------
BIAS = 2*q
MAXL = [0]
def bf_ct(U, V, S):   # packed CT butterfly on lane lists
    out_lo=[];out_hi=[]
    for j in range(4):
        x = V[j] * S
        assert x * M40 < 2**64, "barrett overflow"
        v = barrett(x); assert 0 <= v < 2*q
        out_lo.append(U[j] + v); out_hi.append(U[j] + BIAS - v)
        assert out_hi[-1] >= 0
        MAXL[0] = max(MAXL[0], out_lo[-1], out_hi[-1])
    return out_lo, out_hi

def fused_fw(A):
    A = [w[:] for w in A]
    S1 = fw[1]; S2a, S2b = fw[2], fw[3]; S3 = fw[4:8]
    # pass A: octets i + 16k
    for i in range(16):
        w = [A[i + 16*k] for k in range(8)]
        for k in range(4): w[k], w[k+4] = bf_ct(w[k], w[k+4], S1)
        for k in (0,1): w[k], w[k+2] = bf_ct(w[k], w[k+2], S2a)
        for k in (4,5): w[k], w[k+2] = bf_ct(w[k], w[k+2], S2b)
        for k in range(4): w[2*k], w[2*k+1] = bf_ct(w[2*k], w[2*k+1], S3[k])
        for k in range(8): A[i + 16*k] = w[k]
    # pass B: blocks of 16 words, octets 16b + r + 2k
    for b in range(8):
        S8 = fw[8 + b]; S4a, S4b = fw[16 + 2*b], fw[17 + 2*b]; S2 = fw[32 + 4*b: 36 + 4*b]
        for r in range(2):
            idx = [16*b + r + 2*k for k in range(8)]
            w = [A[x] for x in idx]
            for k in range(4): w[k], w[k+4] = bf_ct(w[k], w[k+4], S8)
            for k in (0,1): w[k], w[k+2] = bf_ct(w[k], w[k+2], S4a)
            for k in (4,5): w[k], w[k+2] = bf_ct(w[k], w[k+2], S4b)
            for k in range(4): w[2*k], w[2*k+1] = bf_ct(w[2*k], w[2*k+1], S2[k])
            for k in range(8): A[idx[k]] = w[k]
    # pass C: pairs (2j, 2j+1): t=4 packed, then in-word t=2 (packed on half-words), t=1 scalar mulmod
    for j in range(64):
        U, V = A[2*j], A[2*j+1]
        U, V = bf_ct(U, V, fw[64 + j])
        out = []
        for w, W in ((2*j, U), (2*j+1, V)):
            S = fw[128 + w]
            lo = W[0:2]; hi = W[2:4]
            lo2, hi2 = [], []
            for jj in range(2):
                x = hi[jj] * S; assert x * M40 < 2**64
                v = barrett(x)
                lo2.append(lo[jj] + v); hi2.append(lo[jj] + BIAS - v)
            l0,l1,l2,l3 = lo2[0], lo2[1], hi2[0], hi2[1]
            Sa = fw[256 + 2*w]; Sb = fw[257 + 2*w]
            va = (l1 * Sa) % q; vb = (l3 * Sb) % q   # mulmod exact
            W2 = [l0 + va, l0 + BIAS - va, l2 + vb, l2 + BIAS - vb]
            for v in W2: assert 0 <= v < 2**64; MAXL[0] = max(MAXL[0], v)
            A[w] = W2
    return A

def bf_gs(U, V, S, K):  # packed GS: s = U+V unreduced ; d = barrett((U + K*q - V) * S)
    s=[];d=[]
    for j in range(4):
        s.append(U[j] + V[j])
        t = U[j] + K*q - V[j]; assert t >= 0
        x = t * S; assert x * M40 < 2**64, ("gs overflow", x.bit_length())
        d.append(barrett(x)); assert 0 <= d[-1] < 2*q
    return s, d

def fused_inv_mul(A, PK):  # A lanes arbitrary < 2^64 (lazy); PK canonical per coefficient; returns canonical
    A = [w[:] for w in A]
    # pass C': pointwise mulmod, in-word t=1, t=2 (scalars), then t=4 packed
    for j in range(64):
        W2 = []
        for w in (2*j, 2*j+1):
            l = [(A[w][k] * PK[4*w + k]) % q for k in range(4)]
            Sa = inv[256 + 2*w]; Sb = inv[257 + 2*w]
            s0 = l[0] + l[1]; d0 = ((l[0] + q - l[1]) * Sa) % q
            s1 = l[2] + l[3]; d1 = ((l[2] + q - l[3]) * Sb) % q
            S = inv[128 + w]
            a0 = (s0 + s1) % q; a2 = ((s0 + 2*q - s1) * S) % q
            a1 = (d0 + d1) % q; a3 = ((d0 + q - d1) * S) % q
            W2.append([a0, a1, a2, a3])
        U, V = W2
        s, d = bf_gs(U, V, inv[64 + j], 1)
        A[2*j] = s; A[2*j+1] = d          # lanes < 2q
    # pass B': octets 16b + r + 2k ; layers twds=2 (slots (2k,2k+1)), twds=4, twds=8
    for b in range(8):
        S2 = inv[32 + 4*b: 36 + 4*b]; S4a, S4b = inv[16 + 2*b], inv[17 + 2*b]; S8 = inv[8 + b]
        for r in range(2):
            idx = [16*b + r + 2*k for k in range(8)]
            w = [A[x] for x in idx]
            for k in range(4): w[2*k], w[2*k+1] = bf_gs(w[2*k], w[2*k+1], S2[k], 2)   # lanes < 2q -> s<4q
            for k in (0,1): w[k], w[k+2] = bf_gs(w[k], w[k+2], S4a, 4)              # lanes < 4q -> s<8q
            for k in (4,5): w[k], w[k+2] = bf_gs(w[k], w[k+2], S4b, 4)
            for k in range(4): w[k], w[k+4] = bf_gs(w[k], w[k+4], S8, 8)            # lanes < 8q -> s<16q
            for k in range(8): A[idx[k]] = w[k]
    # pass A': octets i + 16k ; twds=16 slots (2k,2k+1) with inv[4+k]; twds=32 (0,2),(1,3):inv[2], (4,6),(5,7):inv[3]; twds=64 (k,k+4): inv[1] folded with NINV
    S1f = (inv[1] * NINV) % q
    for i in range(16):
        w = [A[i + 16*k] for k in range(8)]
        for k in range(4): w[2*k], w[2*k+1] = bf_gs(w[2*k], w[2*k+1], inv[4 + k], 16)   # <16q -> s<32q
        for k in (0,1): w[k], w[k+2] = bf_gs(w[k], w[k+2], inv[2], 32)                 # <32q -> s<64q
        for k in (4,5): w[k], w[k+2] = bf_gs(w[k], w[k+2], inv[3], 32)
        for k in range(4):
            U, V = w[k], w[k+4]
            s=[];d=[]
            for jj in range(4):
                x = (U[jj] + V[jj]) * NINV; assert x * M40 < 2**64
                s.append(barrett(x))
                t = U[jj] + 64*q - V[jj]; assert t >= 0
                x = t * S1f; assert x * M40 < 2**64
                d.append(barrett(x))
            # canonicalise (< 2q -> < q)
            s = [v - q if v >= q else v for v in s]; d = [v - q if v >= q else v for v in d]
            w[k], w[k+4] = s, d
        for k in range(8): A[i + 16*k] = w[k]
    return A


def fused_inv_mul_swar(A, PK):  # SWAR in-word variant: pointwise via mul+mask, GS t=1/t=2 packed with lazy sums
    A = [w[:] for w in A]
    for j in range(64):
        W2 = []
        for w in (2*j, 2*j+1):
            # pointwise: 4 products in lanes (< 19q * q), one Barrett -> < 2q
            P = []
            for k in range(4):
                x = A[w][k] * PK[4*w + k]; assert x < 2**64 and x * M40 < 2**64
                P.append(barrett(x)); assert 0 <= P[-1] < 2*q
            Sa = inv[256 + 2*w]; Sb = inv[257 + 2*w]
            # t = 1 (SWAR): lanes (0,1) with Sa, (2,3) with Sb; sums unreduced (< 4q), diffs Barrett (< 2q)
            s0 = P[0] + P[1]; t = P[0] + 2*q - P[1]; assert t >= 0; x = t * Sa; assert x * M40 < 2**64; d0 = barrett(x)
            s1 = P[2] + P[3]; t = P[2] + 2*q - P[3]; assert t >= 0; x = t * Sb; assert x * M40 < 2**64; d1 = barrett(x)
            # t = 2 (SWAR): (s0, d0) against (s1, d1) with S; bias 4q
            S = inv[128 + w]
            a0 = s0 + s1; a1 = d0 + d1
            t = s0 + 4*q - s1; assert t >= 0; x = t * S; assert x * M40 < 2**64; a2 = barrett(x)
            t = d0 + 4*q - d1; assert t >= 0; x = t * S; assert x * M40 < 2**64; a3 = barrett(x)
            W2.append([a0, a1, a2, a3])   # lanes < 8q
        U, V = W2
        s, d = bf_gs(U, V, inv[64 + j], 8)
        A[2*j] = s; A[2*j+1] = d          # lanes < 16q
    for b in range(8):
        S2 = inv[32 + 4*b: 36 + 4*b]; S4a, S4b = inv[16 + 2*b], inv[17 + 2*b]; S8 = inv[8 + b]
        for r in range(2):
            idx = [16*b + r + 2*k for k in range(8)]
            w = [A[x] for x in idx]
            for k in range(4): w[2*k], w[2*k+1] = bf_gs(w[2*k], w[2*k+1], S2[k], 16)
            for k in (0,1): w[k], w[k+2] = bf_gs(w[k], w[k+2], S4a, 32)
            for k in (4,5): w[k], w[k+2] = bf_gs(w[k], w[k+2], S4b, 32)
            for k in range(4): w[k], w[k+4] = bf_gs(w[k], w[k+4], S8, 64)
            for k in range(8): A[idx[k]] = w[k]
    S1f = (inv[1] * NINV) % q
    MAXI = 0
    for i in range(16):
        w = [A[i + 16*k] for k in range(8)]
        for k in range(4): w[2*k], w[2*k+1] = bf_gs(w[2*k], w[2*k+1], inv[4 + k], 128)
        for k in (0,1): w[k], w[k+2] = bf_gs(w[k], w[k+2], inv[2], 256)
        for k in (4,5): w[k], w[k+2] = bf_gs(w[k], w[k+2], inv[3], 256)
        for k in range(4):
            U, V = w[k], w[k+4]
            s=[];d=[]
            for jj in range(4):
                MAXI = max(MAXI, U[jj] + V[jj])
                x = (U[jj] + V[jj]) * NINV; assert x * M40 < 2**64, ("last sum overflow", x.bit_length())
                s.append(barrett(x))
                t = U[jj] + 512*q - V[jj]; assert t >= 0
                x = t * S1f; assert x * M40 < 2**64, ("last diff overflow", x.bit_length())
                d.append(barrett(x))
            s = [v - q if v >= q else v for v in s]; d = [v - q if v >= q else v for v in d]
            w[k], w[k+4] = s, d
        for k in range(8): A[i + 16*k] = w[k]
    MAXLI[0] = max(MAXLI[0], MAXI)
    return A

MAXLI = [0]

def rand_poly(rng, sat=False):
    return [[q-1 if sat else rng.randrange(q) for _ in range(4)] for _ in range(128)]

rng = random.Random(1)
for trial in range(30):
    sat = (trial == 0)
    A = rand_poly(rng, sat); PK = [q-1 if sat else rng.randrange(q) for _ in range(512)]
    R = ref_fw(A); F = fused_fw(A)
    assert all((R[w][j] - F[w][j]) % q == 0 for w in range(128) for j in range(4)), "fw mismatch"
    # inverse path: reference = unpack(ref_inv(vecmul(ref_fw)))
    P = [[(R[w][j] % q) * PK[4*w+j] % q for j in range(4)] for w in range(128)]
    RI = ref_inv(P); RI = [[v % q for v in w] for w in RI]
    FI = fused_inv_mul(F, PK)
    assert all(0 <= FI[w][j] < q for w in range(128) for j in range(4)), "not canonical"
    assert RI == FI, "inv mismatch"
    FS = fused_inv_mul_swar(F, PK)
    assert all(0 <= FS[w][j] < q for w in range(128) for j in range(4)), "swar not canonical"
    assert RI == FS, "swar inv mismatch"
print("all trials OK; max forward lane =", MAXL[0], "=", round(MAXL[0]/q, 2), "q; max last-layer sum (swar inv) =", MAXLI[0], "=", round(MAXLI[0]/q, 2), "q; worst Barrett product bits =", (MAXLI[0]*q).bit_length())
