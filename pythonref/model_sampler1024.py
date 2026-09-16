#!/usr/bin/env python3
# model_sampler1024.py -- 256-bit replay of the grouped paths of hashToPointNormS1_1024
# (src/ZKNOX_falcon1024_core.sol) against the scalar definition
#     sum over accepted candidates t of (((t + 3q + 6144 - s1_i) mod q) - 6144)^2
# for random pairs of state lanes with 0, 1 or 2 rejections, the four-candidate path of the
# 17th lane, s1 over its whole domain [0, 3q), and arbitrary 32-bit garbage in the s1 lanes
# a group reads but does not count (past the end of s1).
#
#   python3 pythonref/model_sampler1024.py
import random

q = 12289
W = (1 << 256) - 1
CPL = 3 * q + 6144


def rep(v, sp, n):
    return sum(v << (sp * k) for k in range(n))


def shl(s, x):
    return (x << s) & W if s < 256 else 0


def shr(s, x):
    return x >> s if s < 256 else 0


def sub(a, b):
    return (a - b) & W


def add(a, b):
    return (a + b) & W


def mul(a, b):
    return (a * b) & W


def NOT(x):
    return ~x & W


L64 = (1 << 64) - 1
H64 = L64 << 64
SA = 0xFFFFFFFF | (0xFFFFFFFF << 128)
SB = (0xFFFFFFFF << 32) | (0xFFFFFFFF << 160)
SC = sum(0xFFFF << (64 * i) for i in range(4))
SD = sum(0xFFFF0000 << (64 * i) for i in range(4))
CQ17, G17, NIB8 = rep((1 << 17) - q, 32, 8), rep(1 << 17, 32, 8), rep(0xF, 32, 8)
C6145, G31, Q8, S6144 = rep((1 << 31) - 6145, 32, 8), rep(1 << 31, 32, 8), rep(q, 32, 8), rep(6144, 32, 8)
M64LO = 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF
M64HI = M64LO << 64
M32LO = rep(0xFFFFFFFF, 64, 4)
M32HI = M32LO << 32
T7FFF, T0FFB, T8000 = rep(0x7FFF, 16, 8), rep(0x0FFB, 16, 8), rep(0x8000, 16, 8)


def drop(L, b):
    return (L & sub(shr(15, b), 1)) | shr(16, L & NOT(sub(shl(1, b), 1)))


def group(L, cnt, w0, w1, i):
    """the shared group body: returns the norm increment"""
    L = (L & L64) | shl(64, L & H64)
    L = (L & SA) | shl(32, L & SB)
    L = (L & SC) | shl(16, L & SD)
    sh = 32 * (i & 7)
    x = sub(add(shr(sh, w0) | shl(256 - sh, w1), L), S6144)
    x = sub(x, mul(shr(24, mul(x, 1365)) & NIB8, q))
    x = sub(x, mul(shr(17, add(x, CQ17) & G17), q))
    f = add(x, C6145) & G31
    f = f | sub(f, shr(31, f))
    x = (x ^ (f & (x ^ sub(Q8, x)))) & sub(shl(32 * cnt, 1), 1)
    g = shl(128, x) | shr(128, x)
    g = shl(64, g & M64LO) | shr(64, g & M64HI)
    g = shl(32, g & M32LO) | shr(32, g & M32HI)
    return shr(224, mul(x, g))


def scalar(cands, s1, i):
    n = 0
    for t in cands:
        if t < 5 * q:
            d = ((t + CPL - s1[i]) % q) - 6144
            n += d * d
            i += 1
    return n, i


def main():
    rng = random.Random(0x1024)
    hits = {"pair0": 0, "pair1": 0, "pair2": 0, "lane4": 0, "slow": 0}
    for trial in range(60000):
        nf = 4 if trial % 4 == 3 else 8
        rej = rng.choice([0, 0, 1, 1, 2, 3]) if nf == 8 else rng.choice([0, 1, 2])
        cands = [rng.randrange(5 * q) for _ in range(nf)]
        for pos in rng.sample(range(nf), rej):
            cands[pos] = rng.randrange(5 * q, 1 << 16)
        if trial % 11 == 0:
            cands = [rng.choice([0, 5 * q - 1]) if c < 5 * q else rng.choice([5 * q, 0xFFFF]) for c in cands]
        L = sum(c << (16 * k) for k, c in enumerate(cands))
        i = rng.randrange(0, 16)
        s1 = [rng.choice([0, 3 * q - 1, rng.randrange(3 * q)]) for _ in range(i + 16)]
        lanes = [CPL - x for x in s1]
        # lanes a group reads but does not count may be anything
        cnt_accept = sum(c < 5 * q for c in cands)
        for j in range(i + cnt_accept, len(lanes)):
            if rng.random() < 0.5:
                lanes[j] = rng.randrange(1 << 32)
        base = i & ~7
        w0 = sum(lanes[base + k] << (32 * k) for k in range(8))
        w1 = sum(lanes[base + 8 + k] << (32 * k) for k in range(8))
        want, _ = scalar(cands, [CPL - x for x in lanes], i)
        b = (((L & T7FFF) + T0FFB) & L) & T8000
        if nf == 8 and b & (b - 1) == 0:
            got = group(drop(L, b), 8 - (b != 0), w0, w1, i)
            hits["pair1" if b else "pair0"] += 1
        elif nf == 8:
            b1 = b & sub(0, b)
            b2 = shr(16, b ^ b1)
            if b2 & (b2 - 1) != 0:
                hits["slow"] += 1
                continue
            got = group(drop(drop(L, b1), b2), 6, w0, w1, i)
            hits["pair2"] += 1
        else:
            if b & (b - 1) != 0:
                hits["slow"] += 1
                continue
            got = group(drop(L, b), 4 - (b != 0), w0, w1, i)
            hits["lane4"] += 1
        assert got == want, (trial, cands, i, got, want)
    print("grouped paths == scalar definition:", hits)


if __name__ == "__main__":
    main()
