#!/usr/bin/env python3
# sched1024.py -- exact lane-bound analysis for the Falcon-1024 eight-lane transforms,
# shared by gen_ntt1024.py (emission), model_ntt1024.py (replay) and the placement search.
#
# Bounds are tracked PER COEFFICIENT (1,024 inclusive maxima) with the actual twiddle of
# every butterfly, instead of one bound per layer with twiddle q - 1:
#   CT  t <= floor((M_hi z + (R - 1) q) / R),  lo' <= M_lo + t,  hi' <= M_lo + kq
#   GS  d <= M_lo + kq,  hi' <= floor((d z + (R - 1) q) / R),  lo' <= M_lo + M_hi
# k is the smallest multiple of q above every t (CT) or every M_hi (GS) of the layer, REDC
# lane locality (x + (R - 1) q < 2^32) is asserted, Barrett M = 21 is bounded by its exact
# prefix maximum (inputs < 2^19: quotient < 32, x * 21 < 2^32).
#
#   python3 pythonref/sched1024.py            prints the three schedules
#   python3 pythonref/sched1024.py --search   reruns the reduction placement search (minutes)
import itertools
import sys

q = 12289
N = 1024
R = 1 << 16
LANE = 1 << 32
QINV = (-pow(q, -1, R)) % R
assert QINV == 12287
NINV = pow(N, -1, q)


def brv(x, bits=10):
    return int(format(x, f"0{bits}b")[::-1], 2)


assert pow(7, 1024, q) == q - 1
FW = [pow(7, brv(i), q) for i in range(N)]
INV = [pow(x, -1, q) for x in FW]
FWM = [(x * R) % q for x in FW]
INVM = [(x * R) % q for x in INV]
CN = (NINV * R) % q  # REDC(s CN) = s / 1024
DN = (INV[1] * NINV * R) % q
CNR = (NINV * R * R) % q  # the same after a pointwise REDC left R^-1 on the values
DNR = (INV[1] * NINV * R * R) % q
CPL = 3 * q + 6144  # product lanes are stored as CPL - s1_i

BLIM = 1 << 19
PREFIX_MAX = []
_b = 0
for _y in range(BLIM):
    _b = max(_b, _y - ((_y * 21) >> 18) * q)
    PREFIX_MAX.append(_b)


class Infeasible(Exception):
    pass


def redc_max(x):
    if x + (R - 1) * q >= LANE:
        raise Infeasible("REDC not lane-local")
    return (x + (R - 1) * q) >> 16


def barrett_max(x):
    if x >= BLIM:
        raise Infeasible("Barrett range")
    return PREFIX_MAX[x]


def ceil_q(x):
    return -(-x // q)


def apply(st, M):
    """one step on the bound vector M (in place); returns (biases, label)"""
    kind = st[0]
    if kind == "ct":
        t = st[1]
        m = N // (2 * t)
        tm = 0
        for i in range(m):
            z = FWM[m + i]
            for j in range(2 * i * t, 2 * i * t + t):
                tm = max(tm, redc_max(M[j + t] * z))
        k = ceil_q(tm)
        for i in range(m):
            z = FWM[m + i]
            for j in range(2 * i * t, 2 * i * t + t):
                lo = M[j]
                M[j] = lo + redc_max(M[j + t] * z)
                M[j + t] = lo + k * q
        return [k], f"ct t={t} bias {k}q"
    if kind == "gs":
        t, red = st[1], st[2]
        h = N // (2 * t)
        k = ceil_q(max(M[j + t] for j in range(N) if (j // t) % 2 == 0) + 1)
        for i in range(h):
            z = INVM[h + i]
            for j in range(2 * i * t, 2 * i * t + t):
                lo, hi = M[j], M[j + t]
                M[j] = barrett_max(lo + hi) if red else lo + hi
                M[j + t] = redc_max((lo + k * q) * z)
        return [k], f"gs t={t} bias {k}q" + (" sums Barrett" if red else "")
    if kind == "bar":
        M[:] = [barrett_max(x) for x in M]
        return [], "Barrett"
    if kind == "condq":
        if max(M) >= 2 * q:
            raise Infeasible("cond -q needs lanes < 2q")
        M[:] = [min(x, q - 1) for x in M]
        return [], "cond -q"
    if kind == "pw16":
        M[:] = [redc_max(x * 0xFFFF) for x in M]
        return [], "pointwise (16-bit key)"
    if kind == "fold":
        cs, cd, out_max = st[1], st[2], st[3]
        H = N // 2
        k = ceil_q(max(M[H:]) + 1)
        for j in range(H):
            lo, hi = M[j], M[j + H]
            M[j] = redc_max((lo + hi) * cs)
            M[j + H] = redc_max((lo + k * q) * cd)
        if max(M) > out_max:
            raise Infeasible("fold output")
        return [k], f"gs t=512 folded, bias {k}q"
    raise ValueError(kind)


def analyze(steps, M=None):
    """returns (biases in step order, [(label, max bound)], final bound vector)"""
    M = [q - 1] * N if M is None else M[:]
    biases, log = [], []
    for st in steps:
        b, label = apply(st, M)
        biases += b
        log.append((label, max(M)))
    return biases, log, M


FW_ALIGNED = [("ct", t) for t in (512, 256, 128, 64, 32, 16, 8)]
INV_LAYERS = (1, 2, 4, 8, 16, 32, 64, 128, 256)


def fw_inword(bars):
    s = []
    for t in (4, 2, 1):
        if t in bars:
            s.append(("bar",))
        s.append(("ct", t))
    return s


def inv_part(pre, red):
    s = []
    for t in INV_LAYERS:
        if t in pre:
            s.append(("bar",))
        s.append(("gs", t, t in red))
    return s


def spec_ntt(bars):
    return FW_ALIGNED + fw_inword(bars) + [("bar",), ("condq",)]


def spec_intt(pre, red):
    return inv_part(pre, red) + [("fold", CN, DN, LANE - 1), ("bar",), ("condq",)]


def spec_product(fwbars, pre, red):
    return FW_ALIGNED + fw_inword(fwbars) + [("pw16",)] + inv_part(pre, red) + [("fold", CNR, DNR, CPL)]


def reduction_cost(fwbars, pre, red):
    """word operations spent in reductions: a Barrett of all words costs 128, the sums of
    an in-word layer 128 (one per word), the sums of an aligned layer 64"""
    return 128 * len(fwbars) + 128 * len(pre) + sum(128 if t < 8 else 64 for t in red)


# Schedules emitted by gen_ntt1024.py, found by search(). Pre-Barretts are only placed in
# front of in-word layers (t = 1, 2, 4), where they are one SWAR statement per word.
NTT_BARS = (1,)
INTT_PRE = ()
INTT_RED = (8, 64)
PROD_FWBARS = (1,)
PROD_PRE = (4,)
PROD_RED = (32, 256)


def _search_inverse(M0, tail):
    best = [10**9, None]

    def feasible(M, li):
        steps = []
        for t in INV_LAYERS[li:]:
            steps += ([("bar",)] if t < 8 else []) + [("gs", t, True)]
        try:
            analyze(steps + tail, M)
            return True
        except Infeasible:
            return False

    def dfs(M, li, c, pre, red):
        if c >= best[0]:
            return
        if li == len(INV_LAYERS):
            try:
                analyze(tail, M)
            except Infeasible:
                return
            best[0], best[1] = c, (tuple(pre), tuple(red))
            return
        t = INV_LAYERS[li]
        for p in (False, True) if t < 8 else (False,):
            for r in (False, True):
                st = ([("bar",)] if p else []) + [("gs", t, r)]
                try:
                    _, _, nM = analyze(st, M)
                except Infeasible:
                    continue
                if li + 1 < len(INV_LAYERS) and not feasible(nM, li + 1):
                    continue
                dc = (128 if p else 0) + ((128 if t < 8 else 64) if r else 0)
                dfs(nM, li + 1, c + dc, pre + ([t] if p else []), red + ([t] if r else []))

    dfs(M0, 0, 0, [], [])
    return best


def search():
    # standalone forward
    res = []
    for r in range(4):
        for bars in itertools.combinations((4, 2, 1), r):
            try:
                analyze(spec_ntt(bars))
                res.append((128 * len(bars), bars))
            except Infeasible:
                pass
    print("NTT      Barretts before in-word layers:", min(res))
    # standalone inverse
    c, (pre, red) = _search_inverse([q - 1] * N, [("fold", CN, DN, LANE - 1), ("bar",), ("condq",)])
    print("INTT     cost", c, "pre", pre, "red", red)
    # product
    res = []
    for r in range(4):
        for bars in itertools.combinations((4, 2, 1), r):
            try:
                _, _, M = analyze(FW_ALIGNED + fw_inword(bars) + [("pw16",)])
            except Infeasible:
                continue
            c, sol = _search_inverse(M, [("fold", CNR, DNR, CPL)])
            if sol:
                res.append((c + 128 * len(bars), bars, sol))
                print("  product fw Barretts", bars, "cost", c + 128 * len(bars), sol)
    print("PRODUCT  best", min(res))


def schedules():
    return {
        "ntt": analyze(spec_ntt(NTT_BARS)),
        "intt": analyze(spec_intt(INTT_PRE, INTT_RED)),
        "product": analyze(spec_product(PROD_FWBARS, PROD_PRE, PROD_RED)),
    }


if __name__ == "__main__":
    if "--search" in sys.argv:
        search()
    else:
        for name, (b, log, _) in schedules().items():
            print(name, "biases", b, "reduction cost", end=" ")
            print(
                reduction_cost(NTT_BARS, (), ()) + 128
                if name == "ntt"
                else reduction_cost((), INTT_PRE, INTT_RED) + 128
                if name == "intt"
                else reduction_cost(PROD_FWBARS, PROD_PRE, PROD_RED)
            )
            for label, m in log:
                print(f"   {label:<32} {m:>7}  {m / q:.3f} q")
