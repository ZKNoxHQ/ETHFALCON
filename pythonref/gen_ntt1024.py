#!/usr/bin/env python3
# gen_ntt1024.py -- emits src/ZKNOX_NTT_falcon1024.sol: the Falcon-1024 forward
# and inverse NTT (q = 12289, n = 1024) on EIGHT 32-bit lanes per word, Montgomery
# R = 2^16, same machinery as gen_ntt8.py (Falcon-512).
#
#   python3 pythonref/gen_ntt1024.py > src/ZKNOX_NTT_falcon1024.sol && forge fmt src/ZKNOX_NTT_falcon1024.sol
#   python3 pythonref/gen_ntt1024.py --schedule      (prints the bound analysis)
#
# Convention: psi_rev[i] = 7^brv10(i) mod q (7 has order 2048), psi_inv_rev[i] =
# its inverse, loops of eprint 2016/504 Alg. 1/2 (ZKNOX_NTT.sol), INTT scaled by
# 1024^-1. Same tables as @noble/post-quantum falcon (ROOT_OF_UNITY 7, brvBits 10)
# and, restricted to the first 512 entries, as the Falcon-512 tables of this repo.
#
# Layout: 128 words, coefficient 8w + j in lane j (bits 32j..32j+31) of word w.
# Compact form: 64 words of sixteen 16-bit fields, coefficient 16c + i in field i.
#
# Forward (Cooley-Tukey), layers t = 512 .. 1:
#   A0  t = 512          words (w, w + 64), spread from the compact input
#   A   t = 256, 128, 64 radix-8 on word octets (i + 8k), two blocks of 64 words
#   B   t = 32, 16, 8    radix-8 on eight consecutive words
#   W   t = 4, 2, 1      SWAR inside each word (per-lane twiddles), Barrett first,
#                        canonical output gathered straight into the compact result
# Inverse (Gentleman-Sande), layers t = 1 .. 512:
#   W'  t = 1, 2, 4      SWAR inside each word, spread from the compact input
#   B'  t = 8, 16, 32
#   A'  t = 64, 128, 256
#   A0' t = 512 with 1024^-1 folded, canonical output gathered into the compact result
# Biases, reductions and lane locality are derived and asserted by schedule() below;
# pythonref/model_ntt1024.py replays the schedule lane by lane.
import sys

q = 12289
N = 1024
R = 1 << 16
QINV = (-pow(q, -1, R)) % R
assert QINV == 12287
NINV = pow(N, -1, q)
LANE = 1 << 32


def brv(x, bits=10):
    return int(format(x, f"0{bits}b")[::-1], 2)


assert pow(7, 1024, q) == q - 1
FW = [pow(7, brv(i), q) for i in range(N)]
INV = [pow(x, -1, q) for x in FW]
FWM = [(x * R) % q for x in FW]
INVM = [(x * R) % q for x in INV]
CN = (NINV * R) % q  # REDC(s * CN) = s / 1024
DN = (INV[1] * NINV * R) % q  # REDC(d * DN) = d * inv[1] / 1024
ZMAX = q - 1


# ---------------------------------------------------------------- bound analysis
def redc_max(x):
    """largest REDC output for a lane product x <= X; asserts lane locality"""
    assert x + (R - 1) * q < LANE, "REDC not lane-local"
    return (x + (R - 1) * q) >> 16


def barrett_max(M):
    """largest x - floor(21x / 2^18) q over 0 <= x <= M (exhaustive), quotient < 32"""
    assert (M * 21) >> 18 < 32
    return max(x - ((x * 21) >> 18) * q for x in range(M + 1))


def ceil_q(x):
    return -(-x // q)


def schedule():
    """lane bounds (inclusive maxima) through both transforms; returns biases (in q)"""
    S = {"fw": [], "inv": []}
    M = q - 1  # canonical input, enforced by the public functions
    log = [("fw in", M)]
    for layer in ("512", "256", "128", "64", "32", "16", "8", "BAR", "4", "2", "1"):
        if layer == "BAR":
            M = barrett_max(M)
            log.append(("fw Barrett before t=4", M))
            continue
        t = redc_max(M * ZMAX)
        k = ceil_q(t)
        S["fw"].append(k)
        M = M + k * q  # sum <= M + t <= M + kq, difference <= M + kq
        log.append((f"fw t={layer} bias {k}q", M))
    M = barrett_max(M)
    log.append(("fw Barrett final", M))
    assert M < 2 * q
    log.append(("fw cond -q", q - 1))

    M = q - 1
    log.append(("inv in", M))
    # sums reduced by a conditional -4q when the next layer would otherwise not fit
    for layer in ("1", "2", "4", "8", "16", "32", "64", "128", "256"):
        k = ceil_q(M + 1) if M >= q else 1  # bias >= every hi lane
        d = M + k * q
        t = redc_max(d * ZMAX)
        s = 2 * M
        red = s >= 4 * q
        if red:
            assert s < 8 * q and s < (1 << 17) + 4 * q
            s = 4 * q - 1
        M = max(s, t)
        S["inv"].append((k, red))
        log.append((f"inv t={layer} bias {k}q{' sums -4q' if red else ''}", M))
    # t = 512 folded: sums and differences both multiplied by a constant < q
    k = ceil_q(M + 1)
    S["inv512"] = k
    s_out = redc_max(2 * M * ZMAX)
    d_out = redc_max((M + k * q) * ZMAX)
    M = max(s_out, d_out)
    log.append((f"inv t=512 bias {k}q, x 1/1024", M))
    M = barrett_max(M)
    log.append(("inv Barrett final", M))
    assert M < 2 * q
    log.append(("inv cond -q", q - 1))
    S["log"] = log
    return S


SCHED = schedule()


# ---------------------------------------------------------------- emitters
def rep8(v):
    return sum(v << (32 * i) for i in range(8))


def lanes(v, idx):
    return sum(v << (32 * i) for i in idx)


def hx(v):
    return "0x" + format(v, "064x")


CONSTS = {}


def C(name, value):
    if name in CONSTS:
        assert CONSTS[name] == value
    CONSTS[name] = value
    return name


def BQ8(k):
    return C(f"_F10_Q8x{k}", rep8(k * q))


def RED(v):
    return f"{v} := shr(16, add({v}, mul(and(mul(and({v}, _F10_M16), 12287), _F10_M16), 12289)))"


def BAR(v):
    return f"{v} := sub({v}, mul(and(shr(18, mul({v}, 21)), _F10_Q5), 12289))"


def CONDQ(v):
    return f"{v} := sub({v}, mul(shr(17, and(add({v}, _F10_CQ17), _F10_G17)), 12289))"


def COND4(expr):
    return f"sub({expr}, mul(shr(17, and(add({expr}, _F10_C4Q17), _F10_G17)), 49156))"


C("_F10_M16", rep8(0xFFFF))
C("_F10_Q5", rep8(0x1F))
C("_F10_G17", rep8(1 << 17))
C("_F10_CQ17", rep8((1 << 17) - q))
C("_F10_C4Q17", rep8((1 << 17) - 4 * q))
C("_F10_LO128", (1 << 128) - 1)
C("_F10_M0145", lanes(0xFFFFFFFF, (0, 1, 4, 5)))
C("_F10_M0246", lanes(0xFFFFFFFF, (0, 2, 4, 6)))
C("_F10_M01", (1 << 64) - 1)
C("_F10_M45", ((1 << 64) - 1) << 128)
for _j in (0, 2, 4, 6):
    C(f"_F10_LN{_j}", 0xFFFFFFFF << (32 * _j))
# spread / gather between 8 x 16-bit fields and 8 x 32-bit lanes (128-bit halves)
C("_F10_L64", (1 << 64) - 1)
C("_F10_SA", 0xFFFFFFFF | (0xFFFFFFFF << 128))
C("_F10_SB", (0xFFFFFFFF << 32) | (0xFFFFFFFF << 160))
C("_F10_SC", sum(0xFFFF << (64 * i) for i in range(4)))
C("_F10_SD", sum(0xFFFF0000 << (64 * i) for i in range(4)))
C("_F10_H64", ((1 << 64) - 1) << 64)


def spread(x):
    """half word (8 fields of 16 bits, bits 0..127) -> 8 lanes"""
    return [
        f"{x} := or(and({x}, _F10_L64), shl(64, and({x}, _F10_H64)))",
        f"{x} := or(and({x}, _F10_SA), shl(32, and({x}, _F10_SB)))",
        f"{x} := or(and({x}, _F10_SC), shl(16, and({x}, _F10_SD)))",
    ]


def gather(x):
    """8 lanes (values < 2^16) -> half word of 8 fields of 16 bits"""
    return [
        f"{x} := or(and({x}, _F10_SC), shr(16, and({x}, shl(32, _F10_SC))))",
        f"{x} := or(and({x}, _F10_SA), shr(32, and({x}, shl(64, _F10_SA))))",
        f"{x} := or(and({x}, _F10_L64), shr(64, and({x}, shl(128, _F10_L64))))",
    ]


def indent(lines, n):
    pad = " " * n
    return "\n".join(pad + l if l else l for l in lines)


def tw_at(ptr, off=0):
    src = ptr if off == 0 else f"add({ptr}, {off})"
    return f"and(shr(240, mload({src})), 0xffff)"


def ct_octet(ld, st, tw, K):
    """Cooley-Tukey radix-8 body on an octet of words; K = biases (in q) of the three layers"""
    b1, b2, b3 = BQ8(K[0]), BQ8(K[1]), BQ8(K[2])
    L = ["let c0, c2, c4, c6", "{"]
    L += [
        f"    let u0 := {ld(0)}",
        f"    let t := mul({ld(4)}, {tw['S1']})",
        "    " + RED("t"),
        "    let a0 := add(u0, t)",
        f"    u0 := sub(add(u0, {b1}), t)",
        f"    let u2 := {ld(2)}",
        f"    t := mul({ld(6)}, {tw['S1']})",
        "    " + RED("t"),
        "    let a2 := add(u2, t)",
        f"    u2 := sub(add(u2, {b1}), t)",
        f"    t := mul(a2, {tw['S2a']})",
        "    " + RED("t"),
        "    c0 := add(a0, t)",
        f"    c2 := sub(add(a0, {b2}), t)",
        f"    t := mul(u2, {tw['S2b']})",
        "    " + RED("t"),
        "    c4 := add(u0, t)",
        f"    c6 := sub(add(u0, {b2}), t)",
        "}",
        "{",
        f"    let u1 := {ld(1)}",
        f"    let t := mul({ld(5)}, {tw['S1']})",
        "    " + RED("t"),
        "    let a1 := add(u1, t)",
        f"    let b1 := sub(add(u1, {b1}), t)",
        f"    u1 := {ld(3)}",
        f"    t := mul({ld(7)}, {tw['S1']})",
        "    " + RED("t"),
        "    let a3 := add(u1, t)",
        f"    u1 := sub(add(u1, {b1}), t)",
        f"    t := mul(a3, {tw['S2a']})",
        "    " + RED("t"),
        f"    a3 := sub(add(a1, {b2}), t)",
        "    a1 := add(a1, t)",
        f"    t := mul(u1, {tw['S2b']})",
        "    " + RED("t"),
        f"    u1 := sub(add(b1, {b2}), t)",
        "    b1 := add(b1, t)",
    ]
    for lo, hi, k in (("c0", "a1", 0), ("c2", "a3", 2), ("c4", "b1", 4), ("c6", "u1", 6)):
        L += [
            f"    t := mul({hi}, {tw['S3'][k // 2]})",
            "    " + RED("t"),
            f"    {st(k, f'add({lo}, t)')}",
            f"    {st(k + 1, f'sub(add({lo}, {b3}), t)')}",
        ]
    L.append("}")
    return L


def gs_octet(ld, st, tw, K, red):
    """Gentleman-Sande radix-8 body; K = biases (in q), red = sums reduced by -4q per layer"""
    b1, b2, b3 = BQ8(K[0]), BQ8(K[1]), BQ8(K[2])

    def S(expr, layer):
        return COND4(expr) if red[layer] else expr

    L = ["let b0, b1, b2, b3", "{"]
    L += [
        f"    let u := {ld(0)}",
        f"    let v := {ld(1)}",
        f"    let t := mul(sub(add(u, {b1}), v), {tw['S3'][0]})",
        "    " + RED("t"),
        f"    u := {S('add(u, v)', 0)}",
        f"    v := {ld(2)}",
        f"    let w := {ld(3)}",
        f"    let s := mul(sub(add(v, {b1}), w), {tw['S3'][1]})",
        "    " + RED("s"),
        f"    v := {S('add(v, w)', 0)}",
        f"    w := mul(sub(add(u, {b2}), v), {tw['S2a']})",
        "    " + RED("w"),
        f"    b0 := {S('add(u, v)', 1)}",
        "    b2 := w",
        f"    w := mul(sub(add(t, {b2}), s), {tw['S2a']})",
        "    " + RED("w"),
        f"    b1 := {S('add(t, s)', 1)}",
        "    b3 := w",
        "}",
        "{",
        f"    let u := {ld(4)}",
        f"    let v := {ld(5)}",
        f"    let t := mul(sub(add(u, {b1}), v), {tw['S3'][2]})",
        "    " + RED("t"),
        f"    u := {S('add(u, v)', 0)}",
        f"    v := {ld(6)}",
        f"    let w := {ld(7)}",
        f"    let s := mul(sub(add(v, {b1}), w), {tw['S3'][3]})",
        "    " + RED("s"),
        f"    v := {S('add(v, w)', 0)}",
        f"    w := mul(sub(add(u, {b2}), v), {tw['S2b']})",
        "    " + RED("w"),
        f"    u := {S('add(u, v)', 1)}",
        f"    v := mul(sub(add(t, {b2}), s), {tw['S2b']})",
        "    " + RED("v"),
        f"    t := {S('add(t, s)', 1)}",
    ]
    for lo, hi, k in (("b0", "u", 0), ("b1", "t", 1), ("b2", "w", 2), ("b3", "v", 3)):
        L += [
            f"    s := mul(sub(add({lo}, {b3}), {hi}), {tw['S1']})",
            "    " + RED("s"),
            f"    {st(k + 4, 's')}",
            f"    {st(k, S(f'add({lo}, {hi})', 2))}",
        ]
    L.append("}")
    return L


def ldp(k, stride):
    return "mload(p)" if k == 0 else f"mload(add(p, {hex(k * stride)}))"


def stp(k, e, stride):
    return f"mstore(p, {e})" if k == 0 else f"mstore(add(p, {hex(k * stride)}), {e})"


FWK = SCHED["fw"]  # 10 biases: 512, 256, 128, 64, 32, 16, 8, 4, 2, 1
INVK = SCHED["inv"]  # 9 (bias, reduce): 1, 2, 4, 8, 16, 32, 64, 128, 256


def fw_A0():
    k = FWK[0]
    L = [
        "let x := and(shr(ks, mload(src)), _F10_LO128)",
        *spread("x"),
        "bad := or(bad, and(add(x, _F10_CQ17), _F10_G17))",
        "let y := and(shr(ks, mload(add(src, 0x400))), _F10_LO128)",
        *spread("y"),
        "bad := or(bad, and(add(y, _F10_CQ17), _F10_G17))",
        f"y := mul(y, {hex(FWM[1])})",
        RED("y"),
        "mstore(p, add(x, y))",
        f"mstore(add(p, 0x800), sub(add(x, {BQ8(k)}), y))",
    ]
    return L


def fw_inword():
    kb4, kb2, kb1 = FWK[7], FWK[8], FWK[9]
    L = ["let W := mload(p)", BAR("W")]
    L += [
        "let V := mul(shr(128, W), and(shr(240, mload(t1)), 0xffff))",
        RED("V"),
        "let lo := and(W, _F10_LO128)",
        f"W := or(add(lo, V), shl(128, sub(add(lo, {C(f'_F10_LOx{kb4}', lanes(kb4 * q, range(4)))}), V)))",
    ]
    L += [
        "V := shr(224, mload(t2))",
        "lo := and(shr(64, W), _F10_M0145)",
        "V := or(and(mul(lo, shr(16, V)), _F10_M01), and(mul(lo, and(V, 0xffff)), _F10_M45))",
        RED("V"),
        "lo := and(W, _F10_M0145)",
        f"W := or(add(lo, V), shl(64, sub(add(lo, {C(f'_F10_0145x{kb2}', lanes(kb2 * q, (0, 1, 4, 5)))}), V)))",
    ]
    L += [
        "V := shr(192, mload(t3))",
        "lo := and(shr(32, W), _F10_M0246)",
        "V := or(or(and(mul(lo, shr(48, V)), _F10_LN0), and(mul(lo, and(shr(32, V), 0xffff)), _F10_LN2)), or(and(mul(lo, and(shr(16, V), 0xffff)), _F10_LN4), and(mul(lo, and(V, 0xffff)), _F10_LN6)))",
        RED("V"),
        "lo := and(W, _F10_M0246)",
        f"W := or(add(lo, V), shl(32, sub(add(lo, {C(f'_F10_0246x{kb1}', lanes(kb1 * q, (0, 2, 4, 6)))}), V)))",
    ]
    L += [BAR("W"), CONDQ("W"), *gather("W"), "mstore(op, or(mload(op), shl(ks, W)))"]
    return L


def inv_inword():
    (k1, r1), (k2, r2), (k4, r4) = INVK[0], INVK[1], INVK[2]
    L = [
        "let W := and(shr(ks, mload(src)), _F10_LO128)",
        *spread("W"),
        "bad := or(bad, and(add(W, _F10_CQ17), _F10_G17))",
    ]

    def sum_(e, r):
        return COND4(e) if r else e

    L += [
        "let V := shr(192, mload(t3))",
        "let lo := and(W, _F10_M0246)",
        "W := and(shr(32, W), _F10_M0246)",
        f"let d := sub(add(lo, {C(f'_F10_0246x{k1}', lanes(k1 * q, (0, 2, 4, 6)))}), W)",
        f"lo := {sum_('add(lo, W)', r1)}",
        "W := or(or(and(mul(d, shr(48, V)), _F10_LN0), and(mul(d, and(shr(32, V), 0xffff)), _F10_LN2)), or(and(mul(d, and(shr(16, V), 0xffff)), _F10_LN4), and(mul(d, and(V, 0xffff)), _F10_LN6)))",
        RED("W"),
        "W := or(lo, shl(32, W))",
    ]
    L += [
        "V := shr(224, mload(t2))",
        "lo := and(W, _F10_M0145)",
        "W := and(shr(64, W), _F10_M0145)",
        f"d := sub(add(lo, {C(f'_F10_0145x{k2}', lanes(k2 * q, (0, 1, 4, 5)))}), W)",
        f"lo := {sum_('add(lo, W)', r2)}",
        "W := or(and(mul(d, shr(16, V)), _F10_M01), and(mul(d, and(V, 0xffff)), _F10_M45))",
        RED("W"),
        "W := or(lo, shl(64, W))",
    ]
    L += [
        "V := and(shr(240, mload(t1)), 0xffff)",
        "lo := and(W, _F10_LO128)",
        "W := shr(128, W)",
        f"d := mul(sub(add(lo, {C(f'_F10_LOx{k4}', lanes(k4 * q, range(4)))}), W), V)",
        RED("d"),
        f"mstore(p, or({sum_('add(lo, W)', r4)}, shl(128, d)))",
    ]
    return L


def inv_A0():
    k = SCHED["inv512"]
    return [
        "let x := mload(p)",
        "let y := mload(add(p, 0x800))",
        f"let s := mul(add(x, y), {hex(CN)})",
        RED("s"),
        BAR("s"),
        CONDQ("s"),
        *gather("s"),
        "mstore(op, or(mload(op), shl(ks, s)))",
        f"s := mul(sub(add(x, {BQ8(k)}), y), {hex(DN)})",
        RED("s"),
        BAR("s"),
        CONDQ("s"),
        *gather("s"),
        "mstore(add(op, 0x400), or(mload(add(op, 0x400)), shl(ks, s)))",
    ]


def table_hex(t):
    return "".join(format(x, "04x") for x in t)


def tw_const(tbl, i):
    return hex(tbl[i])


def emit():
    fwA = [
        {"S1": tw_const(FWM, 2 + b), "S2a": tw_const(FWM, 4 + 2 * b), "S2b": tw_const(FWM, 5 + 2 * b), "S3": [tw_const(FWM, 8 + 4 * b + k) for k in range(4)]}
        for b in (0, 1)
    ]
    invA = [
        {"S1": tw_const(INVM, 2 + b), "S2a": tw_const(INVM, 4 + 2 * b), "S2b": tw_const(INVM, 5 + 2 * b), "S3": [tw_const(INVM, 8 + 4 * b + k) for k in range(4)]}
        for b in (0, 1)
    ]
    twB = {"S1": tw_at("t1"), "S2a": tw_at("t2"), "S2b": tw_at("t2", 2), "S3": [tw_at("t3", 2 * k) for k in range(4)]}
    ld8 = lambda k: ldp(k, 0x100)
    st8 = lambda k, e: stp(k, e, 0x100)
    ld1 = lambda k: ldp(k, 0x20)
    st1 = lambda k, e: stp(k, e, 0x20)
    invAK = [k for k, _ in INVK[6:9]]
    invAR = [r for _, r in INVK[6:9]]
    invBK = [k for k, _ in INVK[3:6]]
    invBR = [r for _, r in INVK[3:6]]

    passA = []
    for b in (0, 1):
        passA += [
            f"// block {b}: words {64 * b}..{64 * b + 63}",
            "{",
            f"    let p := add(A, {hex(32 + 32 * 64 * b)})",
            "    for { let e := add(p, 0x100) } lt(p, e) { p := add(p, 32) } {",
            indent(ct_octet(ld8, st8, fwA[b], FWK[1:4]), 8),
            "    }",
            "}",
        ]
    passAinv = []
    for b in (0, 1):
        passAinv += [
            f"// block {b}: words {64 * b}..{64 * b + 63}",
            "{",
            f"    let p := add(A, {hex(32 + 32 * 64 * b)})",
            "    for { let e := add(p, 0x100) } lt(p, e) { p := add(p, 32) } {",
            indent(gs_octet(ld8, st8, invA[b], invAK, invAR), 8),
            "    }",
            "}",
        ]

    body = f"""
/// @dev forward t = 512: spread the compact input (64 words) to 128 lane words; flags fields >= q
function _f10FwA0(uint256[] memory c, uint256[] memory A) pure returns (uint256 bad) {{
    assembly ("memory-safe") {{
        let src := add(c, 32)
        let p := add(A, 32)
        let ks := 0
        for {{ let e := add(p, 0x800) }} lt(p, e) {{ p := add(p, 32) }} {{
{indent(fw_A0(), 12)}
            src := add(src, shr(2, ks))
            ks := xor(ks, 128)
        }}
    }}
}}

/// @dev forward t = 256, 128, 64: radix-8 on word octets (i + 8k), twiddles as constants
function _f10FwA(uint256[] memory A) pure {{
    assembly ("memory-safe") {{
{indent(passA, 8)}
    }}
}}

/// @dev forward t = 32, 16, 8: radix-8 on eight consecutive words, twiddles from the table
function _f10FwB(uint256[] memory A, uint256 tb) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        let t1 := add(tb, 32)
        let t2 := add(tb, 64)
        let t3 := add(tb, 128)
        for {{ let e := add(p, 0x1000) }} lt(p, e) {{ p := add(p, 0x100) }} {{
{indent(ct_octet(ld1, st1, twB, FWK[4:7]), 12)}
            t1 := add(t1, 2)
            t2 := add(t2, 4)
            t3 := add(t3, 8)
        }}
    }}
}}

/// @dev forward t = 4, 2, 1 inside each word (SWAR), canonical output gathered into the compact result
function _f10FwW(uint256[] memory A, uint256[] memory out, uint256 tb) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        let op := add(out, 32)
        let ks := 0
        // fw[128 + w] at byte 256 + 2w, fw[256 + 2w] at 512 + 4w, fw[512 + 4w] at 1024 + 8w
        let t1 := add(tb, 256)
        let t2 := add(tb, 512)
        let t3 := add(tb, 1024)
        for {{ let e := add(p, 0x1000) }} lt(p, e) {{ p := add(p, 32) }} {{
{indent(fw_inword(), 12)}
            t1 := add(t1, 2)
            t2 := add(t2, 4)
            t3 := add(t3, 8)
            op := add(op, shr(2, ks))
            ks := xor(ks, 128)
        }}
    }}
}}

/// @dev inverse t = 1, 2, 4 inside each word, spread from the compact input; flags fields >= q
function _f10InvW(uint256[] memory c, uint256[] memory A, uint256 tb) pure returns (uint256 bad) {{
    assembly ("memory-safe") {{
        let src := add(c, 32)
        let p := add(A, 32)
        let ks := 0
        let t1 := add(tb, 256)
        let t2 := add(tb, 512)
        let t3 := add(tb, 1024)
        for {{ let e := add(p, 0x1000) }} lt(p, e) {{ p := add(p, 32) }} {{
{indent(inv_inword(), 12)}
            t1 := add(t1, 2)
            t2 := add(t2, 4)
            t3 := add(t3, 8)
            src := add(src, shr(2, ks))
            ks := xor(ks, 128)
        }}
    }}
}}

/// @dev inverse t = 8, 16, 32
function _f10InvB(uint256[] memory A, uint256 tb) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        let t1 := add(tb, 32)
        let t2 := add(tb, 64)
        let t3 := add(tb, 128)
        for {{ let e := add(p, 0x1000) }} lt(p, e) {{ p := add(p, 0x100) }} {{
{indent(gs_octet(ld1, st1, twB, invBK, invBR), 12)}
            t1 := add(t1, 2)
            t2 := add(t2, 4)
            t3 := add(t3, 8)
        }}
    }}
}}

/// @dev inverse t = 64, 128, 256
function _f10InvA(uint256[] memory A) pure {{
    assembly ("memory-safe") {{
{indent(passAinv, 8)}
    }}
}}

/// @dev inverse t = 512 with 1024^-1 folded, canonical output gathered into the compact result
function _f10InvA0(uint256[] memory A, uint256[] memory out) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        let op := add(out, 32)
        let ks := 0
        for {{ let e := add(p, 0x800) }} lt(p, e) {{ p := add(p, 32) }} {{
{indent(inv_A0(), 12)}
            op := add(op, shr(2, ks))
            ks := xor(ks, 128)
        }}
    }}
}}

/// @notice forward NTT of a Falcon-1024 polynomial, compact form (64 words, coefficient
///         16c + i in 16-bit field i of word c), canonical coefficients in and out
function falconNTT1024(uint256[] memory a) pure returns (uint256[] memory out) {{
    require(a.length == 64, "compact length");
    bytes memory tw = _F10_TW;
    uint256 tb;
    assembly ("memory-safe") {{
        tb := add(tw, 32)
    }}
    uint256[] memory A = new uint256[](128);
    require(_f10FwA0(a, A) == 0, "coefficient >= q");
    _f10FwA(A);
    _f10FwB(A, tb);
    out = new uint256[](64);
    _f10FwW(A, out, tb);
}}

/// @notice inverse NTT (scaled by 1024^-1) of a Falcon-1024 polynomial, compact form,
///         canonical coefficients in and out
function falconINTT1024(uint256[] memory a) pure returns (uint256[] memory out) {{
    require(a.length == 64, "compact length");
    bytes memory tw = _F10_TW;
    uint256 tb;
    assembly ("memory-safe") {{
        tb := add(tw, 2080)
    }}
    uint256[] memory A = new uint256[](128);
    require(_f10InvW(a, A, tb) == 0, "coefficient >= q");
    _f10InvB(A, tb);
    _f10InvA(A);
    out = new uint256[](64);
    _f10InvA0(A, out);
}}
"""
    sched = "\n".join(f"//   {name:<28} lanes <= {m} ({m / q:.3f} q)" for name, m in SCHED["log"])
    consts = "\n".join(f"uint256 constant {k} = {hx(v)};" for k, v in CONSTS.items())
    return f"""// SPDX-License-Identifier: MIT
// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_NTT_falcon1024.sol
// GENERATED by pythonref/gen_ntt1024.py -- do not edit by hand.
//
// Forward and inverse NTT for Falcon-1024 (q = 12289, n = 1024) on EIGHT 32-bit
// lanes per word, Montgomery R = 2^16 (-q^-1 mod R = 12287), same machinery as
// ZKNOX_NTT_falcon8.sol (Falcon-512).
// Tables: psi_rev[i] = 7^brv10(i) mod q, the convention of ZKNOX_NTT.sol and of
// @noble/post-quantum (falcon, ROOT_OF_UNITY = 7, brvBits = 10).
// Layout: 128 words, coefficient 8w + j in lane j (bits 32j..32j+31) of word w.
//   forward  A0 t = 512 | A t = 256, 128, 64 (word octets i + 8k) | B t = 32, 16, 8
//            (eight consecutive words) | W t = 4, 2, 1 inside the word (SWAR)
//   inverse  W' t = 1, 2, 4 | B' t = 8, 16, 32 | A' t = 64, 128, 256 | A0' t = 512
//            with 1024^-1 folded (sums * {hex(CN)}, differences * {hex(DN)})
// Lane bounds, asserted by the generator:
{sched}
// Twiddle table: forward then inverse, 1,024 big-endian uint16 each, entries in
// Montgomery form (x R mod q), read by unaligned mload at running pointers.
pragma solidity ^0.8.25;

{consts}

bytes constant _F10_TW = hex"{table_hex(FWM)}{table_hex(INVM)}";
{body}"""


if __name__ == "__main__":
    if "--schedule" in sys.argv:
        for name, m in SCHED["log"]:
            print(f"{name:<30} {m:>7}  {m / q:.3f} q")
        print("fw biases", FWK, "inv", INVK, "inv512", SCHED["inv512"])
    else:
        sys.stdout.write(emit())
