#!/usr/bin/env python3
# gen_ntt1024.py -- emits src/ZKNOX_NTT_falcon1024.sol: the Falcon-1024 forward and inverse
# NTT (q = 12289, n = 1024) and the fused product s1 = INTT(NTT(s2) o h) on EIGHT 32-bit
# lanes per word, Montgomery R = 2^16, same machinery as gen_ntt8.py (Falcon-512).
#
#   python3 pythonref/gen_ntt1024.py > src/ZKNOX_NTT_falcon1024.sol && forge fmt src/ZKNOX_NTT_falcon1024.sol
#   python3 pythonref/sched1024.py            (the schedules and their bounds)
#
# Convention: psi_rev[i] = 7^brv10(i) mod q, loops of eprint 2016/504 (ZKNOX_NTT.sol), INTT
# scaled by 1024^-1; the tables of @noble/post-quantum falcon and, on 512 entries, of the
# Falcon-512 code of this repo.
#
# Layout: 128 words, coefficient 8w + j in lane j (bits 32j..32j+31) of word w. Compact form:
# 64 words of sixteen 16-bit fields, coefficient 16c + i in field i.
#
# Passes: A0 t = 512 (words w, w + 64) | A t = 256, 128, 64 (word octets i + 8k, twiddles as
# constants) | B t = 32, 16, 8 (eight consecutive words) | W t = 4, 2, 1 inside the word
# (SWAR); the inverse runs them backwards, t = 512 folded with 1024^-1. Every bias, Barrett
# and REDC comes from the exact per-coefficient analysis of pythonref/sched1024.py.
import sys

import sched1024 as S

q, N, R = S.q, S.N, S.R
FWM, INVM = S.FWM, S.INVM

B_NTT, LOG_NTT, _ = S.analyze(S.spec_ntt(S.NTT_BARS))
B_INTT, LOG_INTT, _ = S.analyze(S.spec_intt(S.INTT_PRE, S.INTT_RED))
B_PROD, LOG_PROD, _ = S.analyze(S.spec_product(S.PROD_FWBARS, S.PROD_PRE, S.PROD_RED))
# the aligned forward passes are shared: same biases in both chains
assert B_NTT[:7] == B_PROD[:7]
FWK = B_NTT  # 512 .. 1
INVK = B_INTT[:9]  # 1 .. 256
INV512 = B_INTT[9]
PFWK = B_PROD[7:10]  # 4, 2, 1
PINVK = B_PROD[10:19]
PINV512 = B_PROD[19]


def rep8(v):
    return sum(v << (32 * i) for i in range(8))


def lanes(v, idx):
    return sum(v << (32 * i) for i in idx)


def hx(v):
    return "0x" + format(v, "064x")


CONSTS = {}


def C(name, value):
    if name in CONSTS:
        assert CONSTS[name] == value, name
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


C("_F10_M16", rep8(0xFFFF))
C("_F10_Q5", rep8(0x1F))
C("_F10_G17", rep8(1 << 17))
C("_F10_CQ17", rep8((1 << 17) - q))
C("_F10_LO128", (1 << 128) - 1)
C("_F10_M0145", lanes(0xFFFFFFFF, (0, 1, 4, 5)))
C("_F10_M0246", lanes(0xFFFFFFFF, (0, 2, 4, 6)))
C("_F10_M01", (1 << 64) - 1)
C("_F10_M45", ((1 << 64) - 1) << 128)
for _j in range(8):
    C(f"_F10_LN{_j}", 0xFFFFFFFF << (32 * _j))
C("_F10_L64", (1 << 64) - 1)
C("_F10_SA", 0xFFFFFFFF | (0xFFFFFFFF << 128))
C("_F10_SB", (0xFFFFFFFF << 32) | (0xFFFFFFFF << 160))
C("_F10_SC", sum(0xFFFF << (64 * i) for i in range(4)))
C("_F10_SD", sum(0xFFFF0000 << (64 * i) for i in range(4)))
C("_F10_H64", ((1 << 64) - 1) << 64)
C("_F10_CPL", rep8(S.CPL))


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
    return f"shr(240, mload({src}))"


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
    """Gentleman-Sande radix-8 body; K = biases (in q), red[l] = sums of layer l take a Barrett"""
    b1, b2, b3 = BQ8(K[0]), BQ8(K[1]), BQ8(K[2])

    def sums(var, expr, layer):
        out = [f"    {var} := {expr}"]
        if red[layer]:
            out.append("    " + BAR(var))
        return out

    L = ["let b0, b1, b2, b3", "{"]
    L += [
        f"    let u := {ld(0)}",
        f"    let v := {ld(1)}",
        f"    let t := mul(sub(add(u, {b1}), v), {tw['S3'][0]})",
        "    " + RED("t"),
        *sums("u", "add(u, v)", 0),
        f"    v := {ld(2)}",
        f"    let w := {ld(3)}",
        f"    let s := mul(sub(add(v, {b1}), w), {tw['S3'][1]})",
        "    " + RED("s"),
        *sums("v", "add(v, w)", 0),
        f"    w := mul(sub(add(u, {b2}), v), {tw['S2a']})",
        "    " + RED("w"),
        *sums("b0", "add(u, v)", 1),
        "    b2 := w",
        f"    w := mul(sub(add(t, {b2}), s), {tw['S2a']})",
        "    " + RED("w"),
        *sums("b1", "add(t, s)", 1),
        "    b3 := w",
        "}",
        "{",
        f"    let u := {ld(4)}",
        f"    let v := {ld(5)}",
        f"    let t := mul(sub(add(u, {b1}), v), {tw['S3'][2]})",
        "    " + RED("t"),
        *sums("u", "add(u, v)", 0),
        f"    v := {ld(6)}",
        f"    let w := {ld(7)}",
        f"    let s := mul(sub(add(v, {b1}), w), {tw['S3'][3]})",
        "    " + RED("s"),
        *sums("v", "add(v, w)", 0),
        f"    w := mul(sub(add(u, {b2}), v), {tw['S2b']})",
        "    " + RED("w"),
        *sums("u", "add(u, v)", 1),
        f"    v := mul(sub(add(t, {b2}), s), {tw['S2b']})",
        "    " + RED("v"),
        *sums("t", "add(t, s)", 1),
    ]
    for lo, hi, k in (("b0", "u", 0), ("b1", "t", 1), ("b2", "w", 2), ("b3", "v", 3)):
        L += [
            f"    s := mul(sub(add({lo}, {b3}), {hi}), {tw['S1']})",
            "    " + RED("s"),
            f"    {st(k + 4, 's')}",
            *sums(lo, f"add({lo}, {hi})", 2),
            f"    {st(k, lo)}",
        ]
    L.append("}")
    return L


def ldp(k, stride):
    return "mload(p)" if k == 0 else f"mload(add(p, {hex(k * stride)}))"


def stp(k, e, stride):
    return f"mstore(p, {e})" if k == 0 else f"mstore(add(p, {hex(k * stride)}), {e})"


# ---------------------------------------------------------------- in-word pieces
def fw_t4(k):
    return [
        "V := mul(shr(128, W), shr(240, mload(t1)))",
        RED("V"),
        "lo := and(W, _F10_LO128)",
        f"W := or(add(lo, V), shl(128, sub(add(lo, {C(f'_F10_LOx{k}', lanes(k * q, range(4)))}), V)))",
    ]


def fw_t2(k):
    return [
        "V := shr(224, mload(t2))",
        "lo := and(shr(64, W), _F10_M0145)",
        "V := or(and(mul(lo, shr(16, V)), _F10_M01), and(mul(lo, and(V, 0xffff)), _F10_M45))",
        RED("V"),
        "lo := and(W, _F10_M0145)",
        f"W := or(add(lo, V), shl(64, sub(add(lo, {C(f'_F10_0145x{k}', lanes(k * q, (0, 1, 4, 5)))}), V)))",
    ]


def fw_t1(k):
    return [
        "V := shr(192, mload(t3))",
        "lo := and(shr(32, W), _F10_M0246)",
        "V := or(or(and(mul(lo, shr(48, V)), _F10_LN0), and(mul(lo, and(shr(32, V), 0xffff)), _F10_LN2)), or(and(mul(lo, and(shr(16, V), 0xffff)), _F10_LN4), and(mul(lo, and(V, 0xffff)), _F10_LN6)))",
        RED("V"),
        "lo := and(W, _F10_M0246)",
        f"W := or(add(lo, V), shl(32, sub(add(lo, {C(f'_F10_0246x{k}', lanes(k * q, (0, 2, 4, 6)))}), V)))",
    ]


def fw_kernel(bars, ks):
    L = []
    for t, k, piece in zip((4, 2, 1), ks, (fw_t4, fw_t2, fw_t1)):
        if t in bars:
            L.append(BAR("W"))
        L += piece(k)
    return L


def inv_t1(k, red, tb_off):
    L = [
        f"V := shr(192, mload({'t3' if tb_off == 0 else f'add(t3, {tb_off})'}))",
        "lo := and(W, _F10_M0246)",
        "W := and(shr(32, W), _F10_M0246)",
        f"d := sub(add(lo, {C(f'_F10_0246x{k}', lanes(k * q, (0, 2, 4, 6)))}), W)",
        "lo := add(lo, W)",
    ]
    if red:
        L.append(BAR("lo"))
    L += [
        "W := or(or(and(mul(d, shr(48, V)), _F10_LN0), and(mul(d, and(shr(32, V), 0xffff)), _F10_LN2)), or(and(mul(d, and(shr(16, V), 0xffff)), _F10_LN4), and(mul(d, and(V, 0xffff)), _F10_LN6)))",
        RED("W"),
        "W := or(lo, shl(32, W))",
    ]
    return L


def inv_t2(k, red, tb_off):
    L = [
        f"V := shr(224, mload({'t2' if tb_off == 0 else f'add(t2, {tb_off})'}))",
        "lo := and(W, _F10_M0145)",
        "W := and(shr(64, W), _F10_M0145)",
        f"d := sub(add(lo, {C(f'_F10_0145x{k}', lanes(k * q, (0, 1, 4, 5)))}), W)",
        "lo := add(lo, W)",
    ]
    if red:
        L.append(BAR("lo"))
    L += [
        "W := or(and(mul(d, shr(16, V)), _F10_M01), and(mul(d, and(V, 0xffff)), _F10_M45))",
        RED("W"),
        "W := or(lo, shl(64, W))",
    ]
    return L


def inv_t4(k, red, tb_off):
    L = [
        f"V := shr(240, mload({'t1' if tb_off == 0 else f'add(t1, {tb_off})'}))",
        "lo := and(W, _F10_LO128)",
        "W := shr(128, W)",
        f"d := mul(sub(add(lo, {C(f'_F10_LOx{k}', lanes(k * q, range(4)))}), W), V)",
        "lo := add(lo, W)",
    ]
    if red:
        L.append(BAR("lo"))
    L += [RED("d"), "W := or(lo, shl(128, d))"]
    return L


def inv_kernel(pre, red, ks, tb_off):
    L = []
    for t, k, piece in zip((1, 2, 4), ks, (inv_t1, inv_t2, inv_t4)):
        if t in pre:
            L.append(BAR("W"))
        L += piece(k, t in red, tb_off)
    return L


def pointwise():
    terms = [f"and(mul(W, {'and(V, 0xffff)' if j == 0 else f'and(shr({16 * j}, V), 0xffff)'}), _F10_LN{j})" for j in range(8)]
    return [
        "V := shr(ks, mload(kp))",
        f"W := or(or(or({terms[0]}, {terms[1]}), or({terms[2]}, {terms[3]})), or(or({terms[4]}, {terms[5]}), or({terms[6]}, {terms[7]})))",
        RED("W"),
    ]


def fw_A0(check):
    k = FWK[0]
    return [
        "let x := and(shr(ks, mload(src)), _F10_LO128)",
        *spread("x"),
        *(["bad := or(bad, and(add(x, _F10_CQ17), _F10_G17))"] if check else []),
        "let y := and(shr(ks, mload(add(src, 0x400))), _F10_LO128)",
        *spread("y"),
        *(["bad := or(bad, and(add(y, _F10_CQ17), _F10_G17))"] if check else []),
        f"y := mul(y, {hex(FWM[1])})",
        RED("y"),
        "mstore(p, add(x, y))",
        f"mstore(add(p, 0x800), sub(add(x, {BQ8(k)}), y))",
    ]


def table_hex(t):
    return "".join(format(x, "04x") for x in t)


def aligned_A(tbl, ks_or_none, ct, red=None):
    out = []
    for b in (0, 1):
        tw = {"S1": hex(tbl[2 + b]), "S2a": hex(tbl[4 + 2 * b]), "S2b": hex(tbl[5 + 2 * b]), "S3": [hex(tbl[8 + 4 * b + k]) for k in range(4)]}
        body = ct_octet(lambda k: ldp(k, 0x100), lambda k, e: stp(k, e, 0x100), tw, ks_or_none) if ct else gs_octet(lambda k: ldp(k, 0x100), lambda k, e: stp(k, e, 0x100), tw, ks_or_none, red)
        out += [
            f"// block {b}: words {64 * b}..{64 * b + 63}",
            "{",
            f"    let p := add(A, {hex(32 + 32 * 64 * b)})",
            "    for { let e := add(p, 0x100) } lt(p, e) { p := add(p, 32) } {",
            indent(body, 8),
            "    }",
            "}",
        ]
    return out


TWB = {"S1": tw_at("t1"), "S2a": tw_at("t2"), "S2b": tw_at("t2", 2), "S3": [tw_at("t3", 2 * k) for k in range(4)]}


def passB(name, doc, body):
    return f"""
/// @dev {doc}
function {name}(uint256[] memory A, uint256 tb) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        let t1 := add(tb, 32)
        let t2 := add(tb, 64)
        let t3 := add(tb, 128)
        for {{ let e := add(p, 0x1000) }} lt(p, e) {{ p := add(p, 0x100) }} {{
{indent(body, 12)}
            t1 := add(t1, 2)
            t2 := add(t2, 4)
            t3 := add(t3, 8)
        }}
    }}
}}
"""


def passA(name, doc, body):
    return f"""
/// @dev {doc}
function {name}(uint256[] memory A) pure {{
    assembly ("memory-safe") {{
{indent(body, 8)}
    }}
}}
"""


def red_flags(red, layers):
    return [t in red for t in layers]


def emit():
    ld1 = lambda k: ldp(k, 0x20)
    st1 = lambda k, e: stp(k, e, 0x20)
    body = ""
    body += f"""
/// @dev forward t = 512: spread the compact input (64 words) to 128 lane words; `check` flags fields >= q
function _f10FwA0(uint256[] memory c, uint256[] memory A) pure returns (uint256 bad) {{
    assembly ("memory-safe") {{
        let src := add(c, 32)
        let p := add(A, 32)
        let ks := 0
        for {{ let e := add(p, 0x800) }} lt(p, e) {{ p := add(p, 32) }} {{
{indent(fw_A0(True), 12)}
            src := add(src, shr(2, ks))
            ks := xor(ks, 128)
        }}
    }}
}}

/// @dev forward t = 512 for the product: s2 is canonical (checked by the caller), no flag
function _f10ProdA0(uint256[] memory c, uint256[] memory A) pure {{
    assembly ("memory-safe") {{
        let src := add(c, 32)
        let p := add(A, 32)
        let ks := 0
        for {{ let e := add(p, 0x800) }} lt(p, e) {{ p := add(p, 32) }} {{
{indent(fw_A0(False), 12)}
            src := add(src, shr(2, ks))
            ks := xor(ks, 128)
        }}
    }}
}}
"""
    body += passA("_f10FwA", "forward t = 256, 128, 64: radix-8 on word octets (i + 8k), twiddles as constants", aligned_A(FWM, FWK[1:4], True))
    body += passB("_f10FwB", "forward t = 32, 16, 8: radix-8 on eight consecutive words, twiddles from the table", ct_octet(ld1, st1, TWB, FWK[4:7]))
    body += f"""
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
{indent(["let W := mload(p)", "let V", "let lo", *fw_kernel(S.NTT_BARS, FWK[7:10]), BAR("W"), CONDQ("W"), *gather("W"), "mstore(op, or(mload(op), shl(ks, W)))"], 12)}
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
{indent(["let W := and(shr(ks, mload(src)), _F10_LO128)", *spread("W"), "bad := or(bad, and(add(W, _F10_CQ17), _F10_G17))", "let V", "let lo", "let d", *inv_kernel(S.INTT_PRE, S.INTT_RED, INVK[0:3], 0), "mstore(p, W)"], 12)}
            t1 := add(t1, 2)
            t2 := add(t2, 4)
            t3 := add(t3, 8)
            src := add(src, shr(2, ks))
            ks := xor(ks, 128)
        }}
    }}
}}
"""
    body += passB("_f10InvB", "inverse t = 8, 16, 32 (standalone INTT)", gs_octet(ld1, st1, TWB, INVK[3:6], red_flags(S.INTT_RED, (8, 16, 32))))
    body += passA("_f10InvA", "inverse t = 64, 128, 256 (standalone INTT)", aligned_A(INVM, INVK[6:9], False, red_flags(S.INTT_RED, (64, 128, 256))))
    body += f"""
/// @dev inverse t = 512 with 1024^-1 folded, canonical output gathered into the compact result
function _f10InvA0(uint256[] memory A, uint256[] memory out) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        let op := add(out, 32)
        let ks := 0
        for {{ let e := add(p, 0x800) }} lt(p, e) {{ p := add(p, 32) }} {{
{indent(["let x := mload(p)", "let y := mload(add(p, 0x800))", f"let s := mul(add(x, y), {hex(S.CN)})", RED("s"), BAR("s"), CONDQ("s"), *gather("s"), "mstore(op, or(mload(op), shl(ks, s)))", f"s := mul(sub(add(x, {BQ8(INV512)}), y), {hex(S.DN)})", RED("s"), BAR("s"), CONDQ("s"), *gather("s"), "mstore(add(op, 0x400), or(mload(add(op, 0x400)), shl(ks, s)))"], 12)}
            op := add(op, shr(2, ks))
            ks := xor(ks, 128)
        }}
    }}
}}

/// @dev product kernel inside each word: forward t = 4, 2, 1, pointwise by the compact key
///      (one REDC, R^-1 left on the values), inverse t = 1, 2, 4
function _f10ProdW(uint256[] memory A, uint256[] memory h, uint256 tb) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        // forward entries as in _f10FwW, the inverse ones 2,048 bytes further
        let t1 := add(tb, 256)
        let t2 := add(tb, 512)
        let t3 := add(tb, 1024)
        let kp := add(h, 32)
        let ks := 0
        for {{ let e := add(p, 0x1000) }} lt(p, e) {{ p := add(p, 32) }} {{
{indent(["let W := mload(p)", "let V", "let lo", "let d", *fw_kernel(S.PROD_FWBARS, PFWK), *pointwise(), *inv_kernel(S.PROD_PRE, S.PROD_RED, PINVK[0:3], 2048), "mstore(p, W)"], 12)}
            t1 := add(t1, 2)
            t2 := add(t2, 4)
            t3 := add(t3, 8)
            kp := add(kp, shr(2, ks))
            ks := xor(ks, 128)
        }}
    }}
}}
"""
    body += passB("_f10ProdInvB", "inverse t = 8, 16, 32 of the product", gs_octet(ld1, st1, TWB, PINVK[3:6], red_flags(S.PROD_RED, (8, 16, 32))))
    body += passA("_f10ProdInvA", "inverse t = 64, 128, 256 of the product", aligned_A(INVM, PINVK[6:9], False, red_flags(S.PROD_RED, (64, 128, 256))))
    body += f"""
/// @dev last inverse layer of the product: t = 512 with 1024^-1 and R folded, lanes stored
///      as 3q + 6144 - s1_i
function _f10ProdA0Inv(uint256[] memory A) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        for {{ let e := add(p, 0x800) }} lt(p, e) {{ p := add(p, 32) }} {{
{indent(["let x := mload(p)", "let y := mload(add(p, 0x800))", f"let s := mul(add(x, y), {hex(S.CNR)})", RED("s"), "mstore(p, sub(_F10_CPL, s))", f"s := mul(sub(add(x, {BQ8(PINV512)}), y), {hex(S.DNR)})", RED("s"), "mstore(add(p, 0x800), sub(_F10_CPL, s))"], 12)}
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

/// @notice s1 = INTT(NTT(s2) o h) for Falcon-1024: s2 compact and canonical (64 words of
///         16-bit fields), h the compact NTT-domain key (16-bit fields, not range-checked).
///         Result PACKED on eight 32-bit lanes per word (coefficient 8w + j in lane j of
///         word w), each lane holding 3q + 6144 - x with x <= {LOG_PROD[-1][1]} congruent to s1_i,
///         the term the norm sampler of ZKNOX_falcon1024_core.sol adds to a hash candidate.
function falconProduct1024(uint256[] memory s2, uint256[] memory h) pure returns (uint256[] memory A) {{
    require(s2.length == 64 && h.length == 64, "compact length");
    bytes memory tw = _F10_TW;
    uint256 tb;
    assembly ("memory-safe") {{
        tb := add(tw, 32)
    }}
    A = new uint256[](128);
    _f10ProdA0(s2, A);
    _f10FwA(A);
    _f10FwB(A, tb);
    _f10ProdW(A, h, tb);
    _f10ProdInvB(A, tb + 2048);
    _f10ProdInvA(A);
    _f10ProdA0Inv(A);
}}
"""

    def fmt(title, log):
        return [f"//   {title}"] + [f"//     {label:<34} lanes <= {m} ({m / q:.3f} q)" for label, m in log]

    sched = "\n".join(fmt("falconNTT1024", LOG_NTT) + fmt("falconINTT1024", LOG_INTT) + fmt("falconProduct1024", LOG_PROD))
    consts = "\n".join(f"uint256 constant {k} = {hx(v)};" for k, v in CONSTS.items())
    return f"""// SPDX-License-Identifier: MIT
// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_NTT_falcon1024.sol
// GENERATED by pythonref/gen_ntt1024.py -- do not edit by hand.
//
// Forward and inverse NTT for Falcon-1024 (q = 12289, n = 1024) and the fused product
// s1 = INTT(NTT(s2) o h), on EIGHT 32-bit lanes per word, Montgomery R = 2^16
// (-q^-1 mod R = 12287), same machinery as ZKNOX_NTT_falcon8.sol (Falcon-512).
// Tables: psi_rev[i] = 7^brv10(i) mod q, the convention of ZKNOX_NTT.sol and of
// @noble/post-quantum (falcon, ROOT_OF_UNITY = 7, brvBits = 10).
// Layout: 128 words, coefficient 8w + j in lane j (bits 32j..32j+31) of word w.
//   forward  A0 t = 512 | A t = 256, 128, 64 (word octets i + 8k) | B t = 32, 16, 8
//            (eight consecutive words) | W t = 4, 2, 1 inside the word (SWAR)
//   inverse  W' t = 1, 2, 4 | B' t = 8, 16, 32 | A' t = 64, 128, 256 | A0' t = 512 folded
//            (INTT: 1024^-1 = sums * {hex(S.CN)}, differences * {hex(S.DN)}; product: the
//            pointwise R as well, {hex(S.CNR)} and {hex(S.DNR)})
// Biases, Barretts (M = 21) and REDC locality come from the exact per-coefficient bound
// analysis of pythonref/sched1024.py (actual twiddle of every butterfly); maxima:
{sched}
// Twiddle table: forward then inverse, 1,024 big-endian uint16 each, entries in
// Montgomery form (x R mod q), read by unaligned mload at running pointers.
pragma solidity ^0.8.25;

{consts}

bytes constant _F10_TW = hex"{table_hex(FWM)}{table_hex(INVM)}";
{body}"""


if __name__ == "__main__":
    sys.stdout.write(emit())
