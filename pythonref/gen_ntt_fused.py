#!/usr/bin/env python3
# gen_ntt_fused.py -- emits src/ZKNOX_NTT_falcon_fused.sol
#
# The radix-8 octet bodies are repetitive (12 butterflies each) and the stack
# discipline (<= 16 reachable slots under the legacy codegen, no spilling)
# depends on the exact order of loads, temporaries and scopes. Generating them
# keeps the four bodies (forward A/B, inverse A'/B') consistent and reviewable
# from ONE place:
#
#   python3 pythonref/gen_ntt_fused.py > src/ZKNOX_NTT_falcon_fused.sol \
#       && forge fmt src/ZKNOX_NTT_falcon_fused.sol
#
# Twiddle tables are read verbatim from src/ZKNOX_NTT_falcon_packed.sol, so the
# fused transform uses exactly the same twiddle per butterfly as the layer by
# layer packed transform it is measured against (test/ntt_fused.t.sol).
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "..", "src", "ZKNOX_NTT_falcon_packed.sol")).read()
ARRAYS = re.findall(r"uint256\[32\] memory psirev = \[(.*?)\];", SRC, re.S)
assert len(ARRAYS) == 2, "expected the forward and inverse psirev tables"


def parse(a):
    w = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", a)]
    assert len(w) == 32
    return w


FW, INV = parse(ARRAYS[0]), parse(ARRAYS[1])
q = 12289
NINV = pow(512, -1, q)
assert NINV == 12265


def field(tbl, idx):
    return (tbl[idx >> 4] >> (16 * (idx & 15))) & 0xFFFF


def rep4(v):
    return v * (1 + (1 << 64) + (1 << 128) + (1 << 192))


def rep16(v):
    return sum(v << (16 * i) for i in range(16))


def hx(v):
    return "0x%064x" % v


def table_literal(tbl):
    lines = []
    for i, w in enumerate(tbl):
        s = "uint256(0x%x)" % w if i == 0 else "0x%x" % w
        lines.append("        " + s + ("," if i < 31 else ""))
    return "\n".join(lines)


def indent(lines, n):
    return "\n".join((" " * n + l) if l else "" for l in lines)


# Barrett, one step: M40 = floor(2^40/q). Lane-local for x < 2^37.6, residue < 2q.
def RED(v):
    return f"{v} := sub({v}, mul(and(shr(40, mul({v}, 89471204)), _QHAT24), 12289))"


# ---------------------------------------------------------------------------
# Radix-8 octet bodies. Stack budget (legacy codegen, 16 reachable slots):
#   caller keeps at most 3 variables live (A, table pointer, p);
#   the body adds 4 outer + 5 block locals = 12, plus <= 3 expression temporaries.
# ---------------------------------------------------------------------------
def ct_octet(stride, tw):
    """Forward (Cooley-Tukey) radix-8 body on the octet p + k*stride, k = 0..7.
    Layer 1 pairs (k, k+4) with S1; layer 2 pairs (0,2),(1,3) with S2a and
    (4,6),(5,7) with S2b; layer 3 pairs (2k, 2k+1) with S3[k].
    Butterfly: (u, v) -> (u + V, u + 2q - V) with V = red(v * S) < 2q."""
    o = lambda k: "p" if k == 0 else f"add(p, {hex(k * stride)})"
    L = ["let c0, c2, c4, c6", "{"]
    L += [
        f"    let u0 := mload({o(0)})",
        f"    let t := mul(mload({o(4)}), {tw['S1']})",
        "    " + RED("t"),
        "    let a0 := add(u0, t)",
        "    u0 := sub(add(u0, _Q4_2), t)",  # b0
        f"    let u2 := mload({o(2)})",
        f"    t := mul(mload({o(6)}), {tw['S1']})",
        "    " + RED("t"),
        "    let a2 := add(u2, t)",
        "    u2 := sub(add(u2, _Q4_2), t)",  # b2
        f"    t := mul(a2, {tw['S2a']})",
        "    " + RED("t"),
        "    c0 := add(a0, t)",
        "    c2 := sub(add(a0, _Q4_2), t)",
        f"    t := mul(u2, {tw['S2b']})",
        "    " + RED("t"),
        "    c4 := add(u0, t)",
        "    c6 := sub(add(u0, _Q4_2), t)",
        "}",
        "{",
        f"    let u1 := mload({o(1)})",
        f"    let t := mul(mload({o(5)}), {tw['S1']})",
        "    " + RED("t"),
        "    let a1 := add(u1, t)",
        "    let b1 := sub(add(u1, _Q4_2), t)",
        f"    u1 := mload({o(3)})",
        f"    t := mul(mload({o(7)}), {tw['S1']})",
        "    " + RED("t"),
        "    let a3 := add(u1, t)",
        "    u1 := sub(add(u1, _Q4_2), t)",  # b3
        f"    t := mul(a3, {tw['S2a']})",
        "    " + RED("t"),
        "    a3 := sub(add(a1, _Q4_2), t)",  # c3
        "    a1 := add(a1, t)",  # c1
        f"    t := mul(u1, {tw['S2b']})",
        "    " + RED("t"),
        "    u1 := sub(add(b1, _Q4_2), t)",  # c7
        "    b1 := add(b1, t)",  # c5
    ]
    for lo, hi, k in (("c0", "a1", 0), ("c2", "a3", 2), ("c4", "b1", 4), ("c6", "u1", 6)):
        L += [
            f"    t := mul({hi}, {tw['S3'][k // 2]})",
            "    " + RED("t"),
            f"    mstore({o(k)}, add({lo}, t))",
            f"    mstore({o(k + 1)}, sub(add({lo}, _Q4_2), t))",
        ]
    L.append("}")
    return L


def gs_octet(stride, tw, K, last=False):
    """Inverse (Gentleman-Sande) radix-8 body on the octet p + k*stride.
    Layer 1 pairs (2k, 2k+1) with S3[k] and bias K[0]*q; layer 2 pairs
    (0,2),(1,3) with S2a and (4,6),(5,7) with S2b, bias K[1]*q; layer 3 pairs
    (k, k+4) with S1, bias K[2]*q. Butterfly: (u, v) -> (u + v, red((u + Kq - v) * S)).
    If last: layer 3 folds n^-1 into both branches (S1 is then S1 * ninv) and
    canonicalises the outputs (< q)."""
    o = lambda k: "p" if k == 0 else f"add(p, {hex(k * stride)})"
    B = {1: "_Q4_1", 2: "_Q4_2", 4: "_Q4_4", 8: "_Q4_8", 16: "_Q4_16", 32: "_Q4_32", 64: "_Q4_64", 128: "_Q4_128", 256: "_Q4_256", 512: "_Q4_512"}
    b1, b2, b3 = B[K[0]], B[K[1]], B[K[2]]
    L = ["let b0, b1, b2, b3", "{"]
    L += [
        f"    let u := mload({o(0)})",
        f"    let v := mload({o(1)})",
        f"    let t := mul(sub(add(u, {b1}), v), {tw['S3'][0]})",
        "    " + RED("t"),  # a1
        "    u := add(u, v)",  # a0
        f"    v := mload({o(2)})",
        f"    let w := mload({o(3)})",
        f"    let s := mul(sub(add(v, {b1}), w), {tw['S3'][1]})",
        "    " + RED("s"),  # a3
        "    v := add(v, w)",  # a2
        f"    w := mul(sub(add(u, {b2}), v), {tw['S2a']})",
        "    " + RED("w"),
        "    b0 := add(u, v)",
        "    b2 := w",
        f"    w := mul(sub(add(t, {b2}), s), {tw['S2a']})",
        "    " + RED("w"),
        "    b1 := add(t, s)",
        "    b3 := w",
        "}",
        "{",
        f"    let u := mload({o(4)})",
        f"    let v := mload({o(5)})",
        f"    let t := mul(sub(add(u, {b1}), v), {tw['S3'][2]})",
        "    " + RED("t"),  # a5
        "    u := add(u, v)",  # a4
        f"    v := mload({o(6)})",
        f"    let w := mload({o(7)})",
        f"    let s := mul(sub(add(v, {b1}), w), {tw['S3'][3]})",
        "    " + RED("s"),  # a7
        "    v := add(v, w)",  # a6
        f"    w := mul(sub(add(u, {b2}), v), {tw['S2b']})",
        "    " + RED("w"),  # b6
        "    u := add(u, v)",  # b4
        f"    v := mul(sub(add(t, {b2}), s), {tw['S2b']})",
        "    " + RED("v"),  # b7
        "    t := add(t, s)",  # b5
    ]
    for lo, hi, k in (("b0", "u", 0), ("b1", "t", 1), ("b2", "w", 2), ("b3", "v", 3)):
        L += [
            f"    s := mul(sub(add({lo}, {b3}), {hi}), {tw['S1']})",
            "    " + RED("s"),
        ]
        if last:
            L += ["    s := sub(s, mul(shr(14, and(add(s, _C14), _H14)), 12289))"]
        L += [f"    mstore({o(k + 4)}, s)"]
        if last:
            L += [
                f"    s := mul(add({lo}, {hi}), 12265)",
                "    " + RED("s"),
                "    s := sub(s, mul(shr(14, and(add(s, _C14), _H14)), 12289))",
                f"    mstore({o(k)}, s)",
            ]
        else:
            L += [f"    mstore({o(k)}, add({lo}, {hi}))"]
    L.append("}")
    return L


# twiddle sources -----------------------------------------------------------
fwA = {
    "S1": hex(field(FW, 1)),
    "S2a": hex(field(FW, 2)),
    "S2b": hex(field(FW, 3)),
    "S3": [hex(field(FW, 4 + k)) for k in range(4)],
}
# pass B: scratch word at address 0 -- S8 | S4a<<16 | S4b<<32 | S2_k<<(48+16k)
fwB = {
    "S1": "and(mload(0), 0xffff)",
    "S2a": "and(shr(16, mload(0)), 0xffff)",
    "S2b": "and(shr(32, mload(0)), 0xffff)",
    "S3": [f"and(shr({48 + 16 * k}, mload(0)), 0xffff)" for k in range(4)],
}
# pass B': same scratch word, read in the other order
invB = {
    "S3": [f"and(shr({48 + 16 * k}, mload(0)), 0xffff)" for k in range(4)],
    "S2a": "and(shr(16, mload(0)), 0xffff)",
    "S2b": "and(shr(32, mload(0)), 0xffff)",
    "S1": "and(mload(0), 0xffff)",
}
invA = {
    "S3": [hex(field(INV, 4 + k)) for k in range(4)],
    "S2a": hex(field(INV, 2)),
    "S2b": hex(field(INV, 3)),
    "S1": hex(field(INV, 1) * NINV % q),
}

# the scratch word of block b, from table words 0..3 (identical for both passes)
SCRATCH_B = """{
    let w := mload(add(tb, add(64, shl(5, shr(2, b)))))
    mstore(
        0,
        or(
            or(and(shr(shl(4, add(8, b)), mload(tb)), 0xffff), shl(16, and(shr(shl(5, b), mload(add(tb, 32))), 0xffffffff))),
            shl(48, and(shr(shl(6, and(b, 3)), w), _L64))
        )
    )
}"""

C14 = rep4((1 << 14) - q)
H14 = rep4(1 << 14)
CENTER = rep4((1 << 63) - 6145)
HIGH = rep4(1 << 63)
EVEN = 0xFFFFFFFFFFFFFFFF | (0xFFFFFFFFFFFFFFFF << 128)
ODD = (0xFFFFFFFFFFFFFFFF << 64) | (0xFFFFFFFFFFFFFFFF << 192)

out = []
out.append(
    f'''// SPDX-License-Identifier: MIT
// FILE: ZKNOX_NTT_falcon_fused.sol
// GENERATED by pythonref/gen_ntt_fused.py -- edit the generator, not this file.
//
// Fused radix-8 packed-SWAR NTT for Falcon-512 (q = 12289, n = 512). Same
// layout as ZKNOX_NTT_falcon_packed.sol (128 words of four 64-bit lanes,
// coefficient 4w+j in lane j of word w), same twiddle tables, same twiddle per
// butterfly. Only the SCHEDULE changes:
//
//   forward   A : t=256,128,64 fused  octet (i, i+16, ..., i+112), 16 octets,
//                 input read STRAIGHT from the 16-bit compact form (one
//                 multiply spreads a 64-bit chunk into four lanes)
//             B : t=32,16,8   fused  octet (16b+r, +2, ..., +14), 16 octets
//             C : t=4 on the word pair (2j, 2j+1), then t=2 and t=1 in-word on
//                 extracted scalars with native mulmod
//   inverse   C': pointwise product with the compact public key folded into
//                 the lane extraction (mulmod, exact), t=1 and t=2 in-word,
//                 t=4 on the pair; output lanes < 2q
//             B': t=8,16,32  fused, sums never reduced (lanes < 16q)
//             A': t=64,128,256 fused, n^-1 folded into the last layer, outputs
//                 CANONICAL (< q)
//
// Each octet is loaded once, run through three layers on the stack and stored
// once: 8 loads + 8 stores per 12 word-butterflies instead of 24 + 24, and one
// loop iteration per 12 butterflies instead of one per butterfly.
//
// Bounds (single-step Barrett, M40 = floor(2^40/q): residue < 2q, lane-local
// as long as x * M40 < 2^64, i.e. x < 2^37.6):
//   forward: lanes enter canonical and grow by 2q per layer (V < 2q, bias 2q),
//            so < 19q after nine layers; twiddle products < 19q*q < 2^28.
//   inverse: lanes < 2q after C', sums double per layer without reduction
//            (< 16q after B', < 128q before the folded last layer); the
//            difference branch (u + Kq - v) < 2Kq with K the entry bound, so
//            every product is < 128q*q < 2^31 and every Barrett multiply < 2^58.
// The saturated (all q-1) vectors in test/ntt_fused.t.sol exercise both.
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";

uint256 constant _QHAT24 = 0x0000000000ffffff0000000000ffffff0000000000ffffff0000000000ffffff;
uint256 constant _L64 = 0xffffffffffffffff;
// in-word SWAR layers: lanes (0,1), lanes (0,2), lane 2, and 2q in those lanes
uint256 constant _LO2 = 0xffffffffffffffffffffffffffffffff;
uint256 constant _M02 = 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;
uint256 constant _L2 = 0x0000000000000000ffffffffffffffff00000000000000000000000000000000;
uint256 constant _Q2_01 = {hx(2 * q + (2 * q << 64))};
uint256 constant _Q2_02 = {hx(2 * q + (2 * q << 128))};
uint256 constant _Q4_1 = {hx(rep4(q))};
uint256 constant _Q4_2 = {hx(rep4(2 * q))};
uint256 constant _Q4_4 = {hx(rep4(4 * q))};
uint256 constant _Q4_8 = {hx(rep4(8 * q))};
uint256 constant _Q4_16 = {hx(rep4(16 * q))};
uint256 constant _Q4_32 = {hx(rep4(32 * q))};
uint256 constant _Q4_64 = {hx(rep4(64 * q))};
// canonicalisation of a lane x < 2q: x >= q  <=>  bit 14 of (x + 2^14 - q)
uint256 constant _C14 = {hx(C14)};
uint256 constant _H14 = {hx(H14)};
// 16-bit compact chunk -> 64-bit lanes: v * (1 + 2^48 + 2^96 + 2^144) lands
// field k at bit 64k; the other partial products never reach a lane's low 16
// bits when every field is < 2^15 (fields that are not are rejected by the
// range check, which reads the compact word directly)
uint256 constant _SPREAD = {hx(1 + (1 << 48) + (1 << 96) + (1 << 144))};
uint256 constant _M16L = {hx(rep4(0xFFFF))};

// ---------------------------------------------------------------------------
// twiddle tables, identical to ZKNOX_NTT_falcon_packed.sol (16 x 16-bit per
// word, psirev[i] = field i & 15 of word i >> 4). Returned as a raw pointer so
// that passing them to the passes costs nothing.
// ---------------------------------------------------------------------------
function _fwTableFused() pure returns (uint256 tb) {{
    uint256[32] memory psirev = [
{table_literal(FW)}
    ];
    assembly ("memory-safe") {{
        tb := psirev
    }}
}}

function _invTableFused() pure returns (uint256 tb) {{
    uint256[32] memory psirev = [
{table_literal(INV)}
    ];
    assembly ("memory-safe") {{
        tb := psirev
    }}
}}
'''
)


# ---------------------------------------------------------------------------
# In-word passes (t = 4 on the pair (2j, 2j+1), then t = 2 and t = 1 inside
# each word). Loop over the 16 words of the t = 1 twiddle table, four pairs
# per iteration, everything unrolled so that every twiddle is a field
# extraction with an immediate shift:
#   scratch 0x00 = S4 fields of the four pairs (bits 0..63) | S2 fields of the
#                  eight words (bits 64..191), pre-shifted once per iteration;
#   w1        = table word 16 + i1 (Sa, Sb of the eight words).
# No cursors, no conditionals, no Yul function calls; at most 9 stack slots.
# ---------------------------------------------------------------------------
SCRATCH_C = """mstore(
    0,
    or(
        and(shr(shl(6, and(i1, 3)), mload(add(tb, add(128, shl(5, shr(2, i1)))))), _L64),
        shl(64, shr(shl(7, and(i1, 1)), mload(add(tb, add(256, shl(5, shr(1, i1)))))))
    )
)
let w1 := mload(add(tb, add(512, shl(5, i1))))"""


def s4(k):
    return f"and(shr({16 * k}, mload(0)), 0xffff)" if k else "and(mload(0), 0xffff)"


def s2(k, half):
    return f"and(shr({64 + 32 * k + 16 * half}, mload(0)), 0xffff)"


def s1(k, half, which):
    sh = 64 * k + 32 * half + 16 * which
    return f"and(shr({sh}, w1), 0xffff)" if sh else "and(w1, 0xffff)"


def swar_inword(W, S2, Sa, Sb):
    """forward t = 2 then t = 1 on the packed word W, SWAR (Barrett, bias 2q per layer).
    Measured against the scalar mulmod variant: 119k vs 130k for the whole forward."""
    return [
        f"V := mul(shr(128, {W}), {S2})",
        RED("V"),
        f"lo := and({W}, _LO2)",
        f"{W} := or(add(lo, V), shl(128, sub(add(lo, _Q2_01), V)))",
        f"V := and(shr(64, {W}), _M02)",
        f"V := or(and(mul(V, {Sa}), _L64), and(mul(V, {Sb}), _L2))",
        RED("V"),
        f"lo := and({W}, _M02)",
        f"{W} := or(add(lo, V), shl(64, sub(add(lo, _Q2_02), V)))",
    ]


def fw_pair(k):
    body = [
        "{",
        "    let U := mload(p)",
        f"    let V := mul(mload(add(p, 32)), {s4(k)})",
        "    " + RED("V"),
        "    let X := sub(add(U, _Q4_2), V)",
        "    U := add(U, V)",
        "    let lo := 0",
    ]
    body += ["    " + l for l in swar_inword("U", s2(k, 0), s1(k, 0, 0), s1(k, 0, 1))]
    body += ["    mstore(p, U)"]
    body += ["    " + l for l in swar_inword("X", s2(k, 1), s1(k, 1, 0), s1(k, 1, 1))]
    body += ["    mstore(add(p, 32), X)", "}", "p := add(p, 64)"]
    return body


def inv_word(addr, chunk, S2, Sa, Sb):
    """pointwise product with the four pk coefficients of `chunk` (16-bit fields),
    GS t = 1 (Sa on lanes (0,1), Sb on (2,3)) then t = 2 (S2); output lanes canonical:
    (s0 + s1, d0 + d1, (s0 - s1) S2, (d0 - d1) S2). Scalars: mulmod (8 gas, exact)
    beats a lane-wise Barrett here, so the lanes are unpacked."""
    return [
        "{",
        f"    let W := mload({addr})",
        f"    let l0 := mulmod(and(W, _L64), and({chunk}, 0xffff), 12289)",
        f"    let l1 := mulmod(and(shr(64, W), _L64), and(shr(16, {chunk}), 0xffff), 12289)",
        f"    let l2 := mulmod(and(shr(128, W), _L64), and(shr(32, {chunk}), 0xffff), 12289)",
        f"    let l3 := mulmod(shr(192, W), and(shr(48, {chunk}), 0xffff), 12289)",
        "    // t = 1: s = a + b (< 2q), d = (a + q - b) S = (s + q - 2b) S",
        "    l0 := add(l0, l1)",
        f"    l1 := mulmod(sub(add(l0, 12289), shl(1, l1)), {Sa}, 12289)",
        "    l2 := add(l2, l3)",
        f"    l3 := mulmod(sub(add(l2, 12289), shl(1, l3)), {Sb}, 12289)",
        "    // t = 2: (s0, d0) against (s1, d1)",
        f"    W := {S2}",
        "    l3 := or(shl(64, addmod(l1, l3, 12289)), shl(192, mulmod(sub(add(l1, 12289), l3), W, 12289)))",
        "    l1 := or(mod(add(l0, l2), 12289), shl(128, mulmod(sub(add(l0, 24578), l2), W, 12289)))",
        f"    mstore({addr}, or(l1, l3))",
        "}",
    ]


def inv_pair(k):
    pkw = f"mload(add(pk, {32 + 32 * (k >> 1)}))" if False else f"mload(add(pk, add({32 + 32 * (k >> 1)}, shl(6, i1))))"
    chunk = f"shr(128, {pkw})" if (k & 1) else pkw
    body = ["{", f"    let c := {chunk}"]
    body += ["    " + l for l in inv_word("p", "c", s2(k, 0), s1(k, 0, 0), s1(k, 0, 1))]
    body += ["    " + l for l in inv_word("add(p, 32)", "shr(64, c)", s2(k, 1), s1(k, 1, 0), s1(k, 1, 1))]
    body += [
        "    {",
        "        // t = 4 (GS): (U, V) -> (U + V, red((U + q - V) * S)), lanes < 2q",
        "        let U := mload(p)",
        "        let V := mload(add(p, 32))",
        "        mstore(p, add(U, V))",
        f"        V := mul(sub(add(U, _Q4_1), V), {s4(k)})",
        "        " + RED("V"),
        "        mstore(add(p, 32), V)",
        "    }",
        "}",
        "p := add(p, 64)",
    ]
    return body


def fw_pass_c():
    lines = []
    for k in range(4):
        lines += fw_pair(k)
    return indent(lines, 12)


def inv_pass_c():
    lines = []
    for k in range(4):
        lines += inv_pair(k)
    return indent(lines, 12)


# ---------------------------------------------------------------------------
# forward
# ---------------------------------------------------------------------------
out.append(
    f'''
/// @dev Forward pass A: t = 256, 128, 64 on the octet (i, i+16, ..., i+112),
///      read straight from the compact form (word i>>2, chunk i&3 of each
///      source word). Twiddles psirev[1..7] are literals.
function _fwPassA(uint256[] memory c) pure returns (uint256[] memory A) {{
    A = new uint256[](128);
    assembly ("memory-safe") {{
        for {{ let i := 0 }} lt(i, 16) {{ i := add(i, 1) }} {{
            let p := add(add(A, 32), shl(5, i))
            {{
                let src := add(add(c, 32), shl(5, shr(2, i)))
                let sh := shl(6, and(i, 3))
                for {{ let k := 0 }} lt(k, 8) {{ k := add(k, 1) }} {{
                    mstore(
                        add(p, shl(9, k)),
                        and(mul(and(shr(sh, mload(add(src, shl(7, k)))), _L64), _SPREAD), _M16L)
                    )
                }}
            }}
{indent(ct_octet(0x200, fwA), 12)}
        }}
    }}
}}

/// @dev Forward pass B: t = 32, 16, 8 on the octets (16b + r, +2, ..., +14).
///      The seven twiddles of block b are packed once into the scratch word at 0.
function _fwPassB(uint256[] memory A, uint256 tb) pure {{
    assembly ("memory-safe") {{
        for {{ let b := 0 }} lt(b, 8) {{ b := add(b, 1) }} {{
{indent(SCRATCH_B.split(chr(10)), 12)}
            let p := add(add(A, 32), shl(9, b))
            for {{ let r := 0 }} lt(r, 2) {{ r := add(r, 1) }} {{
{indent(ct_octet(0x40, fwB), 16)}
                p := add(p, 32)
            }}
        }}
    }}
}}

/// @dev Forward pass C: t = 4 on the pair (2j, 2j+1), then t = 2 and t = 1
///      inside each word (SWAR: lanes (0,1) against (2,3) with S2, then lanes
///      0 and 2 against 1 and 3 with Sa, Sb; Barrett, bias 2q per layer).
///      Twiddles: psirev[64 + j] (table words 4..7), psirev[128 + w] (words
///      8..15), psirev[256 + 2w], psirev[257 + 2w] (words 16..31).
function _fwPassC(uint256[] memory A, uint256 tb) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        for {{ let i1 := 0 }} lt(i1, 16) {{ i1 := add(i1, 1) }} {{
{indent(SCRATCH_C.split(chr(10)), 12)}
{fw_pass_c()}
        }}
    }}
}}

/// @notice Forward NTT of a compact polynomial (32 words x 16 coefficients of
///         16 bits, every coefficient < q). Returns 128 packed words with LAZY
///         lanes (< 19q), congruent lane-wise to _nttFwPacked(_packFromCompact(c)).
function _nttFwFused(uint256[] memory c) pure returns (uint256[] memory A) {{
    A = _fwPassA(c);
    uint256 tb = _fwTableFused();
    _fwPassB(A, tb);
    _fwPassC(A, tb);
}}
'''
)

# ---------------------------------------------------------------------------
# inverse
# ---------------------------------------------------------------------------
out.append(
    f'''
/// @dev Inverse pass C': per word, lanes to scalars, pointwise product with
///      the public key (mulmod, exact), t = 1 and t = 2 in-word, then t = 4
///      on the pair (2j, 2j+1). Output lanes < 2q. Pair j reads the 64-bit
///      chunk (j & 1) of compact pk word j >> 1 (eight coefficients).
function _invPassC(uint256[] memory A, uint256[] memory pk, uint256 tb) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        for {{ let i1 := 0 }} lt(i1, 16) {{ i1 := add(i1, 1) }} {{
{indent(SCRATCH_C.split(chr(10)), 12)}
{inv_pass_c()}
        }}
    }}
}}

/// @dev Inverse pass B': t = 8, 16, 32 on the octets (16b + r, +2, ..., +14).
///      Sums are never reduced: lanes < 2q in, < 16q out.
function _invPassB(uint256[] memory A, uint256 tb) pure {{
    assembly ("memory-safe") {{
        for {{ let b := 0 }} lt(b, 8) {{ b := add(b, 1) }} {{
{indent(SCRATCH_B.split(chr(10)), 12)}
            let p := add(add(A, 32), shl(9, b))
            for {{ let r := 0 }} lt(r, 2) {{ r := add(r, 1) }} {{
{indent(gs_octet(0x40, invB, (2, 4, 8)), 16)}
                p := add(p, 32)
            }}
        }}
    }}
}}

/// @dev Inverse pass A': t = 64, 128, 256 on the octet (i, i+16, ..., i+112)
///      with n^-1 folded into the last layer (psirev[1] * n^-1 is a literal);
///      every output lane canonical (< q).
function _invPassA(uint256[] memory A) pure {{
    assembly ("memory-safe") {{
        for {{ let i := 0 }} lt(i, 16) {{ i := add(i, 1) }} {{
            let p := add(add(A, 32), shl(5, i))
{indent(gs_octet(0x200, invA, (16, 32, 64), last=True), 12)}
        }}
    }}
}}

/// @notice Pointwise product with the compact public key (32 words x 16
///         coefficients of 16 bits, every coefficient < q) followed by the
///         inverse NTT, in place on the 128 packed words A. Input lanes may be
///         lazy (any value < 2^64). Output lanes are CANONICAL (< q) and equal,
///         lane-wise, to _nttInvPacked(_vecMulPacked(A, _packFromCompact(pk)))
///         reduced mod q.
function _nttInvFusedMul(uint256[] memory A, uint256[] memory pk) pure returns (uint256[] memory) {{
    uint256 tb = _invTableFused();
    _invPassC(A, pk, tb);
    _invPassB(A, tb);
    _invPassA(A);
    return A;
}}
'''
)

# ---------------------------------------------------------------------------
# norms, on words of sixteen 16-bit fields.
#   canonicalise (fields < 2q): bit 15 of (v + 2^15 - q) is set iff v >= q
#   centre (fields < q):        bit 15 of (v + 2^15 - 6145) is set iff v > q/2
#   squares: with E = even fields at 32k and R = the same fields reversed,
#   position 7 (bits 224..255) of E * R is sum E_k^2: each product < 2^26,
#   eight of them < 2^29, and position 6 (< 7 * 2^26) never carries into it.
#   R comes from one 16-field reversal of the centred word: its odd fields
#   are the even fields of the input reversed, and vice versa.
# ---------------------------------------------------------------------------
Q16 = rep16(q)
CAN16 = rep16((1 << 15) - q)
CEN16 = rep16((1 << 15) - 6145)
H16 = rep16(1 << 15)
M32LO = sum(0xFFFFFFFF << (64 * i) for i in range(4))          # low 32 bits of each 64
M32HI = sum(0xFFFFFFFF << (64 * i + 32) for i in range(4))
M16LO = sum(0xFFFF << (32 * i) for i in range(8))               # low 16 bits of each 32
M16HI = sum(0xFFFF << (32 * i + 16) for i in range(8))
M64LO = 0xFFFFFFFFFFFFFFFF | (0xFFFFFFFFFFFFFFFF << 128)
M64HI = (0xFFFFFFFFFFFFFFFF << 64) | (0xFFFFFFFFFFFFFFFF << 192)

CENTRE16 = [
    "// centre: fields with v > q/2 take q - v",
    "f := and(add(v, _CEN16), _H16)",
    "f := or(f, sub(f, shr(15, f)))",
    "v := xor(v, and(f, xor(v, sub(_Q16, v))))",
    "// reverse the sixteen fields",
    "f := or(shl(128, v), shr(128, v))",
    "f := or(shl(64, and(f, _M64LO)), shr(64, and(f, _M64HI)))",
    "f := or(shl(32, and(f, _M32LO)), shr(32, and(f, _M32HI)))",
    "f := or(shl(16, and(f, _M16LO)), shr(16, and(f, _M16HI)))",
    "// even fields against reversed even fields, odd against reversed odd",
    "norm := add(norm, shr(224, mul(and(v, _M16LO), and(shr(16, f), _M16LO))))",
    "norm := add(norm, shr(224, mul(and(shr(16, v), _M16LO), and(f, _M16LO))))",
]

out.append(
    f"""
uint256 constant _Q16 = {hx(Q16)};
uint256 constant _CAN16 = {hx(CAN16)};
uint256 constant _CEN16 = {hx(CEN16)};
uint256 constant _H16 = {hx(H16)};
uint256 constant _M64LO = {hx(M64LO)};
uint256 constant _M64HI = {hx(M64HI)};
uint256 constant _M32LO = {hx(M32LO)};
uint256 constant _M32HI = {hx(M32HI)};
uint256 constant _M16LO = {hx(M16LO)};
uint256 constant _M16HI = {hx(M16HI)};

/// @notice Range check and centred squared norm of a compact polynomial (32
///         words x 16 coefficients of 16 bits). outOfRange != 0 iff some
///         coefficient is >= q; norm = sum of min(v, q - v)^2, as in
///         falcon_normalize (meaningful only when outOfRange == 0).
function _s2NormCompact(uint256[] memory c) pure returns (uint256 outOfRange, uint256 norm) {{
    assembly ("memory-safe") {{
        let p := add(c, 32)
        let pe := add(p, 1024)
        for {{}} lt(p, pe) {{ p := add(p, 32) }} {{
            let v := mload(p)
            // v >= q  <=>  bit 15 or bit 14 of v, or bit 14 of ((v & 0x3fff) + 2^14 - q)
            outOfRange := or(outOfRange, and(v, {hx(rep16(0xC000))}))
            outOfRange := or(outOfRange, and(add(and(v, {hx(rep16(0x3FFF))}), {hx(rep16((1 << 14) - q))}), {hx(rep16(0x4000))}))
            let f := 0
{indent(CENTRE16, 12)}
        }}
    }}
}}

/// @notice Centred squared norm of h - s (mod q) over 512 coefficients given
///         as 128 packed words each (4 canonical 64-bit lanes per word), i.e.
///         the ||s1||^2 half of falcon_normalize with s1 = h - s.
function _normS1Packed(uint256[] memory h, uint256[] memory s) pure returns (uint256 norm) {{
    assembly ("memory-safe") {{
        let ph := add(h, 32)
        let ps := add(s, 32)
        let pe := add(ph, 4096)
        for {{}} lt(ph, pe) {{ ph := add(ph, 128) ps := add(ps, 128) }} {{
            // four words of lanes h + q - s (< 2q < 2^15) interleaved into one
            // word of sixteen 16-bit fields (the order does not matter here)
            let v := sub(add(mload(ph), _Q4_1), mload(ps))
            v := or(v, shl(16, sub(add(mload(add(ph, 32)), _Q4_1), mload(add(ps, 32)))))
            v := or(v, shl(32, sub(add(mload(add(ph, 64)), _Q4_1), mload(add(ps, 64)))))
            v := or(v, shl(48, sub(add(mload(add(ph, 96)), _Q4_1), mload(add(ps, 96)))))
            // canonicalise: fields >= q lose q
            let f := and(add(v, _CAN16), _H16)
            v := sub(v, mul(shr(15, f), 12289))
{indent(CENTRE16, 12)}
        }}
    }}
}}
"""
)

sys.stdout.write("".join(out))
