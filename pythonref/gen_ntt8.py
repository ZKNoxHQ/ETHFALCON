#!/usr/bin/env python3
# gen_ntt8.py -- emits src/ZKNOX_NTT_falcon8.sol: the Falcon-512 transform
# chain s1 = INTT(NTT(s2) o h) on EIGHT 32-bit lanes per word, Montgomery
# reduction with R = 2^16. Schedule and bounds validated by
# pythonref/model_ntt8.py against the scalar transforms.
#
#   python3 pythonref/gen_ntt8.py > src/ZKNOX_NTT_falcon8.sol && forge fmt src/ZKNOX_NTT_falcon8.sol
#
# Why eight lanes: with R = 2^16 the Montgomery correction multiply
# ((x & 0xffff) * 12287) fits a 32-bit lane, where a Barrett step needs 64
# bits for x * M40. Half the word-butterflies of the four-lane transform in
# every word-aligned layer (Montgomery R = 2^16, -q^-1 = 12287, biases
# 2q,2q,2q,3q,3q,4q, Barrett M = 21 to bring lanes back below 2q, sums held
# below 4q on the way back, 1/512 folded into the last layer).
#
# Layout: 64 words, coefficient 8w + j in lane j (bits 32j .. 32j+31) of word w.
# Forward: pass A (t = 256, 128, 64) reads the compact s2 (16 x 16-bit fields
# per word) and spreads each half word to eight lanes; pass B (t = 32, 16, 8);
# in-word kernel: Barrett M = 21 to < 2q, t = 4, 2, 1 in scalars, pointwise by
# the compact key (mulmod), inverse t = 1, 2, 4 in scalars (canonical out);
# pass B' (t = 8, 16, 32) and pass A' (t = 64, 128, 256 with 1/512 folded)
# keep lanes < 4q, output lanes < 2q.
import os
import re
import sys

q = 12289
R = 1 << 16
QINV = 12287
D1 = None

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "..", "src", "ZKNOX_NTT_falcon_packed.sol")).read()
ARRAYS = re.findall(r"uint256\[32\] memory psirev = \[(.*?)\];", SRC, re.S)


def parse(a):
    w = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", a)]
    return [(w[i >> 4] >> (16 * (i & 15))) & 0xFFFF for i in range(512)]


FW, INV = parse(ARRAYS[0]), parse(ARRAYS[1])
D1 = (INV[1] * 128) % q


def mont(x):
    return (x * R) % q


# tables: aligned-layer entries (1..63) in Montgomery form, in-word entries plain
def table(t):
    return [mont(t[i]) if 1 <= i else t[i] for i in range(512)]


def hexbytes(tbl):
    return "".join(format(x, "04x") for x in tbl)


def rep8(v):
    return sum(v << (32 * i) for i in range(8))


def hx(v):
    return "0x" + format(v, "064x")


def indent(lines, n):
    pad = " " * n
    return "\n".join(pad + l if l else l for l in lines)


def RED(v):
    """Montgomery step, eight lanes, one statement"""
    return f"{v} := shr(16, add({v}, mul(and(mul(and({v}, _M16), 12287), _M16), 12289)))"


B = {1: "_Q8_1", 2: "_Q8_2", 3: "_Q8_3", 4: "_Q8_4"}


def ct_octet(ld, st, tw, K):
    """Cooley-Tukey radix-8 body; K = biases of the three layers"""
    b1, b2, b3 = B[K[0]], B[K[1]], B[K[2]]
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


COND4 = "sub({s}, mul(shr(17, and(add({s}, _C17), _G17)), 49156))"


def gs_octet(ld, st, tw, K, red, last=False):
    """Gentleman-Sande radix-8 body; K = biases, red = which layers reduce their sums
    (conditional -4q). If last, layer 3 folds 1/512: sums * 128, differences * D1."""
    b1, b2, b3 = B[K[0]], B[K[1]], B[K[2]]

    def S(expr, layer):
        return COND4.format(s=expr) if red[layer] else expr

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
        if last:
            L += [
                f"    s := mul(sub(add({lo}, {b3}), {hi}), {D1R})",
                "    " + RED("s"),
                f"    {st(k + 4, 'sub(_CPL, s)')}",
                f"    s := mul(add({lo}, {hi}), {C128R})",
                "    " + RED("s"),
                f"    {st(k, 'sub(_CPL, s)')}",
            ]
        else:
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


# pass A reads the compact input: octet word i + 8k is half (i & 1) of compact
# word (i >> 1) + 4k; the half is spread from eight 16-bit fields to eight lanes
SPREAD = (
    "{{ let x := and(shr(shl(7, and(i, 1)), mload({src})), _LO128) "
    "x := or(and(x, _L64x8), shl(64, and(x, _H64))) "
    "x := or(and(x, _SA), shl(32, and(x, _SB))) "
    "x := or(and(x, _SC), shl(16, and(x, _SD))) "
    "mstore({dst}, x) }}"
)


def tw16(off):
    """a plain or Montgomery 16-bit table entry at byte offset `off` (an expression)"""
    return f"and(shr(240, mload(add(tb, {off}))), 0xffff)"


fwA = {"S1": hex(mont(FW[1])), "S2a": hex(mont(FW[2])), "S2b": hex(mont(FW[3])), "S3": [hex(mont(FW[4 + k])) for k in range(4)]}
fwB = {"S1": tw16("add(16, shl(1, b))"), "S2a": tw16("add(32, shl(2, b))"), "S2b": tw16("add(34, shl(2, b))"), "S3": [tw16(f"add({64 + 2 * k}, shl(3, b))") for k in range(4)]}
invB = {"S1": tw16("add(16, shl(1, b))"), "S2a": tw16("add(32, shl(2, b))"), "S2b": tw16("add(34, shl(2, b))"), "S3": [tw16(f"add({64 + 2 * k}, shl(3, b))") for k in range(4)]}
invA = {"S1": "0", "S2a": hex(mont(INV[2])), "S2b": hex(mont(INV[3])), "S3": [hex(mont(INV[4 + k])) for k in range(4)]}


C128R = (128 * R) % q
D1R = (D1 * R) % q


def inword():
    """SWAR kernel on one packed word, no lane variables: forward t = 4 (bias
    5q, straight from lanes < 17q), t = 2 (6q), Barrett to < 2q, t = 1 (2q),
    pointwise straight from lanes < 4q by the
    plain key fields through one REDC (a factor R^-1 stays on the values and is
    cancelled by the constants of the last inverse layer), inverse t = 1 (5q),
    t = 2 (10q), Barrett, t = 4 (2q); output lanes < 4q."""
    BAR = "W := sub(W, mul(and(shr(18, mul(W, 21)), _Q5), 12289))"
    L = ["let W := mload(p)"]
    # forward t = 4 straight from lanes < 17q (bias 5q): lanes 4..7 against 0..3, twiddle fw[64+w] at byte 128+2w
    L += [
        "let V := mul(shr(128, W), and(shr(240, mload(add(tb, add(128, shl(1, w))))), 0xffff))",
        RED("V"),
        "let lo := and(W, _LO128)",
        "W := or(add(lo, V), shl(128, sub(add(lo, _Q5LO), V)))",
    ]
    # t = 2 (bias 6q): lanes (2,3)->(0,1) with fw[128+2w], (6,7)->(4,5) with fw[129+2w]; the two fields at byte 256+4w
    L += [
        "V := shr(224, mload(add(tb, add(256, shl(2, w)))))",
        "lo := and(shr(64, W), _M0145)",
        "V := or(and(mul(lo, shr(16, V)), _M01), and(mul(lo, and(V, 0xffff)), _M45))",
        RED("V"),
        "lo := and(W, _M0145)",
        "W := or(add(lo, V), shl(64, sub(add(lo, _Q6_0145), V)))",
        BAR,
    ]
    # t = 1: lanes (1,3,5,7)->(0,2,4,6) with fw[256+4w+k], four fields at byte 512+8w
    L += [
        "V := shr(192, mload(add(tb, add(512, shl(3, w)))))",
        "lo := and(shr(32, W), _M0246)",
        "V := or(or(and(mul(lo, shr(48, V)), _LN0), and(mul(lo, and(shr(32, V), 0xffff)), _LN2)), or(and(mul(lo, and(shr(16, V), 0xffff)), _LN4), and(mul(lo, and(V, 0xffff)), _LN6)))",
        RED("V"),
        "lo := and(W, _M0246)",
        "W := or(add(lo, V), shl(32, sub(add(lo, _Q2_0246), V)))",
    ]
    # pointwise straight from lanes < 4q, by the eight key fields of half (w & 1) of compact key word w >> 1
    L += ["V := shr(shl(7, and(w, 1)), mload(add(pk, add(32, shl(5, shr(1, w))))))"]
    terms = [f"and(mul(W, {'and(V, 0xffff)' if j == 0 else f'and(shr({16 * j}, V), 0xffff)'}), _LN{j})" for j in range(8)]
    L += [f"W := or(or(or({terms[0]}, {terms[1]}), or({terms[2]}, {terms[3]})), or(or({terms[4]}, {terms[5]}), or({terms[6]}, {terms[7]})))", RED("W")]
    # inverse t = 1: (a, b) = lanes (2k, 2k+1): sums in 2k, red((a + 3q - b) S) in 2k+1; inv[256+4w+k] at byte 512+8w
    L += [
        "V := shr(192, mload(add(ti, add(512, shl(3, w)))))",
        "lo := and(W, _M0246)",
        "W := and(shr(32, W), _M0246)",
        "let d := sub(add(lo, _Q5_0246), W)",
        "lo := add(lo, W)",
        "W := or(or(and(mul(d, shr(48, V)), _LN0), and(mul(d, and(shr(32, V), 0xffff)), _LN2)), or(and(mul(d, and(shr(16, V), 0xffff)), _LN4), and(mul(d, and(V, 0xffff)), _LN6)))",
        RED("W"),
        "W := or(lo, shl(32, W))",
    ]
    # inverse t = 2: (0,2),(1,3) with inv[128+2w]; (4,6),(5,7) with inv[129+2w]
    L += [
        "V := shr(224, mload(add(ti, add(256, shl(2, w)))))",
        "lo := and(W, _M0145)",
        "W := and(shr(64, W), _M0145)",
        "d := sub(add(lo, _Q10_0145), W)",
        "lo := add(lo, W)",
        "W := or(and(mul(d, shr(16, V)), _M01), and(mul(d, and(V, 0xffff)), _M45))",
        RED("W"),
        "W := or(lo, shl(64, W))",
        BAR,
    ]
    # inverse t = 4: (i, i+4) with inv[64+w]
    L += [
        "V := and(shr(240, mload(add(ti, add(128, shl(1, w))))), 0xffff)",
        "lo := and(W, _LO128)",
        "W := shr(128, W)",
        "d := mul(sub(add(lo, _Q2LO), W), V)",
        RED("d"),
        "mstore(p, or(add(lo, W), shl(128, d)))",
    ]
    return L


out = f"""// SPDX-License-Identifier: MIT
// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_NTT_falcon8.sol
// GENERATED by pythonref/gen_ntt8.py -- do not edit by hand.
//
// s1 = INTT(NTT(s2) o h) for Falcon-512 on EIGHT 32-bit lanes per word with a
// Montgomery reduction (R = 2^16, -q^-1 mod R = 12287): the correction multiply
// ((x & 0xffff) * 12287) fits a 32-bit lane, where the Barrett step of the
// four-lane transform needs 64 bits for x * M40. Half the word-butterflies in
// every word-aligned layer.
//
// Layout: 64 words, coefficient 8w + j in lane j (bits 32j..32j+31) of word w.
//   pass A   t = 256, 128, 64 read from the compact s2, biases 2q, 2q, 2q
//   pass B   t = 32, 16, 8, biases 3q, 3q, 4q (lanes < 17q)
//   in-word  SWAR on the packed word: t = 4, 2 (biases 5q, 6q, straight from
//            lanes < 17q), Barrett M = 21 to < 2q, t = 1 (2q); pointwise by
//            the compact key straight from lanes < 4q in one REDC (the values
//            then carry a factor R^-1); inverse t = 1, 2, 4 (biases 5q, 10q,
//            2q with a Barrett before t = 4)
//   pass B'  t = 8, 16, 32, bias 4q, sums reduced by 4q (lanes < 4q)
//   pass A'  t = 64, 128 (bias 4q, sums reduced), t = 256 folded with 1/512
//            and the missing R: sums * {C128R} (= 128R mod q), differences
//            * {D1R} (= inv[1]*128R mod q)
// Output lanes stored as 3q + 6144 - s1_i (s1_i < 3q). Every bound is asserted
// by pythonref/model_ntt8.py.
// Twiddle tables: 512 big-endian uint16 (aligned-layer entries 1..63 in
// Montgomery form), copied from code, read by unaligned mload.
pragma solidity ^0.8.25;

uint256 constant _M16 = {hx(rep8(0xFFFF))};
uint256 constant _Q5 = {hx(rep8(0x1F))};
uint256 constant _Q8_1 = {hx(rep8(q))};
uint256 constant _Q8_2 = {hx(rep8(2 * q))};
uint256 constant _Q8_3 = {hx(rep8(3 * q))};
uint256 constant _Q8_4 = {hx(rep8(4 * q))};
uint256 constant _C17 = {hx(rep8((1 << 17) - 4 * q))};
// the output is stored complemented: lane = 3q + 6144 - s1_i (in (6144, 43011]),
// the term the norm sampler adds to each hash candidate
uint256 constant _CPL = {hx(rep8(3 * q + 6144))};
// in-word SWAR: lane groups and biases
uint256 constant _M0145 = {hx(0xFFFFFFFFFFFFFFFF | (0xFFFFFFFFFFFFFFFF << 128))};
uint256 constant _M0246 = {hx(sum(0xFFFFFFFF << (64 * i) for i in range(4)))};
uint256 constant _M01 = 0xffffffffffffffff;
uint256 constant _M45 = {hx(0xFFFFFFFFFFFFFFFF << 128)};
uint256 constant _LN0 = 0xffffffff;
uint256 constant _LN1 = {hx(0xFFFFFFFF << 32)};
uint256 constant _LN2 = {hx(0xFFFFFFFF << 64)};
uint256 constant _LN3 = {hx(0xFFFFFFFF << 96)};
uint256 constant _LN4 = {hx(0xFFFFFFFF << 128)};
uint256 constant _LN5 = {hx(0xFFFFFFFF << 160)};
uint256 constant _LN6 = {hx(0xFFFFFFFF << 192)};
uint256 constant _LN7 = {hx(0xFFFFFFFF << 224)};
uint256 constant _Q2LO = {hx(sum(2 * q << (32 * i) for i in range(4)))};
uint256 constant _Q5LO = {hx(sum(5 * q << (32 * i) for i in range(4)))};
uint256 constant _Q2_0145 = {hx(sum(2 * q << (32 * i) for i in (0, 1, 4, 5)))};
uint256 constant _Q6_0145 = {hx(sum(6 * q << (32 * i) for i in (0, 1, 4, 5)))};
uint256 constant _Q2_0246 = {hx(sum(2 * q << (32 * i) for i in (0, 2, 4, 6)))};
uint256 constant _Q5_0246 = {hx(sum(5 * q << (32 * i) for i in (0, 2, 4, 6)))};
uint256 constant _Q10_0145 = {hx(sum(10 * q << (32 * i) for i in (0, 1, 4, 5)))};
uint256 constant _G17 = {hx(rep8(1 << 17))};
// spread of eight 16-bit fields (a half compact word) to eight lanes
uint256 constant _LO128 = 0xffffffffffffffffffffffffffffffff;
uint256 constant _L64x8 = 0xffffffffffffffff;
uint256 constant _H64 = 0xffffffffffffffff0000000000000000;
uint256 constant _SA = {hx(0xFFFFFFFF | (0xFFFFFFFF << 128))};
uint256 constant _SB = {hx((0xFFFFFFFF << 32) | (0xFFFFFFFF << 160))};
uint256 constant _SC = {hx(sum(0xFFFF << (64 * i) for i in range(4)))};
uint256 constant _SD = {hx(sum(0xFFFF0000 << (64 * i) for i in range(4)))};

bytes constant _FW8 = hex"{hexbytes(table(FW))}";
bytes constant _INV8 = hex"{hexbytes(table(INV))}";

/// @dev pass A: octets (i, i+8, ..., i+56) read from the compact s2 and spread
function _fw8PassA(uint256[] memory c) pure returns (uint256[] memory A) {{
    A = new uint256[](64);
    assembly ("memory-safe") {{
        let src := add(c, 32)
        let p := add(A, 32)
        for {{ let i := 0 }} lt(i, 8) {{ i := add(i, 1) }} {{
{indent([SPREAD.format(src=("src" if k == 0 else f"add(src, {hex(128 * k)})"), dst=("p" if k == 0 else f"add(p, {hex(256 * k)})")) for k in range(8)], 12)}
{indent(ct_octet(lambda k: ldp(k, 0x100), lambda k, e: stp(k, e, 0x100), fwA, (2, 2, 2)), 12)}
            p := add(p, 32)
            src := add(src, mul(32, and(i, 1)))
        }}
    }}
}}

/// @dev pass B: octets of eight consecutive words, twiddles from the table
function _fw8PassB(uint256[] memory A, uint256 tb) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        for {{ let b := 0 }} lt(b, 8) {{ b := add(b, 1) }} {{
{indent(ct_octet(lambda k: ldp(k, 0x20), lambda k, e: stp(k, e, 0x20), fwB, (3, 3, 4)), 12)}
            p := add(p, 0x100)
        }}
    }}
}}

/// @dev in-word kernel on the 64 words, SWAR on the packed word: forward
///      t = 4, 2, 1, pointwise by the compact key (one REDC, the R^-1 it leaves
///      is cancelled in the last layer), inverse t = 1, 2, 4; output lanes < 4q
function _fw8InWord(uint256[] memory A, uint256[] memory pk, uint256 tb, uint256 ti) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        for {{ let w := 0 }} lt(w, 64) {{ w := add(w, 1) }} {{
{indent(inword(), 12)}
            p := add(p, 32)
        }}
    }}
}}

/// @dev pass B': t = 8, 16, 32, bias 4q, sums reduced by 4q: lanes < 4q
function _inv8PassB(uint256[] memory A, uint256 tb) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        for {{ let b := 0 }} lt(b, 8) {{ b := add(b, 1) }} {{
{indent(gs_octet(lambda k: ldp(k, 0x20), lambda k, e: stp(k, e, 0x20), invB, (4, 4, 4), (True, True, True)), 12)}
            p := add(p, 0x100)
        }}
    }}
}}

/// @dev pass A': t = 64, 128, then t = 256 folded with 1/512 and the R of the
///      pointwise step (sums * 128R, differences * inv[1]*128R); output lanes < 3q
function _inv8PassA(uint256[] memory A) pure {{
    assembly ("memory-safe") {{
        let p := add(A, 32)
        for {{ let i := 0 }} lt(i, 8) {{ i := add(i, 1) }} {{
{indent(gs_octet(lambda k: ldp(k, 0x100), lambda k, e: stp(k, e, 0x100), invA, (4, 4, 4), (True, True, True), last=True), 12)}
            p := add(p, 32)
        }}
    }}
}}

/// @notice s1 = INTT(NTT(s2) o h) for a compact s2 (16 coefficients of 16 bits
///         per word, canonical) and a compact key h; result PACKED on eight
///         32-bit lanes per word (coefficient 8w + j in lane j), each lane
///         holding 3q + 6144 - x with x < 3q congruent to s1_i: the term the
///         norm sampler (ZKNOX_falcon_core8.sol) adds to a hash candidate t
///         before its mod q, so that (t + lane) mod q - 6144 is the centred
///         difference h_i - s1_i.
function falconProduct8(uint256[] memory s2, uint256[] memory h) pure returns (uint256[] memory A) {{
    require(s2.length == 32 && h.length == 32, "compact length");
    bytes memory fwt = _FW8;
    bytes memory ivt = _INV8;
    uint256 tb;
    uint256 ti;
    assembly ("memory-safe") {{
        tb := add(fwt, 32)
        ti := add(ivt, 32)
    }}
    A = _fw8PassA(s2);
    _fw8PassB(A, tb);
    _fw8InWord(A, h, tb, ti);
    _inv8PassB(A, ti);
    _inv8PassA(A);
}}
"""
sys.stdout.write(out)
