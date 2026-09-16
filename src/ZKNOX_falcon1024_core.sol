// SPDX-License-Identifier: MIT
// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_falcon1024_core.sol
// Falcon-1024 core on the eight-lane chain (ZKNOX_NTT_falcon1024.sol), same
// structure as ZKNOX_falcon_core8.sol: s1 = INTT(NTT(s2) o h) first, lanes stored
// as 3q + 6144 - s1_i, then hash-to-point accumulates the centred squares of
// h_i - s1_i for the 1,024 accepted candidates and never stores h. The sampler
// takes candidates eight at a time (see hashToPointNormS1_1024).
// Norm bound: floor(beta^2) = 70265242 for n = 1024 (Falcon round 3, Table 3.3).
pragma solidity ^0.8.25;

import {_absorbResident, _f1600Resident, HelperCallFailed} from "./ZKNOX_falcon_core8.sol";
import {
    falconProduct1024,
    _F10_L64,
    _F10_H64,
    _F10_SA,
    _F10_SB,
    _F10_SC,
    _F10_SD,
    _F10_CQ17,
    _F10_G17
} from "./ZKNOX_NTT_falcon1024.sol";
import {_Q16, _CEN16, _H16, _M64LO, _M64HI, _M32LO, _M32HI, _M16LO, _M16HI} from "./ZKNOX_NTT_falcon_fused.sol";

uint256 constant falcon1024_S256 = 64;
// sampler constants: 128-bit byte swap masks, rejection test on eight fields, SWAR reduction
uint256 constant _H8_BS = 0xff00ff00ff00ff00ff00ff00ff00ff00;
uint256 constant _L8_BS = 0x00ff00ff00ff00ff00ff00ff00ff00ff;
uint256 constant _T7FFF = 0x7fff7fff7fff7fff7fff7fff7fff7fff;
uint256 constant _T0FFB = 0x0ffb0ffb0ffb0ffb0ffb0ffb0ffb0ffb;
uint256 constant _T8000 = 0x80008000800080008000800080008000;
uint256 constant _NIB8 = 0x0000000f0000000f0000000f0000000f0000000f0000000f0000000f0000000f;
uint256 constant _C6145 = 0x7fffe7ff7fffe7ff7fffe7ff7fffe7ff7fffe7ff7fffe7ff7fffe7ff7fffe7ff;
uint256 constant _G31 = 0x8000000080000000800000008000000080000000800000008000000080000000;
uint256 constant _S6144 = 0x0000180000001800000018000000180000001800000018000000180000001800;
uint256 constant _Q8 = 0x0000300100003001000030010000300100003001000030010000300100003001;
uint256 constant sigBound1024 = 70265242;

/// @notice hashToPointNIST(salt, msgHash) for n = 1024 consumed on the fly: returns
///         sum over i of centred(h_i - s1_i)^2, with s1 packed on eight lanes as
///         3q + 6144 - s1_i (falconProduct1024).
/// @dev Candidates are taken EIGHT at a time (two state lanes). For a pair with at most one
///      rejected candidate (91.5 % of pairs), the rejected field is dropped by two masks
///      derived from its test bit, the (seven or eight) candidates are spread to 32-bit
///      lanes and added to the eight complement lanes of s1 in one add, 6144 is taken off
///      every lane (x = t + 3q - s1_i, 0 <= x < 2^17); each lane is reduced by Barrett
///      (M = 1365, s = 24, remainder < 2q) and one conditional -q, folded to |centred|
///      (r > 6144 takes q - r), a dropped slot is masked, and the eight
///      squares are summed at once as the middle coefficient of x * reverse(x) (squares
///      < 2^26, eight of them < 2^29: no carry between the 32-bit coefficients). Pairs with
///      exactly two rejections (7.4 %) drop both fields the same way (six candidates); pairs
///      with three or more go candidate by candidate. The 17th lane of each block is grouped
///      as four candidates when at most one is rejected; its unused lanes (4 to 7, possibly
///      past the end of s1) only carry and borrow upwards and are masked before the squares.
///      A pair is grouped only while i < 1017 (the 17th lane while i < 1021), so every lane
///      that is counted is in range.
function hashToPointNormS1_1024(bytes memory salt, bytes memory msgHash, address helper, uint256[] memory s1)
    view
    returns (uint256 norm)
{
    require(s1.length == 128, "s1 length");
    uint256[25] memory buf;
    uint256 st;
    assembly ("memory-safe") {
        st := buf
    }
    _absorbResident(st, abi.encodePacked(salt, msgHash), helper);
    uint256 i;
    uint256 s1p;
    assembly ("memory-safe") {
        s1p := add(s1, 32)
    }
    while (true) {
        assembly ("memory-safe") {
            for { let lp := st } lt(lp, add(st, 512)) { lp := add(lp, 64) } {
                // lanes lp, lp + 32 (low copies), each 16-bit candidate big-endian
                let L := or(and(mload(lp), 0xffffffffffffffff), shl(64, mload(add(lp, 32))))
                L := or(shr(8, and(L, _H8_BS)), shl(8, and(L, _L8_BS)))
                // bit 15 of a field set iff the candidate is >= 5q = 61445
                let b := and(and(add(and(L, _T7FFF), _T0FFB), L), _T8000)
                switch and(lt(i, 1017), iszero(and(b, sub(b, 1))))
                case 1 {
                    // at most one rejection: fields below it stay, fields above move down
                    L := or(and(L, sub(shr(15, b), 1)), shr(16, and(L, not(sub(shl(1, b), 1)))))
                    let cnt := sub(8, iszero(iszero(b)))
                    L := or(and(L, _F10_L64), shl(64, and(L, _F10_H64)))
                    L := or(and(L, _F10_SA), shl(32, and(L, _F10_SB)))
                    L := or(and(L, _F10_SC), shl(16, and(L, _F10_SD)))
                    let sh := shl(5, and(i, 7))
                    let ptr := add(s1p, shl(5, shr(3, i)))
                    // t + (3q + 6144 - s1_i) - 6144 per lane: >= 0, congruent to t - s1_i
                    let x := sub(add(or(shr(sh, mload(ptr)), shl(sub(256, sh), mload(add(ptr, 32)))), L), _S6144)
                    x := sub(x, mul(and(shr(24, mul(x, 1365)), _NIB8), 12289))
                    x := sub(x, mul(shr(17, and(add(x, _F10_CQ17), _F10_G17)), 12289))
                    let f := and(add(x, _C6145), _G31)
                    f := or(f, sub(f, shr(31, f)))
                    x := and(xor(x, and(f, xor(x, sub(_Q8, x)))), sub(shl(shl(5, cnt), 1), 1))
                    f := or(shl(128, x), shr(128, x))
                    f := or(shl(64, and(f, _M64LO)), shr(64, and(f, _M64HI)))
                    f := or(shl(32, and(f, _M32LO)), shr(32, and(f, _M32HI)))
                    norm := add(norm, shr(224, mul(x, f)))
                    i := add(i, cnt)
                }
                default {
                    // exactly two rejections: drop the lower one, then the upper one (moved down)
                    let b1 := and(b, sub(0, b))
                    let b2 := shr(16, xor(b, b1))
                    switch and(lt(i, 1017), iszero(and(b2, sub(b2, 1))))
                    case 1 {
                        L := or(and(L, sub(shr(15, b1), 1)), shr(16, and(L, not(sub(shl(1, b1), 1)))))
                        L := or(and(L, sub(shr(15, b2), 1)), shr(16, and(L, not(sub(shl(1, b2), 1)))))
                        let cnt := 6
                        L := or(and(L, _F10_L64), shl(64, and(L, _F10_H64)))
                        L := or(and(L, _F10_SA), shl(32, and(L, _F10_SB)))
                        L := or(and(L, _F10_SC), shl(16, and(L, _F10_SD)))
                        let sh := shl(5, and(i, 7))
                        let ptr := add(s1p, shl(5, shr(3, i)))
                        // t + (3q + 6144 - s1_i) - 6144 per lane: >= 0, congruent to t - s1_i
                        let x := sub(add(or(shr(sh, mload(ptr)), shl(sub(256, sh), mload(add(ptr, 32)))), L), _S6144)
                        x := sub(x, mul(and(shr(24, mul(x, 1365)), _NIB8), 12289))
                        x := sub(x, mul(shr(17, and(add(x, _F10_CQ17), _F10_G17)), 12289))
                        let f := and(add(x, _C6145), _G31)
                        f := or(f, sub(f, shr(31, f)))
                        x := and(xor(x, and(f, xor(x, sub(_Q8, x)))), sub(shl(shl(5, cnt), 1), 1))
                        f := or(shl(128, x), shr(128, x))
                        f := or(shl(64, and(f, _M64LO)), shr(64, and(f, _M64HI)))
                        f := or(shl(32, and(f, _M32LO)), shr(32, and(f, _M32HI)))
                        norm := add(norm, shr(224, mul(x, f)))
                        i := add(i, cnt)
                    }
                    default {
                        for { let k := 0 } lt(k, 8) { k := add(k, 1) } {
                            let v := and(shr(shl(4, k), L), 0xffff)
                            if and(lt(v, 61445), lt(i, 1024)) {
                                let d :=
                                    sub(
                                        mod(
                                            add(
                                                v,
                                                and(
                                                    shr(shl(5, and(i, 7)), mload(add(s1p, shl(5, shr(3, i))))),
                                                    0xffffffff
                                                )
                                            ),
                                            12289
                                        ),
                                        6144
                                    )
                                norm := add(norm, mul(d, d))
                                i := add(i, 1)
                            }
                        }
                    }
                }
            }
            // the 17th lane of the block: four candidates, grouped when at most one is rejected
            {
                let L := mload(add(st, 512))
                L := or(shr(8, and(L, 0xff00ff00ff00ff00)), shl(8, and(L, 0x00ff00ff00ff00ff)))
                let b := and(and(add(and(L, _T7FFF), _T0FFB), L), _T8000)
                switch and(lt(i, 1021), iszero(and(b, sub(b, 1))))
                case 1 {
                    L := or(and(L, sub(shr(15, b), 1)), shr(16, and(L, not(sub(shl(1, b), 1)))))
                    let cnt := sub(4, iszero(iszero(b)))
                    L := or(and(L, _F10_L64), shl(64, and(L, _F10_H64)))
                    L := or(and(L, _F10_SA), shl(32, and(L, _F10_SB)))
                    L := or(and(L, _F10_SC), shl(16, and(L, _F10_SD)))
                    let sh := shl(5, and(i, 7))
                    let ptr := add(s1p, shl(5, shr(3, i)))
                    // t + (3q + 6144 - s1_i) - 6144 per lane: >= 0, congruent to t - s1_i
                    let x := sub(add(or(shr(sh, mload(ptr)), shl(sub(256, sh), mload(add(ptr, 32)))), L), _S6144)
                    x := sub(x, mul(and(shr(24, mul(x, 1365)), _NIB8), 12289))
                    x := sub(x, mul(shr(17, and(add(x, _F10_CQ17), _F10_G17)), 12289))
                    let f := and(add(x, _C6145), _G31)
                    f := or(f, sub(f, shr(31, f)))
                    x := and(xor(x, and(f, xor(x, sub(_Q8, x)))), sub(shl(shl(5, cnt), 1), 1))
                    f := or(shl(128, x), shr(128, x))
                    f := or(shl(64, and(f, _M64LO)), shr(64, and(f, _M64HI)))
                    f := or(shl(32, and(f, _M32LO)), shr(32, and(f, _M32HI)))
                    norm := add(norm, shr(224, mul(x, f)))
                    i := add(i, cnt)
                }
                default {
                    for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                        let v := and(shr(shl(4, k), L), 0xffff)
                        if and(lt(v, 61445), lt(i, 1024)) {
                            let d :=
                                sub(
                                    mod(
                                        add(
                                            v,
                                            and(shr(shl(5, and(i, 7)), mload(add(s1p, shl(5, shr(3, i))))), 0xffffffff)
                                        ),
                                        12289
                                    ),
                                    6144
                                )
                            norm := add(norm, mul(d, d))
                            i := add(i, 1)
                        }
                    }
                }
            }
        }
        if (i == 1024) break;
        _f1600Resident(st, helper);
    }
}

/// @notice range check and centred squared norm of a compact Falcon-1024 s2
///         (64 words of sixteen 16-bit fields), same SWAR as _s2NormCompact
function _s2NormCompact1024(uint256[] memory c) pure returns (uint256 outOfRange, uint256 norm) {
    require(c.length == 64, "s2 length");
    assembly ("memory-safe") {
        let p := add(c, 32)
        let pe := add(p, 2048)
        for {} lt(p, pe) { p := add(p, 32) } {
            let v := mload(p)
            // v >= q  <=>  bit 15 or bit 14 of v, or bit 14 of ((v & 0x3fff) + 2^14 - q)
            outOfRange := or(outOfRange, and(v, 0xc000c000c000c000c000c000c000c000c000c000c000c000c000c000c000c000))
            outOfRange := or(
                outOfRange,
                and(
                    add(
                        and(v, 0x3fff3fff3fff3fff3fff3fff3fff3fff3fff3fff3fff3fff3fff3fff3fff3fff),
                        0x0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff0fff
                    ),
                    0x4000400040004000400040004000400040004000400040004000400040004000
                )
            )
            let f := 0
            // centre: fields with v > q/2 take q - v
            f := and(add(v, _CEN16), _H16)
            f := or(f, sub(f, shr(15, f)))
            v := xor(v, and(f, xor(v, sub(_Q16, v))))
            // reverse the sixteen fields
            f := or(shl(128, v), shr(128, v))
            f := or(shl(64, and(f, _M64LO)), shr(64, and(f, _M64HI)))
            f := or(shl(32, and(f, _M32LO)), shr(32, and(f, _M32HI)))
            f := or(shl(16, and(f, _M16LO)), shr(16, and(f, _M16HI)))
            // even fields against reversed even fields, odd against reversed odd
            norm := add(norm, shr(224, mul(and(v, _M16LO), and(shr(16, f), _M16LO))))
            norm := add(norm, shr(224, mul(and(shr(16, v), _M16LO), and(f, _M16LO))))
        }
    }
}

/// @notice squared norm ||s2||^2 + ||h - s1||^2 of a Falcon-1024 signature, with
///         s1 = INTT(NTT(s2) o ntth) and h = hashToPointNIST(salt, msgHash);
///         type(uint256).max when s2 has a field >= q
function falcon1024_norm(
    bytes memory salt,
    bytes memory msgHash,
    address helper,
    uint256[] memory s2,
    uint256[] memory ntth
) view returns (uint256 norm) {
    (uint256 outOfRange, uint256 n2) = _s2NormCompact1024(s2);
    if (outOfRange != 0) return type(uint256).max;
    uint256[] memory s1 = falconProduct1024(s2, ntth);
    norm = n2 + hashToPointNormS1_1024(salt, msgHash, helper, s1);
}

/// @notice accepts iff s2 is in range and ||s2||^2 + ||h - s1||^2 <= 70265242
function falcon1024_core(
    bytes memory salt,
    bytes memory msgHash,
    address helper,
    uint256[] memory s2,
    uint256[] memory ntth
) view returns (bool) {
    if (s2.length != 64 || ntth.length != 64) return false;
    return falcon1024_norm(salt, msgHash, helper, s2, ntth) <= sigBound1024;
}
