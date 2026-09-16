// SPDX-License-Identifier: MIT
// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_falcon1024_core.sol
// Falcon-1024 core on the eight-lane chain (ZKNOX_NTT_falcon1024.sol), same
// structure as ZKNOX_falcon_core8.sol: s1 = INTT(NTT(s2) o h) first, lanes stored
// as 3q + 6144 - s1_i, then hash-to-point accumulates the centred squares of
// h_i - s1_i for the 1,024 accepted candidates and never stores h. Only the
// output count changes in the sampler: a block of 68 candidates starting below
// 957 cannot reach 1,024, the grouped path needs 4 free slots (i < 1021).
// Norm bound: floor(beta^2) = 70265242 for n = 1024 (Falcon round 3, Table 3.3).
pragma solidity ^0.8.25;

import {_absorbResident, _f1600Resident, HelperCallFailed} from "./ZKNOX_falcon_core8.sol";
import {falconProduct1024} from "./ZKNOX_NTT_falcon1024.sol";
import {_Q16, _CEN16, _H16, _M64LO, _M64HI, _M32LO, _M32HI, _M16LO, _M16HI} from "./ZKNOX_NTT_falcon_fused.sol";

uint256 constant falcon1024_S256 = 64;
uint256 constant sigBound1024 = 70265242;

/// @notice hashToPointNIST(salt, msgHash) for n = 1024 consumed on the fly: returns
///         sum over i of centred(h_i - s1_i)^2, with s1 packed on eight lanes
///         as 3q + 6144 - s1_i (falconProduct1024).
function hashToPointNormS1_1024(bytes memory salt, bytes memory msgHash, address helper, uint256[] memory s1)
    view
    returns (uint256 norm)
{
    require(s1.length == 128, "s1 length");
    // replicated state
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
            // A block holds at most 68 candidates: when it starts below 957 outputs
            // it cannot reach 1024, so the block runs without output-bound checks.
            switch lt(i, 957)
            case 1 {
                for { let lp := st } lt(lp, add(st, 544)) { lp := add(lp, 32) } {
                    let lane := mload(lp)
                    lane := or(shr(8, and(lane, 0xff00ff00ff00ff00)), shl(8, and(lane, 0x00ff00ff00ff00ff)))
                    switch and(and(add(and(lane, 0x7fff7fff7fff7fff), 0x0ffb0ffb0ffb0ffb), lane), 0x8000800080008000)
                    case 0 {
                        // all four below 5q: the four candidates spread to 32-bit spacing (two
                        // mask/shift steps) are added to the four complement lanes of s1 in one
                        // add, then each sum is reduced, centred and squared
                        let ptr := add(s1p, shl(5, shr(3, i)))
                        let sh := shl(5, and(i, 7))
                        let x := shr(sh, mload(ptr))
                        if gt(sh, 128) { x := or(x, shl(sub(256, sh), mload(add(ptr, 32)))) }
                        let y := or(and(lane, 0xffffffff), shl(32, and(lane, 0xffffffff00000000)))
                        x := add(
                            x,
                            or(
                                and(y, 0x000000000000ffff000000000000ffff),
                                shl(16, and(y, 0x00000000ffff000000000000ffff0000))
                            )
                        )
                        let d := sub(mod(and(x, 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(32, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(64, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(96, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        i := add(i, 4)
                    }
                    default {
                        for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                            let v := and(shr(shl(4, k), lane), 0xffff)
                            if lt(v, 61445) {
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
            default {
                for { let lp := st } lt(lp, add(st, 544)) { lp := add(lp, 32) } {
                    let lane := mload(lp)
                    lane := or(shr(8, and(lane, 0xff00ff00ff00ff00)), shl(8, and(lane, 0x00ff00ff00ff00ff)))
                    switch and(
                        iszero(
                            and(and(add(and(lane, 0x7fff7fff7fff7fff), 0x0ffb0ffb0ffb0ffb), lane), 0x8000800080008000)
                        ),
                        lt(i, 1021)
                    )
                    case 1 {
                        let ptr := add(s1p, shl(5, shr(3, i)))
                        let sh := shl(5, and(i, 7))
                        let x := shr(sh, mload(ptr))
                        if gt(sh, 128) { x := or(x, shl(sub(256, sh), mload(add(ptr, 32)))) }
                        let y := or(and(lane, 0xffffffff), shl(32, and(lane, 0xffffffff00000000)))
                        x := add(
                            x,
                            or(
                                and(y, 0x000000000000ffff000000000000ffff),
                                shl(16, and(y, 0x00000000ffff000000000000ffff0000))
                            )
                        )
                        let d := sub(mod(and(x, 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(32, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(64, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(96, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        i := add(i, 4)
                    }
                    default {
                        for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                            let v := and(shr(shl(4, k), lane), 0xffff)
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
                    if eq(i, 1024) { lp := add(st, 512) }
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
