// SPDX-License-Identifier: MIT
// FILE: ZKNOX_HashToPoint_packed.sol
//
// hashToPointNIST on the helper-backed SHAKE256 (ZKNOX_shake_fast.sol), with
// the rejection sampler rewritten in Yul and emitting the PACKED layout of
// ZKNOX_NTT_falcon_packed.sol (128 words of four 64-bit lanes, coefficient i
// in lane i & 3 of word i >> 2) instead of 512 one-per-word coefficients.
//
// The sampler is the same function as hashToPointNIST: the squeezed bytes are
// read two at a time, big-endian, a pair is accepted iff < 5q and then reduced
// mod q, until 512 coefficients are produced. What changes is only WHERE the
// bytes are read from and HOW the result is written:
//   - the 136-byte rate block is never materialised: the sampler reads the
//     first 17 state lanes directly (lane l holds block bytes 8l..8l+7, little
//     endian), so the big-endian 16-bit read is a byte swap inside the lane;
//   - accepted coefficients are shifted into a 4-lane accumulator that is
//     stored once per four coefficients;
//   - no Solidity bounds checks, no checked modulo, no `bytes` indexing.
// Output is asserted equal to hashToPointNIST's, re-laid out, in
// test/falcon_fused.t.sol.
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_shake_fast.sol";

/// @notice hashToPointNIST(salt, msgHash) in the packed layout.
/// @dev SALT AND MSG ARE SWAPPED (kept from the original): SHAKE256(salt || msgHash).
function hashToPointNISTPacked(bytes memory salt, bytes memory msgHash, address helper)
    view
    returns (uint256[] memory hashed)
{
    hashed = new uint256[](128);

    uint256[25] memory st;
    _absorbFast170(st, abi.encodePacked(salt, msgHash), helper);

    uint256 outPtr;
    uint256 endPtr;
    uint256 acc;
    uint256 sh;
    assembly ("memory-safe") {
        outPtr := add(hashed, 32)
        endPtr := add(outPtr, 4096)
    }

    while (true) {
        bool done;
        assembly ("memory-safe") {
            // 17 rate lanes, 4 big-endian 16-bit reads each. The lane is byte-swapped
            // once (16-bit granularity), then chunk k is bits 16k..16k+15.
            for { let lp := st } lt(lp, add(st, 544)) { lp := add(lp, 32) } {
                let lane := mload(lp)
                lane := or(shr(8, and(lane, 0xff00ff00ff00ff00)), shl(8, and(lane, 0x00ff00ff00ff00ff)))
                let v := and(lane, 0xffff)
                if lt(v, 61445) {
                    acc := or(acc, shl(sh, mod(v, 12289)))
                    sh := add(sh, 64)
                    if eq(sh, 256) {
                        mstore(outPtr, acc)
                        outPtr := add(outPtr, 32)
                        acc := 0
                        sh := 0
                        if eq(outPtr, endPtr) { lp := add(st, 512) }
                    }
                }
                v := and(shr(16, lane), 0xffff)
                if lt(v, 61445) {
                    acc := or(acc, shl(sh, mod(v, 12289)))
                    sh := add(sh, 64)
                    if eq(sh, 256) {
                        mstore(outPtr, acc)
                        outPtr := add(outPtr, 32)
                        acc := 0
                        sh := 0
                        if eq(outPtr, endPtr) { lp := add(st, 512) }
                    }
                }
                v := and(shr(32, lane), 0xffff)
                if lt(v, 61445) {
                    acc := or(acc, shl(sh, mod(v, 12289)))
                    sh := add(sh, 64)
                    if eq(sh, 256) {
                        mstore(outPtr, acc)
                        outPtr := add(outPtr, 32)
                        acc := 0
                        sh := 0
                        if eq(outPtr, endPtr) { lp := add(st, 512) }
                    }
                }
                v := shr(48, lane)
                if lt(v, 61445) {
                    acc := or(acc, shl(sh, mod(v, 12289)))
                    sh := add(sh, 64)
                    if eq(sh, 256) {
                        mstore(outPtr, acc)
                        outPtr := add(outPtr, 32)
                        acc := 0
                        sh := 0
                        if eq(outPtr, endPtr) { lp := add(st, 512) }
                    }
                }
            }
            done := eq(outPtr, endPtr)
        }
        if (done) break;
        f1600Fast170(st, helper);
    }
}
