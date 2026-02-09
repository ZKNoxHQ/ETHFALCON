// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_falcon_core.sol
// Description: Core Falcon-512 signature verification algorithm
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_NTT_falcon.sol";

/// @notice Validates that all coefficients in a polynomial are within the field modulus q
/// @dev Checks each coefficient < q=12289, early exit on first violation for gas efficiency
/// @param polynomial Input polynomial (compacted or expanded format depending on is_compact flag)
/// @param is_compact If true, polynomial is in compacted format (32 words); if false, expanded (512 coefficients)
/// @return true if all coefficients are valid (< q), false otherwise
function falcon_checkPolynomialRange(uint256[] memory polynomial, bool is_compact) pure returns (bool) {
    uint256[] memory a;
    if (is_compact == false) {
        a = _ZKNOX_NTT_Expand(polynomial);
    } else {
        a = polynomial;
    }

    uint256 len = a.length;
    bool result = true;
    assembly ("memory-safe") {
        let ptr := add(a, 32)
        let endPtr := add(ptr, shl(5, len)) // len * 32
        for {} lt(ptr, endPtr) { ptr := add(ptr, 32) } {
            if gt(mload(ptr), q) {
                result := 0
                ptr := endPtr // break
            }
        }
    }
    return result;
}

/// @notice Normalizes signature components and verifies L2 norm bound
/// @dev Core of Falcon verification algorithm:
///      1. Computes s1 = h - s1 (mod q) where h is hash-to-point result
///      2. Normalizes both s1 and s2 to centered representatives (-q/2, q/2]
///      3. Computes squared L2 norm: ||s1||² + ||s2||²
///      4. Verifies norm² < sigBound = 34034726
/// @param s1 First signature component (will be overwritten with h - s1)
/// @param s2 Second signature component in compacted format (32 words)
/// @param hashed Hash-to-point result (512 coefficients)
/// @return result true if signature norm is valid, false otherwise
function falcon_normalize(
    uint256[] memory s1,
    uint256[] memory s2,
    uint256[] memory hashed // result of hashToPoint(signature.salt, msgs, q, n);
)
    pure
    returns (bool result)
{
    uint256 norm = 0;

    // OPTIMIZATION: Added memory-safe annotation, use lt instead of gt for clarity
    assembly ("memory-safe") {
        for { let offset := 32 } lt(offset, 16384) { offset := add(offset, 32) } {
            let s1i := addmod(mload(add(hashed, offset)), sub(q, mload(add(s1, offset))), q) //s1[i] = addmod(hashed[i], q - s1[i], q);
            let cond := gt(s1i, qs1) //s1[i] > qs1 ?
            s1i := add(mul(cond, sub(q, s1i)), mul(sub(1, cond), s1i))
            norm := add(norm, mul(s1i, s1i))
        }

        //s1 = _ZKNOX_NTT_Expand(s2); //avoiding another memory declaration
        let aa := s2
        let bb := add(s1, 32)
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            aa := add(aa, 32)
            let ai := mload(aa)

            for { let j := 0 } lt(j, 16) { j := add(j, 1) } {
                mstore(add(bb, mul(32, add(j, shl(4, i)))), and(shr(shl(4, j), ai), 0xffff)) //b[(i << 4) + j] = (ai >> (j << 4)) & mask16;
            }
        }

        for { let offset := add(s1, 32) } lt(offset, 16384) { offset := add(offset, 32) } {
            let s1i := mload(offset) //s1[i]
            let cond := gt(s1i, qs1) //s1[i] > qs1 ?
            s1i := add(mul(cond, sub(q, s1i)), mul(sub(1, cond), s1i))
            norm := add(norm, mul(s1i, s1i))
        }

        result := gt(sigBound, norm) //norm < SigBound ?
    }

    return result;
}

/// @notice Core Falcon-512 verification algorithm with compacted input
/// @dev Implements the Falcon signature verification equation:
///      1. Computes s1 = h - h·s2 (in NTT domain) where h is the public key
///      2. Verifies ||s1||² + ||s2||² < sigBound
/// @dev Uses compacted polynomial representation for gas efficiency
/// @param s2 Second signature component (32 uint256 words, compacted)
/// @param ntth Public key in NTT domain (32 uint256 words, compacted)
/// @param hashed Hash-to-point result (512 coefficients)
/// @return result true if signature is valid, false otherwise
function falcon_core(
    uint256[] memory s2,
    uint256[] memory ntth, // public key, compacted 16  coefficients of 16 bits per word
    uint256[] memory hashed // result of hashToPoint(signature.salt, msgs, q, n);
)
    pure
    returns (bool result)
{
    if (hashed.length != 512) return false;
    if (s2.length != 32) return false; //"Invalid signature length"

    result = false;

    uint256[] memory s1 = _ZKNOX_NTT_Expand(_ZKNOX_NTT_HALFMUL_Compact(s2, ntth)); //build on top of specific NTT

    return falcon_normalize(s1, s2, hashed);
}
