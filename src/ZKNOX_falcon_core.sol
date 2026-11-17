// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_falcon_core.sol
// Description: Core Falcon-512 signature verification algorithm
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_NTT_falcon.sol";

/// @dev Length in bytes of an encoded public key as accepted by `setKey`:
///      abi.encode(uint256[] ntth) with ntth.length == 32, i.e. offset (0x20) || length (32) || 32 words.
uint256 constant FALCON_PK_ENCODED_LEN = 1088;

/// @dev Code size of an SSTORE2 key pointer written by `setKey`: a leading STOP byte (0x00) || encoded key.
uint256 constant FALCON_PK_CODE_SIZE = 1089;

/// @notice Checks that every 16-bit coefficient of a compacted polynomial is < q
/// @dev SWAR check over the 32 compact words. Each word is split into its even and odd 16-bit lanes,
///      placed in 32-bit slots, and 0xCFFF (= 2^16 - q) is added to every slot: a lane x is >= q
///      iff x + 2^16 - q carries into bit 16 of its slot. The maximum slot value is
///      0xffff + 0xcfff < 2^17, so no carry crosses slots.
/// @param a Compacted polynomial (must have exactly 32 words, otherwise false is returned)
/// @return result true iff a.length == 32 and all 512 coefficients are in [0, q)
function falcon_checkCompactRange(uint256[] memory a) pure returns (bool result) {
    if (a.length != 32) return false;
    assembly ("memory-safe") {
        let lanes := 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff
        let bias := 0x0000cfff0000cfff0000cfff0000cfff0000cfff0000cfff0000cfff0000cfff
        let carry := 0x0001000000010000000100000001000000010000000100000001000000010000
        let bad := 0
        let ptr := add(a, 32)
        let endPtr := add(ptr, 1024)
        for {} lt(ptr, endPtr) { ptr := add(ptr, 32) } {
            let w := mload(ptr)
            bad := or(bad, or(add(and(w, lanes), bias), add(and(shr(16, w), lanes), bias)))
        }
        result := iszero(and(bad, carry))
    }
}

/// @notice Checks that `pubkey` is the canonical `setKey` encoding of a valid public key
/// @dev Canonical encoding is abi.encode(uint256[] ntth) with ntth.length == 32 (1088 bytes),
///      and every 16-bit coefficient of ntth must be < q.
/// @param pubkey Encoded public key
/// @return true iff the encoding is canonical and all coefficients are in range
function falcon_checkKeyEncoding(bytes memory pubkey) pure returns (bool) {
    if (pubkey.length != FALCON_PK_ENCODED_LEN) return false;
    uint256 offset;
    uint256[] memory ntth;
    assembly ("memory-safe") {
        offset := mload(add(pubkey, 32))
        ntth := add(pubkey, 64) // length word followed by the 32 coefficients words
    }
    if (offset != 0x20) return false;
    return falcon_checkCompactRange(ntth); // also checks that the length word is 32
}

/// @notice Loads a public key from an ERC-7913 key, i.e. the 20-byte address of a `setKey` pointer
/// @dev Reverts unless `_pubkey` is exactly 20 bytes and points to a contract whose code is exactly
///      FALCON_PK_CODE_SIZE bytes, starts with a STOP byte and holds the canonical key encoding.
///      Coefficient ranges are checked later by falcon_core.
/// @param _pubkey ERC-7913 key bytes
/// @return ntth Public key in the NTT domain, compacted (32 words)
function falcon_loadKeyPointer(bytes calldata _pubkey) view returns (uint256[] memory ntth) {
    if (_pubkey.length != 20) revert("invalid public key length");
    address pointer = address(bytes20(_pubkey));
    if (pointer.code.length != FALCON_PK_CODE_SIZE) revert("invalid public key");

    bool ok;
    assembly ("memory-safe") {
        let buf := mload(0x40)
        // copy the whole code at buf+31 so that the STOP byte is the lowest byte of the word at buf
        // and the encoded key starts at buf+32
        extcodecopy(pointer, add(buf, 31), 0, FALCON_PK_CODE_SIZE)
        ok := and(iszero(and(mload(buf), 0xff)), eq(mload(add(buf, 32)), 0x20))
        ok := and(ok, eq(mload(add(buf, 64)), 32))
        ntth := add(buf, 64)
        mstore(0x40, add(buf, add(32, FALCON_PK_ENCODED_LEN)))
    }
    if (!ok) revert("invalid public key");
}

/// @notice Normalizes signature components and verifies L2 norm bound
/// @dev Core of Falcon verification algorithm:
///      1. Computes s1 = h - s1 (mod q) where h is hash-to-point result
///      2. Normalizes both s1 and s2 to centered representatives (-q/2, q/2]
///      3. Computes squared L2 norm: ||s1||² + ||s2||²
///      4. Verifies norm² <= sigBound = 34034726
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
    uint256 outOfRange = 0;

    assembly ("memory-safe") {
        // ||s1||^2 contribution. s1_i := (hashed_i - s1_i) mod q, centered in (-q/2, q/2].
        // 512 coefficients -> relative offsets 32..16384 inclusive => bound 16416.
        for { let offset := 32 } lt(offset, 16416) { offset := add(offset, 32) } {
            let s1i := addmod(mload(add(hashed, offset)), sub(q, mload(add(s1, offset))), q)
            let cond := gt(s1i, qs1)
            s1i := add(mul(cond, sub(q, s1i)), mul(sub(1, cond), s1i))
            norm := add(norm, mul(s1i, s1i))
        }

        // ||s2||^2 contribution. Expand the 32 compact words into 512 16-bit
        // coefficients, range-check each (< q, otherwise s_i and s_i+q are
        // interchangeable and the signature is malleable), and accumulate the
        // centered squared sum.
        let aa := s2
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            aa := add(aa, 32)
            let ai := mload(aa)
            for { let j := 0 } lt(j, 16) { j := add(j, 1) } {
                let s2i := and(shr(shl(4, j), ai), 0xffff)
                outOfRange := or(outOfRange, iszero(lt(s2i, q)))
                let cond := gt(s2i, qs1)
                let centered := add(mul(cond, sub(q, s2i)), mul(sub(1, cond), s2i))
                norm := add(norm, mul(centered, centered))
            }
        }

        // accept iff norm <= sigBound, matching the reference (reject only norm > sigBound)
        result := and(iszero(outOfRange), iszero(gt(norm, sigBound)))
    }

    return result;
}

/// @notice Core Falcon-512 verification algorithm with compacted input
/// @dev Implements the Falcon signature verification equation:
///      1. Computes s1 = h - h·s2 (in NTT domain) where h is the public key
///      2. Verifies ||s1||² + ||s2||² <= sigBound
/// @dev Uses compacted polynomial representation for gas efficiency
/// @param s2 Second signature component (32 uint256 words, compacted)
/// @param ntth Public key in NTT domain (32 uint256 words, compacted, every coefficient < q)
/// @param hashed Hash-to-point result (512 coefficients)
/// @return result true if signature is valid, false otherwise (including a malformed ntth)
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
    // reject non-canonical public keys: wrong length or a coefficient >= q
    // (otherwise ntth_i and ntth_i + k*q would be interchangeable)
    if (!falcon_checkCompactRange(ntth)) return false;

    // s1 = h*s2 = INTT(NTT(s2) * ntth). This is _ZKNOX_NTT_HALFMUL_Compact without the final
    // compact/expand round trip, which is the identity on its < q output.
    uint256[] memory s1 = _ZKNOX_NTTINV_vectorized(
        _ZKNOX_VECMULMOD(_ZKNOX_NTTFW_vectorized(_ZKNOX_NTT_Expand(s2)), _ZKNOX_NTT_Expand(ntth))
    );

    return falcon_normalize(s1, s2, hashed);
}
