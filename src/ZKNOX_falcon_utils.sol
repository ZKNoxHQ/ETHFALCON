// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_falcon_utils.sol
// Description: Utility functions and constants for Falcon signature verification
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @dev Mask for extracting 16-bit values from uint256
uint256 constant mask16 = 0xffff;

/// @dev Number of 16-bit chunks that fit in a 256-bit word
uint256 constant chunk16Byword = 16;

/// @dev Number of 256-bit words in a Falcon-512 polynomial (32 words × 16 coefficients = 512 total)
uint256 constant falcon_S256 = 32;

/// @dev Keccak-based hash identifier
uint256 constant ID_keccak = 0x00;

/// @dev Tetration-based hash identifier (PoC only)
uint256 constant ID_tetration = 0x01;

/// @dev Number of 256-bit words in a Falcon polynomial
uint256 constant _FALCON_WORD256_S = 32;

/// @dev Number of 32-bit words (not used in current implementation, for reference)
uint256 constant _FALCON_WORD32_S = 512;

// ==================== FALCON-512 CONSTANTS ====================

/// @dev Polynomial ring degree for Falcon-512
uint256 constant n = 512;

/// @dev Modular inverse of n modulo q: n^(-1) mod 12289 = 12265
uint256 constant nm1modq = 12265;

/// @dev Maximum allowed signature norm squared (L2 norm bound)
uint256 constant sigBound = 34034726;

/// @dev Maximum signature length in bytes (compressed encoding)
uint256 constant sigBytesLen = 666;

/// @dev Prime modulus for Falcon-512: q = 12289
uint256 constant q = 12289;

/// @dev Half of q (used for centered reduction): q/2 = 6144
uint256 constant qs1 = 6144;

/// @dev Rejection sampling bound: 5×q = 61445
uint256 constant kq = 61445;

/// @notice Reverses the order of coefficients in a polynomial
/// @dev Creates a mirror polynomial where coeff[i] becomes coeff[511-i]
/// @dev Optimized assembly implementation for gas efficiency
/// @param Pol Input polynomial with 512 coefficients
/// @return Mirror Reversed polynomial
function Swap(uint256[] memory Pol) pure returns (uint256[] memory Mirror) {
    Mirror = new uint256[](512);
    assembly ("memory-safe") {
        let polPtr := add(Pol, 32)
        let mirPtr := add(Mirror, 32)
        // Mirror[511 - i] = Pol[i]
        for { let i := 0 } lt(i, 512) { i := add(i, 1) } {
            let srcOffset := shl(5, i) // i * 32
            let dstOffset := shl(5, sub(511, i)) // (511-i) * 32
            mstore(add(mirPtr, dstOffset), mload(add(polPtr, srcOffset)))
        }
    }
}

/// @notice Compacts an expanded polynomial from 512 uint256 values to 32 uint256 values
/// @dev Packs 16 coefficients (each 16 bits) into each 256-bit word
/// @dev Each word stores coefficients as: word = c0 | (c1<<16) | (c2<<32) | ... | (c15<<240)
/// @param a Expanded polynomial (512 coefficients as separate uint256 values)
/// @return b Compacted polynomial (32 uint256 words, each containing 16 coefficients)
function _ZKNOX_NTT_Compact(uint256[] memory a) pure returns (uint256[] memory b) {
    b = new uint256[](32);

    assembly ("memory-safe") {
        let aa := a
        let bb := add(b, 32)
        for { let i := 0 } lt(i, 512) { i := add(i, 1) } {
            aa := add(aa, 32)
            let bi := add(bb, mul(32, shr(4, i))) //shr(4,i)*32 !=shl(1,i)
            mstore(bi, xor(mload(bi), shl(shl(4, and(i, 0xf)), mload(aa))))
        }
    }

    return b;
}

/// @notice Expands a compacted polynomial from 32 uint256 values to 512 uint256 values
/// @dev Unpacks 16 coefficients (each 16 bits) from each 256-bit word into separate uint256 values
/// @dev Inverse operation of _ZKNOX_NTT_Compact
/// @param a Compacted polynomial (32 uint256 words)
/// @return b Expanded polynomial (512 coefficients as separate uint256 values)
function _ZKNOX_NTT_Expand(uint256[] memory a) pure returns (uint256[] memory b) {
    b = new uint256[](512);

    /*
    for (uint256 i = 0; i < 32; i++) {
        uint256 ai = a[i];
        for (uint256 j = 0; j < 16; j++) {
            b[(i << 4) + j] = (ai >> (j << 4)) & mask16;
        }
    }
    */

    assembly ("memory-safe") {
        let aa := a
        let bb := add(b, 32)
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            aa := add(aa, 32)
            let ai := mload(aa)

            for { let j := 0 } lt(j, 16) { j := add(j, 1) } {
                mstore(add(bb, mul(32, add(j, shl(4, i)))), and(shr(shl(4, j), ai), 0xffff)) //b[(i << 4) + j] = (ai >> (j << 4)) & mask16;
            }
        }
    }

    return b;
}

/// @notice Decompresses a polynomial from byte buffer using 14-bit encoding
/// @dev Extracts 512 coefficients encoded as 14-bit values from a byte stream
/// @dev Each coefficient must be < q=12289, otherwise the function reverts
/// @dev Used for decompressing Falcon public keys in NIST format
/// @param buf Byte buffer containing compressed polynomial data
/// @param offset Starting position in buffer (typically 1 to skip header byte 0x09)
/// @return Decompressed polynomial as array of 512 uint256 coefficients
function _ZKNOX_NTT_Decompress(bytes memory buf, uint256 offset) pure returns (uint256[] memory) {
    uint256[] memory x = new uint256[](512);
    uint32 acc = 0;
    uint256 acc_len = 0;
    uint256 u = 0;
    uint256 cpt = offset; //start with offset 1 to prune 0x09 header

    unchecked {
        while (u < n) {
            acc = (acc << 8) | uint32(uint8(buf[cpt]));
            cpt++;

            acc_len += 8;
            if (acc_len >= 14) {
                uint32 w;

                acc_len -= 14;
                w = (acc >> acc_len) & 0x3FFF;
                if (w >= 12289) {
                    revert("wrong coeff");
                }
                x[u] = uint256(w);
                u++;
            } //end if
        } //end while
    }
    if ((acc & ((1 << acc_len) - 1)) != 0) {
        revert();
    }

    //console.log("last read kpub", uint8(buf[cpt-1]));
    return x;
}
