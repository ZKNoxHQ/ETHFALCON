// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_common.sol
// Description: Common constants and utility functions for Falcon signatures
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @dev Falcon-SHAKE256 algorithm identifier
/// @dev OID: 2.16.840.1.101.3.4.3.21 (joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) algorithms(4) id-falcon-shake(3) 21)
uint256 constant FALCONSHAKE_ID = 0x216840110134321;

/// @dev Falcon-Keccak256 algorithm identifier (EVM-optimized variant)
/// @dev OID: 2.16.840.1.101.3.4.4.21 (joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) algorithms(4) id-falcon-keccak(4) 21)
uint256 constant FALCONKECCAK_ID = 0x216840110134421;

/// @dev Standard salt length in bytes for Falcon signatures
uint256 constant SALT_LEN = 40;

/// @notice Copies a fixed-size uint256[32] array into a dynamic memory array
/// @dev Creates a new dynamic array and copies all 32 elements
/// @param src Source array of 32 uint256 elements
/// @return dest Newly allocated dynamic array containing copy of src
function ZKNOX_memcpy32(uint256[32] memory src) pure returns (uint256[] memory dest) {
    dest = new uint256[](32);
    for (uint256 i = 0; i < 32; i++) {
        dest[i] = src[i];
    }

    return dest;
}

/// @notice Packs a uint256[32] array into a bytes array
/// @dev Converts 32 uint256 values into 1024 bytes (32 × 32 bytes)
/// @param arr Array of 32 uint256 values
/// @return result Packed bytes representation (1024 bytes total)
function _packUint256Array(uint256[32] memory arr) pure returns (bytes memory result) {
    result = new bytes(1024); // 32 * 32
    assembly {
        let dst := add(result, 32)
        let src := arr
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            mstore(add(dst, mul(i, 32)), mload(add(src, mul(i, 32))))
        }
    }
}

/// @notice Packs a Falcon signature (salt + s2) into a single bytes array
/// @dev Creates a 1064-byte array: 40 bytes salt + 1024 bytes s2 (32 × 32)
/// @param salt 40-byte salt value
/// @param s2 Second signature component (32 uint256 values)
/// @return result Packed signature bytes (1064 bytes total)
function _packSignature(bytes memory salt, uint256[32] memory s2) pure returns (bytes memory result) {
    result = new bytes(1064); // 40 + 1024

    // Copy salt (40 bytes)
    for (uint256 i = 0; i < 40; i++) {
        result[i] = salt[i];
    }

    // Copy s2 (1024 bytes)
    assembly {
        let dst := add(add(result, 32), 40)
        let src := s2
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            mstore(add(dst, mul(i, 32)), mload(add(src, mul(i, 32))))
        }
    }
}
