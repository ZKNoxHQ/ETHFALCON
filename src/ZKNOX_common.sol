// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_common.sol
// Description: verify falcon core component
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/*id-falcon-shake256 OBJECT IDENTIFIER ::= { joint-iso-ccitt(2)
   country(16) us(840) organization(1) gov(101) csor(3) algorithms(4)
   id-falcon-shake(3) 21 }.*/
uint256 constant FALCONSHAKE_ID = 0x216840110134321;

/*id-falcon-shake256 OBJECT IDENTIFIER ::= { joint-iso-ccitt(2)
   country(16) us(840) organization(1) gov(101) csor(3) algorithms(4)
   id-falcon-keccak(4) 21 }.*/
uint256 constant FALCONKECCAK_ID = 0x216840110134421;

uint256 constant SALT_LEN = 40;

//copy and allocate
function ZKNOX_memcpy32(uint256[32] memory src) pure returns (uint256[] memory dest) {
    dest = new uint256[](32);
    for (uint256 i = 0; i < 32; i++) {
        dest[i] = src[i];
    }

    return dest;
}

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
