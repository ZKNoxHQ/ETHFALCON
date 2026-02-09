// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_HashToPoint.sol
// Description: verify falcon core component
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_shake.sol";
//import {Test, console} from "forge-std/Test.sol";
//import "./ZKNOX_display.sol";

uint256 constant MASK_2BYTES = uint256(0xFFFF);

function hashToPointRIP(bytes memory salt, bytes memory msgHash) pure returns (uint256[] memory output) {
    output = new uint256[](n);

    bytes32 state;

    // Initial state
    state = keccak256(abi.encodePacked(salt, msgHash));
    bytes memory extendedState = abi.encodePacked(state, uint64(0x00));

    assembly ("memory-safe") {
        let counter := 0
        let i := 0
        let offset := add(output, 32)
        let extendedAdress := add(extendedState, 64)
        for {} lt(i, n) {} {
            let buffer := keccak256(add(extendedState, 32), 40)
            for { let j := 240 } lt(j, 666) { j := sub(j, 16) } {
                let chunk := and(shr(j, buffer), 0xffff)
                if lt(chunk, kq) {
                    mstore(offset, mod(chunk, q))
                    offset := add(offset, 32)
                    i := add(i, 1)
                    if eq(i, 512) { break }
                }
            }

            counter := add(counter, 6277101735386680763835789423207666416102355444464034512896) //counter+=1, shift by 192 to increment directly memory buffer by a 64 bits counter.
            mstore(extendedAdress, counter)
        }
    }
}

// OPTIMIZATION: Assembly implementation instead of Solidity loop
function splitToHex(bytes32 x) pure returns (uint16[16] memory res) {
    // splits a byte32 into hex
    assembly ("memory-safe") {
        let xVal := x
        for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
            // res[i] = uint16(uint256(x) >> ((15 - i) * 16))
            let shift := shl(4, sub(15, i)) // (15 - i) * 16
            mstore(add(res, shl(5, i)), and(shr(shift, xVal), 0xffff))
        }
    }
}

// OPTIMIZATION: unchecked for bounded loop counters
function hashToPointNIST(bytes memory salt, bytes memory msgHash) pure returns (uint256[] memory) {
    // SALT AND MSG ARE SWAPPED!
    uint256[] memory hashed = new uint256[](512);
    uint256 i = 0;
    uint256 j = 0;
    CtxShake memory ctx;
    bytes memory tmp;
    ctx = shakeUpdate(ctx, abi.encodePacked(salt, msgHash));
    ctx = shakePad(ctx);
    (ctx, tmp) = shakeSqueeze(ctx, _RATE);

    unchecked {
        while (i < n) {
            if (j == _RATE) {
                (ctx, tmp) = shakeSqueeze(ctx, _RATE);
                j = 0;
            }
            uint256 dibytes = uint256(uint8(tmp[j + 1])) + (uint256(uint8(tmp[j])) << 8);
            if (dibytes < kq) {
                hashed[i] = dibytes % q;
                i++;
            }
            j += 2;
        }
    }
    //hashed=Swap(hashed);
    return hashed;
}

//Use for Poc only, as this XOF doesn't respect separation domain for input and output of internal state
//CVETH-2025-080203
// OPTIMIZATION: unchecked for bounded loop counters
function hashToPointTETRATION(bytes memory salt, bytes memory msgHash) pure returns (uint256[] memory) {
    uint256[] memory hashed = new uint256[](512);
    uint256 i = 0;
    uint256 j = 0;
    bytes32 tmp = keccak256(abi.encodePacked(msgHash, salt));
    uint16[16] memory sample = splitToHex(tmp);

    unchecked {
        while (i < n) {
            if (j == 16) {
                tmp = keccak256(abi.encodePacked(tmp));
                sample = splitToHex(tmp);
                j = 0;
            }
            if (sample[j] < kq) {
                hashed[i] = sample[j] % q;
                i++;
            }
            j++;
        }
    }
    return hashed;
}
