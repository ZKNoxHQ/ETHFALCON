// SPDX-License-Identifier: MIT
// FILE: ZKNOX_shake_fast.sol
//
// Drop-in replacement for the SHAKE256 XOF used by hashToPointNIST.
//
// The sponge glue (_xorBlockFast170 / _squeezeBlockFast170 / f1600Fast170) is
// taken verbatim from fireblocks-labs/evm-ml-dsa-verifier (MIT),
// src/FastKeccak170.sol. The Keccak-f[1600] permutation itself is NOT Solidity
// here: it is a 21,622-byte fully-unrolled raw-runtime helper contract
// (helpers/f1600_170.hex in that repository) reached by STATICCALL, with the
// 25-lane state passed in and out in place.
//
// hashToPointNISTFast below keeps the rejection sampler of
// ZKNOX_HashToPoint.hashToPointNIST byte for byte. Only the XOF changes.
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";

uint256 constant _M64_170 = 0xffffffffffffffff;
uint256 constant _RATE_FAST = 136;

/// @notice Keccak-f[1600] permutation, in place on `st` (25 words, lane i = x + 5*y).
function f1600Fast170(uint256[25] memory st, address helper) view {
    bool ok;
    assembly ("memory-safe") {
        ok := staticcall(gas(), helper, st, 800, st, 800)
        ok := and(ok, eq(returndatasize(), 800))
    }
    require(ok, "f1600-170: helper call failed");
}

/// @dev XOR one 136-byte rate block at memory `ptr` into the sponge state (lanes 0..16).
function _xorBlockFast170(uint256[25] memory st, uint256 ptr) pure {
    assembly ("memory-safe") {
        function grev(w) -> v {
            let a := and(w, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
            v := or(shr(8, a), shl(8, xor(w, a)))
            a := and(v, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)
            v := or(shr(16, a), shl(16, xor(v, a)))
            a := and(v, 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)
            v := or(shr(32, a), shl(32, xor(v, a)))
        }
        let v := grev(mload(ptr))
        mstore(st, xor(mload(st), shr(192, v)))
        mstore(add(st, 32), xor(mload(add(st, 32)), and(shr(128, v), _M64_170)))
        mstore(add(st, 64), xor(mload(add(st, 64)), and(shr(64, v), _M64_170)))
        mstore(add(st, 96), xor(mload(add(st, 96)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 32)))
        mstore(add(st, 128), xor(mload(add(st, 128)), shr(192, v)))
        mstore(add(st, 160), xor(mload(add(st, 160)), and(shr(128, v), _M64_170)))
        mstore(add(st, 192), xor(mload(add(st, 192)), and(shr(64, v), _M64_170)))
        mstore(add(st, 224), xor(mload(add(st, 224)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 64)))
        mstore(add(st, 256), xor(mload(add(st, 256)), shr(192, v)))
        mstore(add(st, 288), xor(mload(add(st, 288)), and(shr(128, v), _M64_170)))
        mstore(add(st, 320), xor(mload(add(st, 320)), and(shr(64, v), _M64_170)))
        mstore(add(st, 352), xor(mload(add(st, 352)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 96)))
        mstore(add(st, 384), xor(mload(add(st, 384)), shr(192, v)))
        mstore(add(st, 416), xor(mload(add(st, 416)), and(shr(128, v), _M64_170)))
        mstore(add(st, 448), xor(mload(add(st, 448)), and(shr(64, v), _M64_170)))
        mstore(add(st, 480), xor(mload(add(st, 480)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 104)))
        mstore(add(st, 512), xor(mload(add(st, 512)), and(v, _M64_170)))
    }
}

/// @dev Write one full 136-byte squeeze block from the state to memory at `outPtr`.
function _squeezeBlockFast170(uint256[25] memory st, uint256 outPtr) pure {
    assembly ("memory-safe") {
        function grev(w) -> v {
            v :=
                or(
                    and(shl(8, w), 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00),
                    and(shr(8, w), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                )
            v :=
                or(
                    and(shl(16, v), 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000),
                    and(shr(16, v), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
                )
            v :=
                or(
                    and(shl(32, v), 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000),
                    and(shr(32, v), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)
                )
        }
        mstore(
            outPtr,
            grev(
                or(
                    or(or(shl(192, mload(st)), shl(128, mload(add(st, 32)))), shl(64, mload(add(st, 64)))),
                    mload(add(st, 96))
                )
            )
        )
        mstore(
            add(outPtr, 32),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 128))), shl(128, mload(add(st, 160)))), shl(64, mload(add(st, 192)))),
                    mload(add(st, 224))
                )
            )
        )
        mstore(
            add(outPtr, 64),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 256))), shl(128, mload(add(st, 288)))), shl(64, mload(add(st, 320)))),
                    mload(add(st, 352))
                )
            )
        )
        mstore(
            add(outPtr, 96),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 384))), shl(128, mload(add(st, 416)))), shl(64, mload(add(st, 448)))),
                    mload(add(st, 480))
                )
            )
        )
        mstore(
            add(outPtr, 104),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 416))), shl(128, mload(add(st, 448)))), shl(64, mload(add(st, 480)))),
                    mload(add(st, 512))
                )
            )
        )
    }
}

/// @dev Absorb `input` with FIPS 202 1111 + pad10*1 padding and run the final permutation.
///      Leaves `st` ready for the first squeeze block.
function _absorbFast170(uint256[25] memory st, bytes memory input, address helper) view {
    uint256 ptr;
    uint256 len = input.length;
    assembly ("memory-safe") {
        ptr := add(input, 32)
    }
    unchecked {
        uint256 nFull = len / 136;
        for (uint256 i = 0; i < nFull; ++i) {
            _xorBlockFast170(st, ptr);
            f1600Fast170(st, helper);
            ptr += 136;
        }
        uint256 rem = len - nFull * 136;
        bytes memory last = new bytes(136);
        assembly ("memory-safe") {
            let dst := add(last, 32)
            mcopy(dst, ptr, rem)
            mstore8(add(dst, rem), 0x1f)
            mstore(add(dst, 104), xor(mload(add(dst, 104)), 0x80))
            ptr := dst
        }
        _xorBlockFast170(st, ptr);
        f1600Fast170(st, helper);
    }
}

/// @notice Minimal SHAKE256 over the external helper. Same contract as shake256().
function shake256Fast(bytes memory input, uint256 outLen, address helper) view returns (bytes memory output) {
    uint256[25] memory st;
    _absorbFast170(st, input, helper);
    unchecked {
        uint256 nOut = outLen == 0 ? 1 : (outLen + 135) / 136;
        output = new bytes(nOut * 136);
        uint256 outPtr;
        assembly ("memory-safe") {
            outPtr := add(output, 32)
            mstore(output, outLen)
        }
        uint256 done = 0;
        while (true) {
            _squeezeBlockFast170(st, outPtr + done);
            done += 136;
            if (done >= outLen) break;
            f1600Fast170(st, helper);
        }
    }
}

/// @notice hashToPointNIST with the pure-Solidity SHAKE replaced by the helper-backed one.
/// @dev The rejection sampler is IDENTICAL to ZKNOX_HashToPoint.hashToPointNIST:
///      same big-endian 16-bit reads out of a `bytes memory` rate block, same
///      `< kq` acceptance, same `% q`. Only the XOF underneath changes, so the
///      delta is the SHAKE cost and nothing else.
function hashToPointNISTFast(bytes memory salt, bytes memory msgHash, address helper)
    view
    returns (uint256[] memory)
{
    // SALT AND MSG ARE SWAPPED! (kept from the original)
    uint256[] memory hashed = new uint256[](512);
    uint256 i = 0;
    uint256 j = 0;

    uint256[25] memory st;
    _absorbFast170(st, abi.encodePacked(salt, msgHash), helper);

    bytes memory tmp = new bytes(_RATE_FAST);
    uint256 outPtr;
    assembly ("memory-safe") {
        outPtr := add(tmp, 32)
    }
    _squeezeBlockFast170(st, outPtr);

    unchecked {
        while (i < n) {
            if (j == _RATE_FAST) {
                f1600Fast170(st, helper);
                _squeezeBlockFast170(st, outPtr);
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
    return hashed;
}
