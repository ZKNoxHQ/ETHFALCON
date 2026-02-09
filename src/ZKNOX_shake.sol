// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

uint256 constant _RATE = 136;
bool constant _SPONGE_ABSORBING = false;
bool constant _SPONGE_SQUEEZING = true;

struct CtxShake {
    uint64[25] state;
    uint8[200] buff;
    uint256 i;
    bool direction;
}

function rol64(uint256 x, uint256 s) pure returns (uint64) {
    return (uint64)((x << s) ^ (x >> (64 - s)));
}

/**
 * OPTIMIZATION: f1600 with:
 *   1. FIXED: RC applied only ONCE after all 5 Chi y-rows (was applied 5x — 4 redundant)
 *      Saves ~1,152 gas per f1600 call × ~5 calls = ~5-7k gas
 *   2. Unrolled Theta step 2 (eliminates addmod)
 *   3. Unrolled Chi step (eliminates addmod for x offsets)
 */
function f1600(uint64[25] memory state) pure returns (uint64[25] memory) {
    // forgefmt: disable-next-line
    uint256[24] memory _keccakPi = [uint256(10), 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];// forgefmt: disable-next-line
    uint64[24] memory _keccakRc = [uint64(0x0000000000000001), 0x0000000000008082,0x800000000000808a,0x8000000080008000,0x000000000000808b, 0x0000000080000001,0x8000000080008081, 0x8000000000008009,0x000000000000008a, 0x0000000000000088,0x0000000080008009, 0x000000008000000a,0x000000008000808b, 0x800000000000008b,0x8000000000008089, 0x8000000000008003,0x8000000000008002, 0x8000000000000080,0x000000000000800a, 0x800000008000000a,0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008];// forgefmt: disable-next-line
    uint256[24] memory _keccakRho = [uint256(1), 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];

    uint64[5] memory bc;

    assembly ("memory-safe") {
        for { let i := 0 } lt(i, 24) { i := add(i, 1) } {
            let t
            let offset_X

            // ==================== THETA STEP 1 ====================
            for { offset_X := 0 } lt(offset_X, 160) { offset_X := add(offset_X, 32) } {
                let temp := mload(add(state, offset_X))
                temp := xor(temp, mload(add(state, add(offset_X, 160))))
                temp := xor(temp, mload(add(state, add(offset_X, 320))))
                temp := xor(temp, mload(add(state, add(offset_X, 480))))
                temp := xor(temp, mload(add(state, add(offset_X, 640))))
                mstore(add(bc, offset_X), temp)
            }

            // ==================== THETA STEP 2 (unrolled) ====================
            {
                let bc1 := mload(add(bc, 32))
                let d0 := xor(mload(add(bc, 128)), and(0xffffffffffffffff, xor(shl(1, bc1), shr(63, bc1))))
                mstore(state, xor(mload(state), d0))
                mstore(add(state, 160), xor(mload(add(state, 160)), d0))
                mstore(add(state, 320), xor(mload(add(state, 320)), d0))
                mstore(add(state, 480), xor(mload(add(state, 480)), d0))
                mstore(add(state, 640), xor(mload(add(state, 640)), d0))
            }
            {
                let bc2 := mload(add(bc, 64))
                let d1 := xor(mload(bc), and(0xffffffffffffffff, xor(shl(1, bc2), shr(63, bc2))))
                mstore(add(state, 32), xor(mload(add(state, 32)), d1))
                mstore(add(state, 192), xor(mload(add(state, 192)), d1))
                mstore(add(state, 352), xor(mload(add(state, 352)), d1))
                mstore(add(state, 512), xor(mload(add(state, 512)), d1))
                mstore(add(state, 672), xor(mload(add(state, 672)), d1))
            }
            {
                let bc3 := mload(add(bc, 96))
                let d2 := xor(mload(add(bc, 32)), and(0xffffffffffffffff, xor(shl(1, bc3), shr(63, bc3))))
                mstore(add(state, 64), xor(mload(add(state, 64)), d2))
                mstore(add(state, 224), xor(mload(add(state, 224)), d2))
                mstore(add(state, 384), xor(mload(add(state, 384)), d2))
                mstore(add(state, 544), xor(mload(add(state, 544)), d2))
                mstore(add(state, 704), xor(mload(add(state, 704)), d2))
            }
            {
                let bc4 := mload(add(bc, 128))
                let d3 := xor(mload(add(bc, 64)), and(0xffffffffffffffff, xor(shl(1, bc4), shr(63, bc4))))
                mstore(add(state, 96), xor(mload(add(state, 96)), d3))
                mstore(add(state, 256), xor(mload(add(state, 256)), d3))
                mstore(add(state, 416), xor(mload(add(state, 416)), d3))
                mstore(add(state, 576), xor(mload(add(state, 576)), d3))
                mstore(add(state, 736), xor(mload(add(state, 736)), d3))
            }
            {
                let bc0 := mload(bc)
                let d4 := xor(mload(add(bc, 96)), and(0xffffffffffffffff, xor(shl(1, bc0), shr(63, bc0))))
                mstore(add(state, 128), xor(mload(add(state, 128)), d4))
                mstore(add(state, 288), xor(mload(add(state, 288)), d4))
                mstore(add(state, 448), xor(mload(add(state, 448)), d4))
                mstore(add(state, 608), xor(mload(add(state, 608)), d4))
                mstore(add(state, 768), xor(mload(add(state, 768)), d4))
            }

            // ==================== RHO + PI ====================
            t := mload(add(state, 32))

            for { let x := 0 } lt(x, 768) { x := add(x, 32) } {
                let keccakpix := mload(add(_keccakPi, x))
                let kpix := add(state, shl(5, keccakpix))
                mstore(bc, mload(kpix))
                let rho := mload(add(_keccakRho, x))
                mstore(kpix, and(0xffffffffffffffff, xor(shl(rho, t), shr(sub(64, rho), t))))
                t := mload(bc)
            }

            // ==================== CHI (unrolled, RC applied ONCE) ====================
            let rc := mload(add(_keccakRc, shl(5, i)))

            // y=0, offset=0
            {
                let c0 := mload(state)
                let c1 := mload(add(state, 32))
                let c2 := mload(add(state, 64))
                let c3 := mload(add(state, 96))
                let c4 := mload(add(state, 128))
                // FIX: Apply RC to state[0] inline with Chi for y=0 — only once
                mstore(state, and(xor(xor(c0, and(xor(c1, 0xffffffffffffffff), c2)), rc), 0xffffffffffffffff))
                mstore(add(state, 32), xor(c1, and(xor(c2, 0xffffffffffffffff), c3)))
                mstore(add(state, 64), xor(c2, and(xor(c3, 0xffffffffffffffff), c4)))
                mstore(add(state, 96), xor(c3, and(xor(c4, 0xffffffffffffffff), c0)))
                mstore(add(state, 128), xor(c4, and(xor(c0, 0xffffffffffffffff), c1)))
            }
            // NO RC here — already applied above

            // y=1, offset=160
            {
                let c0 := mload(add(state, 160))
                let c1 := mload(add(state, 192))
                let c2 := mload(add(state, 224))
                let c3 := mload(add(state, 256))
                let c4 := mload(add(state, 288))
                mstore(add(state, 160), xor(c0, and(xor(c1, 0xffffffffffffffff), c2)))
                mstore(add(state, 192), xor(c1, and(xor(c2, 0xffffffffffffffff), c3)))
                mstore(add(state, 224), xor(c2, and(xor(c3, 0xffffffffffffffff), c4)))
                mstore(add(state, 256), xor(c3, and(xor(c4, 0xffffffffffffffff), c0)))
                mstore(add(state, 288), xor(c4, and(xor(c0, 0xffffffffffffffff), c1)))
            }
            // NO RC here

            // y=2, offset=320
            {
                let c0 := mload(add(state, 320))
                let c1 := mload(add(state, 352))
                let c2 := mload(add(state, 384))
                let c3 := mload(add(state, 416))
                let c4 := mload(add(state, 448))
                mstore(add(state, 320), xor(c0, and(xor(c1, 0xffffffffffffffff), c2)))
                mstore(add(state, 352), xor(c1, and(xor(c2, 0xffffffffffffffff), c3)))
                mstore(add(state, 384), xor(c2, and(xor(c3, 0xffffffffffffffff), c4)))
                mstore(add(state, 416), xor(c3, and(xor(c4, 0xffffffffffffffff), c0)))
                mstore(add(state, 448), xor(c4, and(xor(c0, 0xffffffffffffffff), c1)))
            }
            // NO RC here

            // y=3, offset=480
            {
                let c0 := mload(add(state, 480))
                let c1 := mload(add(state, 512))
                let c2 := mload(add(state, 544))
                let c3 := mload(add(state, 576))
                let c4 := mload(add(state, 608))
                mstore(add(state, 480), xor(c0, and(xor(c1, 0xffffffffffffffff), c2)))
                mstore(add(state, 512), xor(c1, and(xor(c2, 0xffffffffffffffff), c3)))
                mstore(add(state, 544), xor(c2, and(xor(c3, 0xffffffffffffffff), c4)))
                mstore(add(state, 576), xor(c3, and(xor(c4, 0xffffffffffffffff), c0)))
                mstore(add(state, 608), xor(c4, and(xor(c0, 0xffffffffffffffff), c1)))
            }
            // NO RC here

            // y=4, offset=640
            {
                let c0 := mload(add(state, 640))
                let c1 := mload(add(state, 672))
                let c2 := mload(add(state, 704))
                let c3 := mload(add(state, 736))
                let c4 := mload(add(state, 768))
                mstore(add(state, 640), xor(c0, and(xor(c1, 0xffffffffffffffff), c2)))
                mstore(add(state, 672), xor(c1, and(xor(c2, 0xffffffffffffffff), c3)))
                mstore(add(state, 704), xor(c2, and(xor(c3, 0xffffffffffffffff), c4)))
                mstore(add(state, 736), xor(c3, and(xor(c4, 0xffffffffffffffff), c0)))
                mstore(add(state, 768), xor(c4, and(xor(c0, 0xffffffffffffffff), c1)))
            }
            // NO RC here — was the 5th redundant application
        }
    }
    return state;
}

function shakeAbsorb(uint256 i, uint8[200] memory buf, uint64[25] memory state, bytes memory input)
    pure
    returns (uint256 iout, uint8[200] memory bufout, uint64[25] memory stateout)
{
    uint256 todo = input.length;
    uint256 index = 0;

    unchecked {
        while (todo > 0) {
            uint256 cando = _RATE - i;
            uint256 willabsorb = (cando < todo) ? cando : todo;

            for (uint256 j = 0; j < willabsorb; j++) {
                buf[i + j] ^= uint8(input[index + j]);
            }
            i += willabsorb;

            if (i == _RATE) {
                (buf, state) = shakePermute(buf, state);
                i = 0;
            }
            todo -= willabsorb;
            index += willabsorb;
        }
    }
    return (i, buf, state);
}

function shakeInit() pure returns (CtxShake memory ctx) {
    // forgefmt: disable-next-line
        ctx.state=[uint64(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];// forgefmt: disable-next-line
        ctx.buff=[uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    ctx.direction = _SPONGE_ABSORBING;
    return ctx;
}

function shakeUpdate(CtxShake memory ctx, bytes memory input) pure returns (CtxShake memory ctxout) {
    if (ctx.direction == _SPONGE_SQUEEZING) {
        (ctx.buff, ctx.state) = shakePermute(ctx.buff, ctx.state);
    }
    ctxout.direction = _SPONGE_ABSORBING;
    (ctxout.i, ctxout.buff, ctxout.state) = shakeAbsorb(ctx.i, ctx.buff, ctx.state, input);
    return ctxout;
}

function shakeSqueeze(CtxShake memory ctx, uint256 n) pure returns (CtxShake memory ctxout, bytes memory) {
    bytes memory output = new bytes(n);
    uint256 tosqueeze = n;
    uint256 offset = 0;

    unchecked {
        while (tosqueeze > 0) {
            uint256 cansqueeze = _RATE - ctx.i;
            uint256 willsqueeze = (cansqueeze < tosqueeze) ? cansqueeze : tosqueeze;

            for (uint256 j = 0; j < willsqueeze; j++) {
                uint256 read = ctx.i + j;
                output[offset + j] = bytes1(uint8((ctx.state[(read >> 3)] >> ((read & 7) << 3)) & 0xff));
            }
            offset += willsqueeze;
            ctx.i += willsqueeze;
            if (ctx.i == _RATE) {
                (ctx.buff, ctx.state) = shakePermute(ctx.buff, ctx.state);
                ctx.i = 0;
            }
            tosqueeze -= willsqueeze;
        }
    }

    return (ctx, output);
}

/**
 * OPTIMIZATION: Process buf→state XOR in uint64 chunks (25 iterations vs 200)
 * Each iteration XORs 8 bytes at once.
 * Estimated savings: ~3k-5k gas per permutation × ~5 calls = ~15-25k gas
 */
function shakePermute(uint8[200] memory buf, uint64[25] memory state)
    pure
    returns (uint8[200] memory buffer, uint64[25] memory stateout)
{
    assembly {
        // Process 8 bytes at a time — 25 uint64 words instead of 200 bytes
        for { let w := 0 } lt(w, 25) { w := add(w, 1) } {
            let stateAddr := add(state, mul(w, 32))
            let bufBase := add(buf, mul(mul(w, 8), 32)) // buf is uint8[200], each element at 32-byte slot

            // Reconstruct the uint64 from 8 individual uint8 slots in buf
            let val := mload(bufBase)
            val := or(val, shl(8, mload(add(bufBase, 32))))
            val := or(val, shl(16, mload(add(bufBase, 64))))
            val := or(val, shl(24, mload(add(bufBase, 96))))
            val := or(val, shl(32, mload(add(bufBase, 128))))
            val := or(val, shl(40, mload(add(bufBase, 160))))
            val := or(val, shl(48, mload(add(bufBase, 192))))
            val := or(val, shl(56, mload(add(bufBase, 224))))
            val := and(val, 0xffffffffffffffff)

            mstore(stateAddr, xor(mload(stateAddr), val))
        }
    }

    state = f1600(state);
    return (buffer, state);
}

function shakePad(CtxShake memory ctx) pure returns (CtxShake memory ctxout) {
    ctx.buff[ctx.i] ^= 0x1f;
    ctx.buff[_RATE - 1] ^= 0x80;
    (ctx.buff, ctx.state) = shakePermute(ctx.buff, ctx.state);

    ctx.i = 0;

    return ctx;
}

function shakeDigest(CtxShake memory ctx, uint256 size8) pure returns (bytes memory output) {
    output = new bytes(size8);
    if (ctx.direction == _SPONGE_ABSORBING) {
        ctx.buff[ctx.i] ^= 0x1f;
        ctx.buff[_RATE - 1] ^= 0x80;
        (ctx.buff, ctx.state) = shakePermute(ctx.buff, ctx.state);

        ctx.i = 0;
    }
    (, output) = shakeSqueeze(ctx, size8);
}
