/**
 *
 */
/*ZZZZZZZZZZZZZZZZZZZKKKKKKKKK    KKKKKKKNNNNNNNN        NNNNNNNN     OOOOOOOOO     XXXXXXX       XXXXXXX                         ..../&@&#.       .###%@@@#, ..
/*Z:::::::::::::::::ZK:::::::K    K:::::KN:::::::N       N::::::N   OO:::::::::OO   X:::::X       X:::::X                      ...(@@* .... .           &#//%@@&,.
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::::N      N::::::N OO:::::::::::::OO X:::::X       X:::::X                    ..*@@.........              .@#%%(%&@&..
/*Z:::ZZZZZZZZ:::::Z K:::::::K   K::::::KN:::::::::N     N::::::NO:::::::OOO:::::::OX::::::X     X::::::X                   .*@( ........ .  .&@@@@.      .@%%%%%#&@@.
/*ZZZZZ     Z:::::Z  KK::::::K  K:::::KKKN::::::::::N    N::::::NO::::::O   O::::::OXXX:::::X   X::::::XX                ...&@ ......... .  &.     .@      /@%%%%%%&@@#
/*        Z:::::Z      K:::::K K:::::K   N:::::::::::N   N::::::NO:::::O     O:::::O   X:::::X X:::::X                   ..@( .......... .  &.     ,&      /@%%%%&&&&@@@.
/*       Z:::::Z       K::::::K:::::K    N:::::::N::::N  N::::::NO:::::O     O:::::O    X:::::X:::::X                   ..&% ...........     .@%(#@#      ,@%%%%&&&&&@@@%.
/*      Z:::::Z        K:::::::::::K     N::::::N N::::N N::::::NO:::::O     O:::::O     X:::::::::X                   ..,@ ............                 *@%%%&%&&&&&&@@@.
/*     Z:::::Z         K:::::::::::K     N::::::N  N::::N:::::::NO:::::O     O:::::O     X:::::::::X                  ..(@ .............             ,#@&&&&&&&&&&&&@@@@*
/*    Z:::::Z          K::::::K:::::K    N::::::N   N:::::::::::NO:::::O     O:::::O    X:::::X:::::X                   .*@..............  . ..,(%&@@&&&&&&&&&&&&&&&&@@@@,
/*   Z:::::Z           K:::::K K:::::K   N::::::N    N::::::::::NO:::::O     O:::::O   X:::::X X:::::X                 ...&#............. *@@&&&&&&&&&&&&&&&&&&&&@@&@@@@&
/*ZZZ:::::Z     ZZZZZKK::::::K  K:::::KKKN::::::N     N:::::::::NO::::::O   O::::::OXXX:::::X   X::::::XX               ...@/.......... *@@@@. ,@@.  &@&&&&&&@@@@@@@@@@@.
/*Z::::::ZZZZZZZZ:::ZK:::::::K   K::::::KN::::::N      N::::::::NO:::::::OOO:::::::OX::::::X     X::::::X               ....&#..........@@@, *@@&&&@% .@@@@@@@@@@@@@@@&
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::N       N:::::::N OO:::::::::::::OO X:::::X       X:::::X                ....*@.,......,@@@...@@@@@@&..%@@@@@@@@@@@@@/
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::N        N::::::N   OO:::::::::OO   X:::::X       X:::::X                   ...*@,,.....%@@@,.........%@@@@@@@@@@@@(
/*ZZZZZZZZZZZZZZZZZZZKKKKKKKKK    KKKKKKKNNNNNNNN         NNNNNNN     OOOOOOOOO     XXXXXXX       XXXXXXX                      ...&@,....*@@@@@ ..,@@@@@@@@@@@@@&.
/*                                                                                                                                   ....,(&@@&..,,,/@&#*. .
/*                                                                                                                                    ......(&.,.,,/&@,.
/*                                                                                                                                      .....,%*.,*@%
/*                                                                                                                                    .#@@@&(&@*,,*@@%,..
/*                                                                                                                                    .##,,,**$.,,*@@@@@%.
/*                                                                                                                                     *(%%&&@(,,**@@@@@&
/*                                                                                                                                      . .  .#@((@@(*,**
/*                                                                                                                                             . (*. .
/*                                                                                                                                              .*/
///* Copyright (C) 2025 - Renaud Dubois, Simon Masson - This file is part of ZKNOX project
///* License: This software is licensed under MIT License
///* This Code may be reused including this header, license and copyright notice.
///* See LICENSE file at the root folder of the project.
///* FILE: ZKNOX_shake.sol
///* Description: SHAKE XOF function implementation
/**
 *
 */
// SPDX-License-Identifier: MIT
//this is a direct translation from https://github.com/coruus/py-keccak/blob/master/fips202/keccak.py
pragma solidity ^0.8.25;

//import {Test, console} from "forge-std/Test.sol";

uint256 constant _RATE = 136;
bool constant _SPONGE_ABSORBING = false;
bool constant _SPONGE_SQUEEZING = true;

struct ctx_shake {
    uint64[25] state;
    uint8[200] buff;
    uint256 i;
    bool direction;
}

// """Rotate uint64 x left by s.""
function rol64(uint256 x, uint256 s) pure returns (uint64) {
    return (uint64)((x << s) ^ (x >> (64 - s)));
}

// OPTIMIZATION: F1600 with unrolled Theta step 2 and Chi - eliminates addmod calls
function F1600(uint64[25] memory state) pure returns (uint64[25] memory) {
    // forgefmt: disable-next-line
    uint256[24] memory _KECCAK_PI = [uint256(10), 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];// forgefmt: disable-next-line
    uint64[24] memory _KECCAK_RC = [uint64(0x0000000000000001), 0x0000000000008082,0x800000000000808a,0x8000000080008000,0x000000000000808b, 0x0000000080000001,0x8000000080008081, 0x8000000000008009,0x000000000000008a, 0x0000000000000088,0x0000000080008009, 0x000000008000000a,0x000000008000808b, 0x800000000000008b,0x8000000000008089, 0x8000000000008003,0x8000000000008002, 0x8000000000000080,0x000000000000800a, 0x800000008000000a,0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008];// forgefmt: disable-next-line
    uint256[24] memory _KECCAK_RHO =[uint256(1), 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];

    uint64[5] memory bc = [uint64(0), 0, 0, 0, 0];

    //console.log("F1600");

    assembly ("memory-safe") {
        for { let i := 0 } lt(i, 24) { i := add(i, 1) } {
            //
            let t
            let offset_X

            // ==================== THETA STEP 1 ====================
            // Optimized: removed redundant mstore(bc,0) then mload(bc)
            for { offset_X := 0 } lt(offset_X, 160) { offset_X := add(offset_X, 32) } {
                //for (uint256 x = 0; x < 5; x++)
                let temp := mload(add(state, offset_X))
                temp := xor(temp, mload(add(state, add(offset_X, 160))))
                temp := xor(temp, mload(add(state, add(offset_X, 320))))
                temp := xor(temp, mload(add(state, add(offset_X, 480))))
                temp := xor(temp, mload(add(state, add(offset_X, 640))))
                mstore(add(bc, offset_X), temp)
            }

            // ==================== THETA STEP 2 ====================
            // OPTIMIZATION: Unrolled to eliminate addmod calls
            // x=0: d = bc[4] ^ rol64(bc[1], 1)
            {
                let bc1 := mload(add(bc, 32))
                let d := xor(mload(add(bc, 128)), and(0xffffffffffffffff, xor(shl(1, bc1), shr(63, bc1))))
                mstore(state, xor(mload(state), d))
                mstore(add(state, 160), xor(mload(add(state, 160)), d))
                mstore(add(state, 320), xor(mload(add(state, 320)), d))
                mstore(add(state, 480), xor(mload(add(state, 480)), d))
                mstore(add(state, 640), xor(mload(add(state, 640)), d))
            }
            // x=1: d = bc[0] ^ rol64(bc[2], 1)
            {
                let bc2 := mload(add(bc, 64))
                let d := xor(mload(bc), and(0xffffffffffffffff, xor(shl(1, bc2), shr(63, bc2))))
                mstore(add(state, 32), xor(mload(add(state, 32)), d))
                mstore(add(state, 192), xor(mload(add(state, 192)), d))
                mstore(add(state, 352), xor(mload(add(state, 352)), d))
                mstore(add(state, 512), xor(mload(add(state, 512)), d))
                mstore(add(state, 672), xor(mload(add(state, 672)), d))
            }
            // x=2: d = bc[1] ^ rol64(bc[3], 1)
            {
                let bc3 := mload(add(bc, 96))
                let d := xor(mload(add(bc, 32)), and(0xffffffffffffffff, xor(shl(1, bc3), shr(63, bc3))))
                mstore(add(state, 64), xor(mload(add(state, 64)), d))
                mstore(add(state, 224), xor(mload(add(state, 224)), d))
                mstore(add(state, 384), xor(mload(add(state, 384)), d))
                mstore(add(state, 544), xor(mload(add(state, 544)), d))
                mstore(add(state, 704), xor(mload(add(state, 704)), d))
            }
            // x=3: d = bc[2] ^ rol64(bc[4], 1)
            {
                let bc4 := mload(add(bc, 128))
                let d := xor(mload(add(bc, 64)), and(0xffffffffffffffff, xor(shl(1, bc4), shr(63, bc4))))
                mstore(add(state, 96), xor(mload(add(state, 96)), d))
                mstore(add(state, 256), xor(mload(add(state, 256)), d))
                mstore(add(state, 416), xor(mload(add(state, 416)), d))
                mstore(add(state, 576), xor(mload(add(state, 576)), d))
                mstore(add(state, 736), xor(mload(add(state, 736)), d))
            }
            // x=4: d = bc[3] ^ rol64(bc[0], 1)
            {
                let bc0 := mload(bc)
                let d := xor(mload(add(bc, 96)), and(0xffffffffffffffff, xor(shl(1, bc0), shr(63, bc0))))
                mstore(add(state, 128), xor(mload(add(state, 128)), d))
                mstore(add(state, 288), xor(mload(add(state, 288)), d))
                mstore(add(state, 448), xor(mload(add(state, 448)), d))
                mstore(add(state, 608), xor(mload(add(state, 608)), d))
                mstore(add(state, 768), xor(mload(add(state, 768)), d))
            }

            // ==================== RHO + PI ====================
            t := mload(add(state, 32)) //t=state[1]

            for { let x := 0 } lt(x, 768) { x := add(x, 32) } {
                //x in [0..23]
                //  for (uint256 x = 0; x < 24; x++) {
                let keccakpix := mload(add(_KECCAK_PI, x)) //_KECCAK_PI[x]
                let kpix := add(state, shl(5, keccakpix)) //@_KECCAK_PI[x];
                mstore(bc, mload(kpix)) //bc[0] = state[keccakpix];
                let res := mload(add(x, _KECCAK_RHO)) // _KECCAK_RHO[x]
                res := and(0xffffffffffffffff, xor(shl(res, t), shr(sub(64, res), t))) //rol64(t, _KECCAK_RHO[x]);

                mstore(kpix, res) //state[keccakpix] = uint64(res);//rol64(t,res);//rol64(t, _KECCAK_RHO[x]);
                t := mload(bc) // t = bc[0];
            }

            // ==================== CHI ====================
            // OPTIMIZATION: Unrolled y loop to eliminate addmod calls
            let rc := mload(add(_KECCAK_RC, shl(5, i)))

            // y=0
            {
                let c0 := mload(state)
                let c1 := mload(add(state, 32))
                let c2 := mload(add(state, 64))
                let c3 := mload(add(state, 96))
                let c4 := mload(add(state, 128))
                mstore(state, xor(c0, and(xor(c1, 0xffffffffffffffff), c2)))
                mstore(add(state, 32), xor(c1, and(xor(c2, 0xffffffffffffffff), c3)))
                mstore(add(state, 64), xor(c2, and(xor(c3, 0xffffffffffffffff), c4)))
                mstore(add(state, 96), xor(c3, and(xor(c4, 0xffffffffffffffff), c0)))
                mstore(add(state, 128), xor(c4, and(xor(c0, 0xffffffffffffffff), c1)))
            }
            mstore(state, and(xor(mload(state), rc), 0xffffffffffffffff)) //state[0] ^= _KECCAK_RC[i];

            // y=1
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
            mstore(state, and(xor(mload(state), rc), 0xffffffffffffffff))

            // y=2
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
            mstore(state, and(xor(mload(state), rc), 0xffffffffffffffff))

            // y=3
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
            mstore(state, and(xor(mload(state), rc), 0xffffffffffffffff))

            // y=4
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
            mstore(state, and(xor(mload(state), rc), 0xffffffffffffffff))
        } //end loop i

    }
    return state;
} //end F1600

// OPTIMIZATION: unchecked for bounded loop variables
function shake_absorb(uint256 i, uint8[200] memory buf, uint64[25] memory state, bytes memory input)
    pure
    returns (uint256 iout, uint8[200] memory bufout, uint64[25] memory stateout)
{
    uint256 todo = input.length;

    //console.log("todo=", todo);
    uint256 index = 0;
    unchecked {
        while (todo > 0) {
            uint256 cando = _RATE - i;
            uint256 willabsorb = (cando < todo) ? cando : todo;
            //console.log("cndo=", cando);
            //console.log("willabsorb=", willabsorb);

            for (uint256 j = 0; j < willabsorb; j++) {
                buf[i + j] ^= uint8(input[index + j]);
            }
            i += willabsorb;

            //console.log("i=", i);
            if (i == _RATE) {
                (buf, state) = shake_permute(buf, state);

                i = 0;
            }
            todo -= willabsorb;
            index += willabsorb;
        }
    }

    return (i, buf, state);
}

//can be ignored, as it is a zeroized structure
function shake_init() pure returns (ctx_shake memory ctx) {
    // forgefmt: disable-next-line
        ctx.state=[uint64(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];// forgefmt: disable-next-line
        ctx.buff=[uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,uint8(0),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    ctx.direction = _SPONGE_ABSORBING;

    return ctx;
}

function shake_update(ctx_shake memory ctx, bytes memory input) pure returns (ctx_shake memory ctxout) {
    if (ctx.direction == _SPONGE_SQUEEZING) {
        (ctx.buff, ctx.state) = shake_permute(ctx.buff, ctx.state);
    }
    ctxout.direction = _SPONGE_ABSORBING;

    (ctxout.i, ctxout.buff, ctxout.state) = shake_absorb(ctx.i, ctx.buff, ctx.state, input);
    return ctxout;
}

// OPTIMIZATION: unchecked for bounded loop variables
function shake_squeeze(ctx_shake memory ctx, uint256 n) pure returns (ctx_shake memory ctxout, bytes memory) {
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
            //console.logBytes(output);
            offset += willsqueeze;
            ctx.i += willsqueeze;
            if (ctx.i == _RATE) {
                (ctx.buff, ctx.state) = shake_permute(ctx.buff, ctx.state);
                ctx.i = 0;
            }
            tosqueeze -= willsqueeze;
        }
    }

    return (ctx, output);
}

function shake_permute(uint8[200] memory buf, uint64[25] memory state)
    pure
    returns (uint8[200] memory buffer, uint64[25] memory stateout)
{
    //require a 64 bits swap
    /*for (uint256 j = 0; j < 200; j++) {
        state[j / 8] ^= uint64(buf[j]) << (((uint8(j & 0x7) << 3)));
    }*/

    assembly {
        for { let j := 0 } lt(j, 200) { j := add(j, 1) } {
            let addr := add(state, shl(5, shr(3, j))) //state[j / 8]
            let val := shl(shl(3, and(j, 7)), and(0xffffffffffffffff, mload(add(buf, shl(5, j))))) // uint64(buf[j]) << (((uint8(j & 0x7) << 3)));

            mstore(addr, xor(mload(addr), val))
        }
    }

    // Call F1600 Keccak permutation function here
    state = F1600(state);
    //directly return buffer: it is zeroized by default
    return (buffer, state); //zeroization of buf external to this function
}

function shake_pad(ctx_shake memory ctx) pure returns (ctx_shake memory ctxout) {
    ctx.buff[ctx.i] ^= 0x1f;
    ctx.buff[_RATE - 1] ^= 0x80;
    (ctx.buff, ctx.state) = shake_permute(ctx.buff, ctx.state);

    ctx.i = 0;

    return ctx;
}

function shake_digest(ctx_shake memory ctx, uint256 size8) pure returns (bytes memory output) {
    output = new bytes(size8);
    if (ctx.direction == _SPONGE_ABSORBING) {
        ctx.buff[ctx.i] ^= 0x1f;
        ctx.buff[_RATE - 1] ^= 0x80;
        (ctx.buff, ctx.state) = shake_permute(ctx.buff, ctx.state);

        ctx.i = 0;
    }
    (, output) = shake_squeeze(ctx, size8);
}
