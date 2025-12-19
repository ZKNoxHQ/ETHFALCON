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
///* FILE: ZKNOX_common.sol
///* Description: Common Interface for Signature Verifier
/**
 *
 */
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
