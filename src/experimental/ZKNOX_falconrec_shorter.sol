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
///* FILE: ZKNOX_falconrec_shorter.sol
///* Description: verify falcon with recovery signature (old version)
/**
 *
 */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ZKNOX_NTT} from "../ZKNOX_NTT.sol";
import "../ZKNOX_HashToPoint.sol";

contract ZKNOX_falconrec_shorter {
    ZKNOX_NTT ntt;

    constructor(ZKNOX_NTT i_ntt) {
        ntt = i_ntt;
    }

    struct Signature {
        bytes salt;
        uint256[512] s1;
        uint256[512] s2;
        uint256 hint; //the ntt of the inverse of s1, provided as a hint
    }

    function HashToAddress(bytes memory m) public pure returns (address) {
        return address(uint160(uint256(keccak256(m))));
    }

    /* A falcon with recovery implementation*/
    function recover(bytes memory msgs, Signature memory signature) public view returns (address result) {
        if (signature.salt.length != 40) revert("wrong salt length"); //CVETH-2025-080201: control salt length to avoid potential forge
        if (signature.s1.length != 512) revert("Invalid s1 length"); //"Invalid s1 length"
        if (signature.s2.length != 512) revert("Invalid s2 length"); //"Invalid s2 length"
        // if (signature.hint.length != 1) revert("Invalid hint length"); //"Invalid hint length"

        // (s1,s2) must be short
        uint256 norm = 0;
        // As (σ1,σ2) are given with positive values, small negative values are actually large (close to q).
        uint256 i;
        for (i = 0; i < n; i++) {
            if (signature.s1[i] > qs1) {
                norm += (q - signature.s1[i]) * (q - signature.s1[i]);
            } else {
                norm += signature.s1[i] * signature.s1[i];
            }
            if (signature.s2[i] > qs1) {
                norm += (q - signature.s2[i]) * (q - signature.s2[i]);
            } else {
                norm += signature.s2[i] * signature.s2[i];
            }
        }

        if (norm > sigBound) {
            revert("norm too large");
        }

        uint256[] memory s2 = new uint256[](512);
        for (i = 0; i < 512; i++) {
            s2[i] = uint256(signature.s2[i]);
        }

        s2 = ntt.ZKNOX_NTTFW(s2, ntt.o_psirev());

        // recover s2.ntt().inverse() from the hint
        uint256[512] memory prefix;
        prefix[0] = s2[0];
        for (i = 1; i < 512; i++) {
            prefix[i] = mulmod(prefix[i - 1], s2[i], q);
        }
        uint256[512] memory s2_inverse_ntt;
        s2_inverse_ntt[511] = signature.hint;
        for (i = 0; i < 511; i++) {
            s2_inverse_ntt[510 - i] = mulmod(s2_inverse_ntt[511 - i], s2[511 - i], q);
        }
        for (i = 1; i < 512; i++) {
            s2_inverse_ntt[i] = mulmod(s2_inverse_ntt[i], prefix[i - 1], q);
        }

        //ntt(s2)*ntt(s2^-1)==ntt(1)?
        for (i = 0; i < 512; i++) {
            if (mulmod(s2[i], s2_inverse_ntt[i], q) != 1) revert("wrong hint");
        }

        uint256[] memory hashed = hashToPointRIP(signature.salt, msgs);
        for (i = 0; i < 512; i++) {
            //hashToPoint-s1
            hashed[i] = addmod(hashed[i], q - signature.s1[i], q);
        }

        for (i = 0; i < 512; i++) {
            s2[i] = uint256(s2_inverse_ntt[i]);
        }
        uint256[] memory hashed_mul_s2 = ntt.ZKNOX_NTT_HALFMUL(hashed, s2);

        return HashToAddress(abi.encodePacked(hashed_mul_s2));
    }
} //end of contract

/* the contract shall be initialized with a valid precomputation of psi_rev and psi_invrev contracts provided to the input ntt contract*/
