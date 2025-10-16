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
///* FILE: ZKNOX_falcon_epervier_old.sol
///* Description: verify falcon with recovery signature (old version)
/**
 *
 */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {console} from "forge-std/Test.sol";
import {ZKNOX_NTT} from "../ZKNOX_NTT.sol";

//choose the XOF to use here
import "../ZKNOX_HashToPoint.sol";

contract ZKNOX_falcon_epervier {
    //FALCON CONSTANTS

    ZKNOX_NTT ntt;

    uint256 constant _ERR_INPUT_SIZE = 0xffffffff01;

    constructor(ZKNOX_NTT i_ntt) {
        ntt = i_ntt;
    }

    struct Signature {
        uint256[512] s1;
        uint256[512] s2;
        uint256[512] hint; //the ntt of the inverse of s1, provided as a hint
        bytes salt;
    }

    function HashToAddress(bytes memory m) public pure returns (address) {
        return address(uint160(uint256(keccak256(m))));
    }

    /* A falcon with recovery implementation*/
    function recover(bytes memory msgs, Signature memory signature, bool h_zknox) public view returns (address result) {
        if (signature.salt.length != 40) revert("wrong salt length"); //CVETH-2025-080201: control salt length to avoid potential forge
        if (signature.s1.length != 512) revert("Invalid s1 length"); //"Invalid s1 length"
        if (signature.s2.length != 512) revert("Invalid s2 length"); //"Invalid s2 length"
        if (signature.hint.length != 512) revert("Invalid hint length"); //"Invalid salt length"

        uint256 i;

        // (s1,s2) must be short
        uint256 norm = 0;
        // As (σ1,σ2) are given with positive values, small negative values are actually large (close to q).
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

        s2 = ntt.ZKNOX_NTTFW(s2, ntt.o_psirev()); //ntt(s2)
        //ntt(s2)*ntt(s2^-1)==ntt(1)?
        for (i = 0; i < 512; i++) {
            if (mulmod(s2[i], signature.hint[i], q) != 1) revert("wrong hint");
        }

        uint256[] memory hashed;
        if (h_zknox) {
            hashed = hashToPointRIP(signature.salt, msgs);
        } else {
            hashed = hashToPointTETRATION(signature.salt, msgs);
        }
        for (i = 0; i < 512; i++) {
            //hashToPoint-s1
            hashed[i] = addmod(hashed[i], q - signature.s1[i], q);
        }

        for (i = 0; i < 512; i++) {
            s2[i] = uint256(signature.hint[i]);
        }
        uint256[] memory hashed_mul_s2_ntt = ntt.ZKNOX_VECMULMOD(ntt.ZKNOX_NTTFW(hashed, ntt.o_psirev()), s2, q);
        return HashToAddress(abi.encodePacked(hashed_mul_s2_ntt));
    }
} //end of contract

/* the contract shall be initialized with a valid precomputation of psi_rev and psi_invrev contracts provided to the input ntt contract*/
