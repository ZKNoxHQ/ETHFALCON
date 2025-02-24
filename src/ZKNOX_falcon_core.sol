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
///* FILE: ZKNOX_falcon_core.sol
///* Description: verify falcon core component
/**
 *
 */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_NTT.sol";

function falcon_checkPolynomialRange(uint256[] memory polynomial, bool is_compact) pure returns (bool) {
    uint256[] memory a;
    if (is_compact == false) {
        a = _ZKNOX_NTT_Expand(polynomial);
    } else {
        a = polynomial;
    }
    for (uint256 i = 0; i < a.length; i++) {
        if (a[i] > q) return false;
    }

    return true;
}

//core falcon verification function, compacted input, WIP (KO on norm)
function falcon_core(
    ZKNOX_NTT ntt,
    bytes memory salt,
    uint256[] memory s2,
    uint256[] memory ntth, // public key, compacted 16  coefficients of 16 bits per word
    uint256[] memory hashed // result of hashToPoint(signature.salt, msgs, q, n);
) view returns (bool result) {
    if (hashed.length != 512) return false;
    if (salt.length != 40) return false; //CVETH-2025-080201: control salt length to avoid potential forge
    if (s2.length != 32) return false; //"Invalid salt length"

    result = false;

    uint256[] memory s1 = _ZKNOX_NTT_Expand(ntt.ZKNOX_NTT_HALFMUL_Compact(s2, ntth));

    uint256 norm = 0;
    for (uint256 i = 0; i < hashed.length; i++) {
        /*
        s1[i] = addmod(hashed[i], q - s1[i], q);
        if (s1[i] > qs1) {// normalize s1
            s1[i] = q - s1[i];
        } 
        norm += s1[i] * s1[i];
        */
        assembly {
            let offset := add(32, mul(32, i)) //offset to read at address tab[i]
            let s1i := addmod(mload(add(hashed, offset)), sub(q, mload(add(s1, offset))), q) //s1[i] = addmod(hashed[i], q - s1[i], q);
            let cond := gt(s1i, qs1) //s1[i] > qs1 ?
            s1i := add(mul(cond, sub(q, s1i)), mul(sub(1, cond), s1i))
            norm := add(norm, mul(s1i, s1i))
        }
    }

    s1 = _ZKNOX_NTT_Expand(s2); //avoiding another memory expansion

    // normalize s2
    for (uint256 i = 0; i < n; i++) {
        /*
        if (s1[i] > qs1) {
            s1[i] = q - s1[i];
        }
        norm += s1[i] * s1[i];
        */
        assembly {
            let s1i := mload(add(s1, add(32, mul(32, i)))) //s1[i]
            let cond := gt(s1i, qs1) //s1[i] > qs1 ?
            s1i := add(mul(cond, sub(q, s1i)), mul(sub(1, cond), s1i))
            norm := add(norm, mul(s1i, s1i))
        }
    }

    if (norm > sigBound) {
        result = false;
    } else {
        result = true;
    }

    return result;
}

//core falcon verification function, expanded input, WIP (untested)
function falcon_core_expanded(
    ZKNOX_NTT ntt,
    bytes memory salt,
    uint256[512] memory s2,
    uint256[] memory ntth, // public key, compacted 16  coefficients of 16 bits per word
    uint256[] memory hashed // result of hashToPoint(signature.salt, msgs, q, n);
) view returns (bool result) {
    if (hashed.length != 512) return false;
    if (salt.length != 40) return false; //CVETH-2025-080201: control salt length to avoid potential forge
    if (s2.length != 512) return false; //"Invalid salt length"

    result = false;

    uint256[] memory s2_in = new uint256[](512);
    for (uint256 i = 0; i < s2.length; i++) {
        s2_in[i] = uint256(s2[i]);
    }

    uint256[] memory s1 = ntt.ZKNOX_NTT_HALFMUL(s2_in, ntth);

    for (uint256 i = 0; i < hashed.length; i++) {
        s1[i] = addmod(hashed[i], q - s1[i], q);
    }

    // normalize s1 // to positive cuz you'll **2 anyway?
    for (uint256 i = 0; i < n; i++) {
        if (s1[i] > qs1) {
            s1[i] = q - s1[i];
        } else {
            s1[i] = s1[i];
        }
    }

    // normalize s2
    for (uint256 i = 0; i < n; i++) {
        if (s2_in[i] > qs1) {
            s2_in[i] = q - s2_in[i];
        } else {
            s2_in[i] = s2_in[i];
        }
    }

    uint256 norm = 0;
    for (uint256 i = 0; i < n; i++) {
        norm += s1[i] * s1[i];
        norm += s2_in[i] * s2_in[i];
    }

    if (norm > sigBound) {
        result = false;
    } else {
        result = true;
    }

    return result;
}
