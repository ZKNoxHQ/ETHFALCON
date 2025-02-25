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
///* FILE: ZKNOX_falcon.sol
///* Description: Compute ethereum friendly version of falcon verification
/**
 *
 */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ZKNOX_NTT} from "./ZKNOX_NTT.sol";

//choose the XOF to use here
import "./HashToPoint.sol";
import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_falcon_core.sol";

contract ZKNOX_falcon {
    ZKNOX_NTT ntt;

    //Outer NTT contract, initialized with falcon field parameters
    constructor(ZKNOX_NTT i_ntt) {
        ntt = i_ntt;
    }

    struct Signature {
        bytes salt;
        uint256[512] s2; // CVETH-2025-080202: remove potential malleability by forcing positive coefficients with uint
    }

    struct FalconPubKey {
        uint256[] value; //polynomial representing the public key, either in canonical or ntt form;
        bool nttform;
        bool is_compact;
        uint256 hashID; //identifier for the internal XOF
    }

    struct FalconSignature {
        bytes salt;
        uint256[] s2; // CVETH-2025-080202: remove potential malleability by forcing positive coefficients with uint
    }

    function CheckKey(FalconPubKey memory Pubkey) public pure returns (bool) {
        bool isKnownID = false;

        if (Pubkey.is_compact) {
            if (Pubkey.value.length != _FALCON_WORD256_S) return false;
        } else {
            if (Pubkey.value.length != _FALCON_WORD32_S) return false;
        }

        if (falcon_checkPolynomialRange(Pubkey.value, Pubkey.is_compact) != true) return false;

        if (Pubkey.hashID == ID_keccak) isKnownID = true;
        if (Pubkey.hashID == ID_tetration) isKnownID = true;

        return isKnownID;
    }

    function verify(
        bytes memory msgs,
        Signature memory signature,
        uint256[] memory h, // public key
        bool h_zknox // choose Tetration's or ZKNox hash function
    ) public view returns (bool result) {
        if (h.length != 512) return false; //"Invalid public key length"
        if (signature.salt.length != 40) return false; //CVETH-2025-080201: control salt length to avoid potential forge
        if (signature.s2.length != 512) return false; //"Invalid salt length"

        h = ntt.ZKNOX_NTTFW(h, ntt.o_psirev());

        result = false;

        uint256[] memory hashed;
        if (h_zknox) {
            hashed = hashToPointZKNOX(signature.salt, msgs, q, n);
        } else {
            hashed = hashToPointTETRATION(signature.salt, msgs, q, n);
        }

        return falcon_core_expanded(ntt, signature.salt, signature.s2, h, hashed);
    }

    function verify_opt(
        bytes memory msgs,
        Signature memory signature,
        uint256[] memory ntth, // public key
        bool h_zknox
    ) public view returns (bool result) {
        if (ntth.length != 512) return false; //"Invalid public key length"
        if (signature.salt.length != 40) return false; //CVETH-2025-080201: control salt length to avoid potential forge
        if (signature.s2.length != 512) return false; //"Invalid salt length"

        result = false;

        uint256[] memory hashed;
        if (h_zknox) {
            hashed = hashToPointZKNOX(signature.salt, msgs, q, n);
        } else {
            hashed = hashToPointTETRATION(signature.salt, msgs, q, n);
        }

        return falcon_core_expanded(ntt, signature.salt, signature.s2, ntth, hashed);
    }

    function verify(FalconPubKey memory pk, bytes memory msgs, FalconSignature memory signature)
        public
        view
        returns (bool result)
    {
        result = false;

        uint256[] memory hashed;
        if (CheckKey(pk) == false) return false;

        if (pk.hashID == ID_keccak) {
            hashed = hashToPointZKNOX(signature.salt, msgs, q, n);
        } else {
            if (pk.hashID == ID_tetration) {
                hashed = hashToPointTETRATION(signature.salt, msgs, q, n);
            } else {
                return false;
            } //unknwon ID
        }

        if (pk.is_compact == false) {
            if (pk.nttform == false) {
                //convert public key to ntt form
                pk.value = ntt.ZKNOX_NTTFW(pk.value, ntt.o_psirev());
            }
            signature.s2 = _ZKNOX_NTT_Compact(signature.s2);
        }

        return falcon_core(ntt, signature.salt, signature.s2, pk.value, hashed); //not implemented yet
    }
}

//end of contract
/* the contract shall be initialized with a valid precomputation of psi_rev and psi_invrev contracts provided to the input ntt contract*/
