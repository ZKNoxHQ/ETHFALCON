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
///* FILE: ZKNOX_ethfalcon_old.sol
///* Description: Compute ethereum friendly version of falcon verification (old version)
/**
 *
 */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../ZKNOX_common.sol";
import "../ZKNOX_IVerifier.sol";

import "../ZKNOX_falcon_utils.sol";
import {ZKNOX_NTT} from "../ZKNOX_NTT.sol";
import "./ZKNOX_falcon_core_old.sol";

//choose the XOF to use here
import "../ZKNOX_HashToPoint.sol";

//import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
//import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/* the contract shall be initialized with a valid precomputation of psi_rev and psi_invrev contracts provided to the input ntt contract*/
contract ZKNOX_ethfalcon is ISigVerifier {
    ZKNOX_NTT ntt;
    address public psirev;
    address public psiInvrev;
    bool EIP7885;
    bool immutableMe;
    uint256 err_flag; //a debug flag

    function update(address i_psirev, address i_psiInvrev) public {
        if (immutableMe == true) revert();
        psirev = i_psirev;
        psiInvrev = i_psiInvrev;
        EIP7885 = false;
        immutableMe = true;
    }

    function updateNTT(ZKNOX_NTT i_ntt) public {
        if (immutableMe == true) revert();
        ntt = i_ntt;
        EIP7885 = true;
        immutableMe = true;
    }

    function setflag(uint256 value) public {
        err_flag = value;
    }

    struct CompactSignature {
        bytes salt;
        uint256[] s2; // compacted signature
    }

    function CheckParameters(CompactSignature memory signature, uint256[] memory ntth) internal pure returns (bool) {
        if (ntth.length != falcon_S256) return false; //"Invalid public key length"
        if (signature.salt.length != 40) return false; //CVETH-2025-080201: control salt length to avoid potential forge
        if (signature.s2.length != falcon_S256) return false; //"Invalid salt length"

        return true;
    }

    function verify(
        bytes memory msgs,
        CompactSignature memory signature,
        uint256[] memory ntth // public key, compacted representing coefficients over 16 bits
    )
        public
        view
        returns (bool result)
    {
        if (CheckParameters(signature, ntth) == false) return false;

        uint256[] memory hashed = hashToPointRIP(signature.salt, msgs);
        return falcon_core(ntt, signature.salt, signature.s2, ntth, hashed);
    }

    function verifyTetration(
        bytes memory msgs,
        CompactSignature memory signature,
        uint256[] memory ntth // public key, compacted representing coefficients over 16 bits
    )
        public
        view
        returns (bool result)
    {
        if (CheckParameters(signature, ntth) == false) return false;
        uint256[] memory hashed = hashToPointTETRATION(signature.salt, msgs);
        return falcon_core(ntt, signature.salt, signature.s2, ntth, hashed);
    }

    function verify_spec(
        bytes memory msgs,
        CompactSignature memory signature,
        uint256[] memory ntth // public key, compacted representing coefficients over 16 bits
    )
        public
        view
        returns (bool result)
    {
        if (CheckParameters(signature, ntth) == false) return false;

        uint256[] memory hashed = hashToPointRIP(signature.salt, msgs);
        return falcon_core(signature.s2, ntth, hashed);
    }

    function verify(
        bytes memory h, //a 32 bytes hash
        bytes memory salt, // compacted signature salt part
        uint256[] memory s2, // compacted signature s2 part
        uint256[] memory ntth // public key, compacted representing coefficients over 16 bits
    )
        external
        view
        returns (bool result)
    {
        // if (h.length != 32) return false;
        if (salt.length != 40) {
            revert("invalid salt length");
            //return false;
        } //CVETH-2025-080201: control salt length to avoid potential forge
        if (s2.length != falcon_S256) {
            revert("invalid s2 length");
            //return false;
        } //"Invalid salt length"
        if (ntth.length != falcon_S256) {
            revert("invalid ntth length");
            //return false;
        } //"Invalid public key length"

        uint256[] memory hashed = hashToPointRIP(salt, h);

        result = falcon_core(s2, ntth, hashed);
        //if (result == false) revert("wrong sig");

        return result;
    }

    function GetPublicKey(address _from) external view override returns (uint256[] memory Kpub) {
        Kpub = new uint256[](32);

        assembly {
            let offset := Kpub

            for { let i := 0 } gt(1024, i) { i := add(i, 32) } {
                //read the 32 words
                offset := add(offset, 32)

                extcodecopy(_from, offset, i, 32) //psi_rev[m+i])
            }
        }
        return Kpub;
    }
} //end of contract ZKNOX_falcon_compact
