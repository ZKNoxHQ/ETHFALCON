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
///* Description: Compute NIST compliant falcon verification
/**
 *
 */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_common.sol";
import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_falcon_core.sol";
import "./ZKNOX_HashToPoint.sol";
import {ISigVerifier} from "InterfaceVerifier/IVerifier.sol";

/// @title ZKNOX_falcon
/// @notice A contract to verify FALCON signatures
/// @dev The format of function is compacted, not compressed, for KATS verification look at dedicated ZKNOX_falconKATS.sol

/// @custom:experimental This library is not audited yet, do not use in production.

contract ZKNOX_falcon is ISigVerifier {
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

    function setKey(bytes memory pubkey) external pure returns (bytes memory) {
        return pubkey;
    }

    /// @notice Compute the  falcon NIST verification function

    /// @param h the hash of message to be signed, expected length is 32 bytes
    /// @param salt the message to be signed, expected length is 40 bytes
    /// @param s2 second part of the signature in Compacted representation (see IO part of README for encodings specification), expected length is 32 uint256
    /// @param ntth public key in the ntt domain, compacted 16  coefficients of 16 bits per word
    /// @return result boolean result of the verification

    function verify(
        bytes memory h, //a 32 bytes hash
        bytes memory salt, // compacted signature salt part
        uint256[] memory s2, // compacted signature s2 part
        uint256[] memory ntth // public key, compacted representing coefficients over 16 bits
    )
        external
        pure
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

        uint256[] memory hashed = hashToPointNIST(salt, h);

        result = falcon_core(s2, ntth, hashed);
        //if (result == false) revert("wrong sig");

        return result;
    }

    function verify(bytes calldata _pubkey, bytes32 _digest, bytes calldata _sig) external view returns (bytes4) {
        bytes memory pubkey = _pubkey;
        bytes memory digest = abi.encodePacked(_digest);
        bytes memory sig = _sig;

        uint256 saltPtr;
        uint256 s2Ptr;
        uint256 ntthPtr;

        assembly {
            // === Salt ===
            let freePtr := mload(0x40)
            saltPtr := freePtr
            mstore(saltPtr, SALT_LEN)
            let src := add(sig, 32)
            let dst := add(saltPtr, 32)
            for { let i := 0 } lt(i, SALT_LEN) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(src, i)))
            }

            let saltAllocSize := and(add(SALT_LEN, 31), not(31))
            freePtr := add(freePtr, add(32, saltAllocSize))

            // === s2 ===
            let s2DataStart := add(src, SALT_LEN)
            let s2LengthSlot := sub(s2DataStart, 32)

            let savedPtr := freePtr
            mstore(savedPtr, mload(sig))
            mstore(add(savedPtr, 32), mload(pubkey))
            mstore(add(savedPtr, 64), mload(s2LengthSlot))
            mstore(0x40, add(savedPtr, 96))

            mstore(s2LengthSlot, div(sub(mload(sig), SALT_LEN), 32))
            s2Ptr := s2LengthSlot

            // === ntth ===
            mstore(pubkey, div(mload(pubkey), 32))
            ntthPtr := pubkey
        }

        bool result = this.verify(digest, _ptrToBytes(saltPtr), _ptrToUint256Array(s2Ptr), _ptrToUint256Array(ntthPtr));

        assembly {
            let savedPtr := sub(mload(0x40), 96)
            mstore(sig, mload(savedPtr))
            mstore(pubkey, mload(add(savedPtr, 32)))
            mstore(add(sig, SALT_LEN), mload(add(savedPtr, 64)))
        }

        if (result) {
            return ISigVerifier.verify.selector;
        }
        return 0xFFFFFFFF;
    }

    function _ptrToBytes(uint256 ptr) private pure returns (bytes memory result) {
        assembly { result := ptr }
    }

    function _ptrToUint256Array(uint256 ptr) private pure returns (uint256[] memory result) {
        assembly { result := ptr }
    }

    //extract the ntt representation of the public key deployed at the _from address input
    function GetPublicKey(address _from) external view returns (uint256[] memory Kpub) {
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
