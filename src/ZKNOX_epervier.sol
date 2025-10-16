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
///* FILE: ZKNOX_epervier.sol
///* Description: recover an epervier public key from an epervier signature
/**
 *
 */
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_NTT_falcon.sol";
import "./ZKNOX_HashToPoint.sol";

/// @title ZKNOX_epervier
/// @notice A contract to verify FALCON signatures with public key recovery
/// @dev The format of function is compacted, not compressed, for KATS verification look at dedicated ZKNOX_falconKATS.sol

/// @custom:experimental This library is not audited yet, do not use in production.
contract ZKNOX_epervier {
    function HashToAddress(bytes memory m) public pure returns (address) {
        return address(uint160(uint256(keccak256(m))));
    }

    /// @notice Compute the  falcon recover function

    /// @param msgs the message to be signed
    /// @param salt the message to be signed, expected length is 40 bytes
    /// @param cs1 first part of the signature in Compacted representation (see IO part of README for encodings specification), expected length is 32 uint256
    /// @param cs2 second part of the signature in Compacted representation (see IO part of README for encodings specification), expected length is 32 uint256
    /// @param hint hinted part of s2^_1 (see specification)
    /// @return result the address recovered

    function recover(bytes memory msgs, bytes memory salt, uint256[] memory cs1, uint256[] memory cs2, uint256 hint)
        public
        pure
        returns (address result)
    {
        if (salt.length != 40) revert("wrong salt length"); //CVETH-2025-080201: control salt length to avoid potential forge
        if (cs1.length != 32) revert("Invalid s1 length"); //"Invalid s1 length"
        if (cs2.length != 32) revert("Invalid s2 length"); //"Invalid s2 length"

        uint256[] memory s1 = _ZKNOX_NTT_Expand(cs1); //avoiding another memory declaration
        uint256[] memory s2 = _ZKNOX_NTT_Expand(cs2); //avoiding another memory declaration

        // (s1,s2) must be short
        uint256 norm = 0;
        // As (σ1,σ2) are given with positive values, small negative values are actually large (close to q).

        assembly {
            //normalization
            for { let offset := 32 } gt(16384, offset) { offset := add(offset, 32) } {
                let s1i := mload(add(s1, offset))

                let cond := gt(s1i, qs1) //s1[i] > qs1 ?
                s1i := add(mul(cond, sub(q, s1i)), mul(sub(1, cond), s1i))
                norm := add(norm, mul(s1i, s1i))

                let s2i := mload(add(s2, offset))
                let cond2 := gt(s2i, qs1) //s1[i] > qs1 ?
                s2i := add(mul(cond2, sub(q, s2i)), mul(sub(1, cond2), s2i))
                norm := add(norm, mul(s2i, s2i))
            }
        }

        if (norm > sigBound) {
            revert("norm too large");
        }

        s2 = _ZKNOX_NTTFW_vectorized(s2); //ntt(s2)

        // recover s2.ntt().inverse() from the hint
        uint256[] memory prefix = new uint256[](512);
        prefix[0] = s2[0];
        uint256[] memory s2_inverse_ntt = new uint256[](512);
        s2_inverse_ntt[511] = hint;

        assembly {
            let temp := mload(add(prefix, 32)) //prefix[i-1]

            for { let offset := 64 } gt(16416, offset) { offset := add(offset, 32) } {
                // for (i = 1; i < 512; i++)
                temp := mulmod(temp, mload(add(s2, offset)), q)
                mstore(add(offset, prefix), temp) //prefix[i] = mulmod(prefix[i - 1], s2[i], q);
            }
        }

        assembly {
            for { let offset := 32 } gt(16384, offset) { offset := add(offset, 32) } {
                let temp :=
                    mulmod(mload(add(s2_inverse_ntt, sub(16416, offset))), mload(add(s2, sub(16416, offset))), q)
                mstore(add(s2_inverse_ntt, sub(16384, offset)), temp)
            }
        }

        assembly {
            for { let offset := 64 } gt(16416, offset) { offset := add(offset, 32) } {
                let a_temp := add(s2_inverse_ntt, offset) //address of s2_inverse_ntt[i]
                let temp := mulmod(mload(add(prefix, sub(offset, 32))), mload(a_temp), q) //mulmod(s2_inverse_ntt[i], prefix[i - 1], q)
                mstore(a_temp, temp) //s2_inverse_ntt[i] = mulmod(s2_inverse_ntt[i], prefix[i - 1], q);
            }
        }

        //ntt(s2)*ntt(s2^-1)==ntt(1)?
        norm = 0; //accumulate the boolean   of testing condition
        uint256[] memory hashed = hashToPointNIST(salt, msgs);

        assembly {
            for { let offset := 32 } gt(16416, offset) { offset := add(offset, 32) } {
                norm := add(norm, sub(1, mulmod(mload(add(offset, s2)), mload(add(offset, s2_inverse_ntt)), q)))
                let a_hashedi := add(hashed, offset)
                mstore(a_hashedi, addmod(mload(a_hashedi), sub(q, mload(add(s1, offset))), q))
            }
        }

        if (norm != 0) revert("wrong hint");

        uint256[] memory hashed_mul_s2_ntt = _ZKNOX_VECMULMOD(_ZKNOX_NTTFW_vectorized(hashed), s2_inverse_ntt);
        return HashToAddress(abi.encodePacked(hashed_mul_s2_ntt));
    }
} //end of contract

/* the contract shall be initialized with a valid precomputation of psi_rev and psi_invrev contracts provided to the input ntt contract*/
