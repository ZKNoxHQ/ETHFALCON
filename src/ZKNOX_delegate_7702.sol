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
///* FILE: ZKNOX_delegate_noproxy.sol
///* Description: A contract designed to be delegated to a 7702 authorization wihtout proxy
/**
 *
 */
pragma solidity ^0.8.25;

import "./ZKNOX_common.sol";
import "./ZKNOX_IVerifier.sol";

/// @notice Contract designed for being delegated to by EOAs to authorize a IVerifier key to transact on their behalf.
contract ZKNOX_Verifier {
    /// @notice Address of the contract storing the public key
    address public authorizedPublicKey;
    /// @notice Address of the verification contract logic

    address public CoreAddress; //adress of the core verifier (FALCON, DILITHIUM, etc.), shall be the adress of a ISigVerifier
    uint256 public algoID;

    /// @notice Internal nonce used for replay protection, must be tracked and included into prehashed message.
    uint256 public nonce;

    constructor() {}

    //input are AlgoIdentifier, Signature verification address, publickey storing contract
    function initialize(uint256 iAlgoID, address iCore, address iPublicKey) external {
        require(CoreAddress == address(0), "already initialized");
        CoreAddress = iCore; // Address of contract of Signature verification (FALCON, DILITHIUM)
        algoID = iAlgoID;
        authorizedPublicKey = iPublicKey;
        nonce = 0;
    }

    /// @notice Main entrypoint for authorized transactions. Accepts transaction parameters (to, data, value) and a musig2 signature.
    function transact(
        address to,
        bytes memory data,
        uint256 val,
        bytes memory salt, // compacted signature salt part
        uint256[] memory s2 // compacted signature s2 part)
    )
        external
        payable
    {
        bytes32 digest = keccak256(abi.encode(nonce++, to, data, val));
        ISigVerifier Core = ISigVerifier(CoreAddress);

        uint256[] memory nttpk;
        require(authorizedPublicKey != address(0), "authorizedPublicKey null");

        nttpk = Core.GetPublicKey(authorizedPublicKey);
        require(nttpk[0] != 0, "wrong extraction");
        require(Core.verify(abi.encodePacked(digest), salt, s2, nttpk), "Invalid signature");

        (bool success,) = to.call{value: val}(data);

        require(success, "failing executing the cal");
    }

    //debug function for now: todo, remove when transact successfully tested
    function isValid(
        bytes memory data,
        bytes memory salt, // compacted signature salt part
        uint256[] memory s2
    )
        external
        payable
        returns (bool)
    {
        ISigVerifier Core = ISigVerifier(CoreAddress);
        uint256[] memory nttpk;
        nttpk = Core.GetPublicKey(authorizedPublicKey);
        return Core.verify(data, salt, s2, nttpk);
    }

    function GetPublicKey() public view returns (uint256[] memory res) {
        ISigVerifier Core = ISigVerifier(CoreAddress);
        res = Core.GetPublicKey(authorizedPublicKey);
    }

    function GetStorage() public view returns (address, address) {
        return (CoreAddress, authorizedPublicKey);
    }
    //receive() external payable {}
}
