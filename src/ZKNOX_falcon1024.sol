// SPDX-License-Identifier: MIT
// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_falcon1024.sol
// Falcon-1024 verifier (NIST round 3 conventions: SHAKE256(salt || message),
// 40-byte salt, beta^2 = 70265242) on the eight-lane chain, same helper binding
// as ZKNOX_falcon8.
pragma solidity ^0.8.25;

import "./ZKNOX_falcon1024_core.sol";

contract ZKNOX_falcon1024 {
    /// @dev our Keccak-f[1600] helper (test/f1600_zknox.hex), the one ZKNOX_falcon8 binds
    bytes32 internal constant F1600_CODEHASH = 0x661c9f13236c0174873874530946d802d0ac54373091f0bdea36ab2e3f409155;

    function F1600_CODEHASH_PUBLIC() external pure returns (bytes32) {
        return F1600_CODEHASH;
    }

    /// @notice the bound Keccak-f[1600] helper
    address public immutable f1600Helper;

    error BadHelper();

    constructor(address helper) {
        if (helper.codehash != F1600_CODEHASH) revert BadHelper();
        f1600Helper = helper;
    }

    function verify(
        bytes memory h, // the signed message (hash-to-point input after the salt)
        bytes memory salt, // 40-byte signature salt
        uint256[] memory s2, // compacted s2 mod q, 64 words of sixteen 16-bit coefficients
        uint256[] memory ntth // public key in NTT domain, compacted, 64 words
    )
        external
        view
        returns (bool result)
    {
        // Re-assert the binding by CONTENT, not by address (absorbs the cold-account charge).
        if (f1600Helper.codehash != F1600_CODEHASH) revert BadHelper();

        if (salt.length != 40) revert("invalid salt length");
        if (s2.length != falcon1024_S256) revert("invalid s2 length");
        if (ntth.length != falcon1024_S256) revert("invalid ntth length");

        result = falcon1024_core(salt, h, f1600Helper, s2, ntth);
    }
}
