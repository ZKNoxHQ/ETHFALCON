// SPDX-License-Identifier: MIT
// FILE: ZKNOX_falcon8.sol
// ZKNOX_falcon_fused on the eight-lane Montgomery chain with the norm folded
// into hash-to-point. Same external interface, same helper binding rules,
// same accept/reject decision (asserted against ZKNOX_falcon / falcon_core).
pragma solidity ^0.8.25;

import "./ZKNOX_common.sol";
import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_falcon_core8.sol";

contract ZKNOX_falcon8 {
    /// @notice keccak256 of the expected helper RUNTIME (helpers/f1600_170.hex,
    ///         21,622 bytes, fireblocks-labs/evm-ml-dsa-verifier @ cca262b).
    /// @dev    See ZKNOX_falcon_turbo: the binding is by code hash, not address,
    ///         so that what SHAKE256 means here is fixed by this source.
    /// @dev our Keccak-f[1600] helper (test/f1600_zknox.hex, 19,515 bytes, generated
    ///      by pythonref/gen_keccak_helper.py): 832 bytes = ignored prefix word + 25
    ///      replicated lanes in, 25 replicated lanes out; 800 bytes = 25 clean lanes
    ///      in and out
    bytes32 internal constant F1600_CODEHASH = 0xdc6a16b17b7f87655cecf5c8cb5c3357c35ce17b25f9050c185ee5862c237442;

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
        bytes memory h, // a 32 bytes hash
        bytes memory salt, // compacted signature salt part
        uint256[] memory s2, // compacted signature s2 part
        uint256[] memory ntth // public key, compacted, 16 coefficients of 16 bits per word
    )
        external
        view
        returns (bool result)
    {
        // Re-assert the binding by CONTENT, not by address (absorbs the cold-account charge).
        if (f1600Helper.codehash != F1600_CODEHASH) revert BadHelper();

        if (salt.length != 40) revert("invalid salt length");
        if (s2.length != falcon_S256) revert("invalid s2 length");
        if (ntth.length != falcon_S256) revert("invalid ntth length");

        result = falcon_core8(salt, h, f1600Helper, s2, ntth);
        return result;
    }
}
