// SPDX-License-Identifier: MIT
// FILE: ZKNOX_falcon_fused.sol
// ZKNOX_falcon_turbo with the fused radix-8 NTT core and the Yul hash-to-point
// sampler. Same external interface, same helper binding rules, same
// accept/reject decision (asserted against ZKNOX_falcon / falcon_core).
pragma solidity ^0.8.25;

import "./ZKNOX_common.sol";
import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_falcon_core_fused.sol";
import "./ZKNOX_HashToPoint_packed.sol";

contract ZKNOX_falcon_fused {
    /// @notice keccak256 of the expected helper RUNTIME (helpers/f1600_170.hex,
    ///         21,622 bytes, fireblocks-labs/evm-ml-dsa-verifier @ cca262b).
    /// @dev    See ZKNOX_falcon_turbo: the binding is by code hash, not address,
    ///         so that what SHAKE256 means here is fixed by this source.
    bytes32 internal constant F1600_CODEHASH = 0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b;

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

        uint256[] memory hashedPacked = hashToPointNISTPacked(salt, h, f1600Helper);

        result = falcon_core_fused(s2, ntth, hashedPacked);
        return result;
    }
}
