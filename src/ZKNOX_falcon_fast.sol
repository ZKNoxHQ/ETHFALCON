// SPDX-License-Identifier: MIT
// FILE: ZKNOX_falcon_fast.sol
// ZKNOX_falcon with hashToPointNIST swapped for hashToPointNISTFast.
// Everything else (falcon_core, the parameter checks, the encodings) is
// unchanged, so the gas delta against ZKNOX_falcon is the SHAKE delta.
pragma solidity ^0.8.25;

import "./ZKNOX_common.sol";
import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_falcon_core.sol";
import "./ZKNOX_shake_fast.sol";

contract ZKNOX_falcon_fast {
    /// @notice keccak256 of the expected helper RUNTIME (helpers/f1600_170.hex,
    ///         21,622 bytes, fireblocks-labs/evm-ml-dsa-verifier @ cca262b).
    /// @dev    The verifier delegates Keccak-f[1600] to an external contract, so
    ///         what it accepts depends on that contract's code. Binding by
    ///         ADDRESS alone would put the choice of what SHAKE256 *means* in the
    ///         hands of whoever deploys this verifier: a helper returning
    ///         attacker-chosen state makes hashToPointNIST return an
    ///         attacker-chosen point, which forges under any public key. Pinning
    ///         the code hash makes the binding readable from this source and
    ///         independent of the deployer, and makes the helper fungible: any
    ///         address holding this exact runtime works.
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
    ) external view returns (bool result) {
        // Re-assert the binding by CONTENT, not by address. Cheap: EXTCODEHASH
        // is the first touch of the helper account, so it absorbs the 2,600 gas
        // cold-account charge the first STATICCALL would otherwise pay.
        if (f1600Helper.codehash != F1600_CODEHASH) revert BadHelper();

        if (salt.length != 40) revert("invalid salt length");
        if (s2.length != falcon_S256) revert("invalid s2 length");
        if (ntth.length != falcon_S256) revert("invalid ntth length");

        uint256[] memory hashed = hashToPointNISTFast(salt, h, f1600Helper);

        result = falcon_core(s2, ntth, hashed);
        return result;
    }
}
