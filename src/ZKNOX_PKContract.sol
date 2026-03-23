// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_PKContract.sol
// Description: Falcon Public Key stored in NTT domain using SSTORE2.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {SSTORE2} from "sstore2/SSTORE2.sol";

/// @title PKContract - Falcon Public Key Storage
/// @notice Stores a Falcon-512 NTT-domain public key using SSTORE2 for gas-efficient on-chain storage
contract PKContract {
    /// @notice Pointer to contract storing the NTT public key as bytecode
    address private immutable ntthPointer;

    /// @notice Constructor stores the public key using SSTORE2
    /// @param _ntthEncoded ABI-encoded uint256[] (32 elements, NTT domain)
    constructor(bytes memory _ntthEncoded) {
        ntthPointer = SSTORE2.write(_ntthEncoded);
    }

    /// @notice Returns the Falcon NTT-domain public key
    /// @return ntth uint256[] of 32 elements
    function getPublicKey() external view returns (uint256[] memory ntth) {
        bytes memory data = SSTORE2.read(ntthPointer);
        ntth = abi.decode(data, (uint256[]));
    }
}

/// @notice Interface for Falcon PK contracts
interface IPKContract {
    function getPublicKey() external view returns (uint256[] memory);
}
