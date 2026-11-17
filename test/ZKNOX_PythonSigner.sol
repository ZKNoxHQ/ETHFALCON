// Copyright (C) 2026 - ZKNOX
// License: This software is licensed under MIT License
// This Code may be reused including this header, license and copyright notice.
// FILE: ZKNOX_PythonSigner.sol
// Description: Test interface for signing messages using external Python Falcon implementation
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";

/// @title PythonSigner
/// @notice Test contract for generating Falcon signatures using an external Python implementation
/// @dev Uses Foundry's FFI (Foreign Function Interface) to call Python signing script
/// @dev NOT FOR PRODUCTION USE - testing and development only
contract PythonSigner is Test {
    /// @notice Converts bytes to string
    /// @dev Simple type cast helper function
    /// @param data Bytes to convert
    /// @return String representation of the bytes
    function bytesToString(bytes memory data) internal pure returns (string memory) {
        return string(data);
    }

    /// @notice Generates a Falcon signature by calling external Python implementation
    /// @dev Calls sig_sol.py script in specified repository using Foundry's vm.ffi
    /// @dev The Python script must be properly configured and accept these exact parameters
    /// @param python_repo_path Path to Python repository containing sig_sol.py and myenv/
    /// @param data Message data to sign
    /// @param mode Signing mode parameter passed to Python script
    /// @param seedStr Seed string for deterministic signature generation
    /// @return pubkey Public key in compacted format (32 uint256 words)
    /// @return salt 40-byte salt value
    /// @return s2_compact Second signature component in compacted format (32 uint256 words)
    function sign(string memory python_repo_path, string memory data, string memory mode, string memory seedStr)
        external
        returns (uint256[32] memory pubkey, bytes memory salt, uint256[32] memory s2_compact)
    {
        string[] memory cmds = new string[](5);
        cmds[0] = string(abi.encodePacked(python_repo_path, "/myenv/bin/python"));
        cmds[1] = string(abi.encodePacked(python_repo_path, "/sig_sol.py"));
        cmds[2] = data;
        cmds[3] = mode;
        cmds[4] = seedStr;
        bytes memory result = vm.ffi(cmds);
        (pubkey, salt, s2_compact) = abi.decode(result, (uint256[32], bytes, uint256[32]));
    }
}
