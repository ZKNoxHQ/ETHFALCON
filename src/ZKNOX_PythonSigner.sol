// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";

contract PythonSigner is Test {
    function bytesToString(bytes memory data) internal pure returns (string memory) {
        return string(data);
    }

    // reusable Python sign function
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
