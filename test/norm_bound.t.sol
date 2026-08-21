// SPDX-License-Identifier: MIT
// Regression test: the norm bound must be inclusive (accept ||s1||^2 + ||s2||^2 == sigBound),
// matching the reference implementation (pythonref/falcon.py rejects only norm > sig_bound).
// Before the fix, falcon_normalize used a strict comparison and rejected the boundary case,
// so a reference-valid signature with squared norm exactly 34034726 failed on-chain.
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon_utils.sol";
import "../src/ZKNOX_falcon_core.sol";

contract NormBoundTest is Test {
    // Build synthetic inputs: s1 = 0 and s2 = 0, so the norm is fully determined by
    // hashed (each coefficient contributes centered(hashed_i)^2).
    function _inputs() internal pure returns (uint256[] memory s1, uint256[] memory s2, uint256[] memory hashed) {
        s1 = new uint256[](512);
        s2 = new uint256[](32);
        hashed = new uint256[](512);
        // 5833^2 + 104^2 + 4^2 + 2^2 + 1^2 = 34034726 = sigBound (all values <= qs1, so centered = identity)
        hashed[0] = 5833;
        hashed[1] = 104;
        hashed[2] = 4;
        hashed[3] = 2;
        hashed[4] = 1;
    }

    function testNormExactlyAtBoundAccepted() public pure {
        (uint256[] memory s1, uint256[] memory s2, uint256[] memory hashed) = _inputs();
        assertTrue(falcon_normalize(s1, s2, hashed), "norm == sigBound must be accepted (reference parity)");
    }

    function testNormJustAboveBoundRejected() public pure {
        (uint256[] memory s1, uint256[] memory s2, uint256[] memory hashed) = _inputs();
        hashed[5] = 1; // norm = sigBound + 1
        assertFalse(falcon_normalize(s1, s2, hashed), "norm == sigBound + 1 must be rejected");
    }
}
