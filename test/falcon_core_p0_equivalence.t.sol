// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon_utils.sol";
import "../src/ZKNOX_NTT_falcon.sol";
import "../src/ZKNOX_falcon_core.sol";

/// @notice Differential tests for the Falcon-core dataflow optimization.
contract FalconCoreP0EquivalenceTest is Test {
    function _randomCompactPolynomial(uint256 seed, uint256 domain) internal pure returns (uint256[] memory packed) {
        packed = new uint256[](32);
        for (uint256 i = 0; i < 512; ++i) {
            uint256 coefficient = uint256(keccak256(abi.encodePacked(seed, domain, i))) % q;
            packed[i >> 4] |= coefficient << ((i & 0xf) << 4);
        }
    }

    function _randomExpandedPolynomial(uint256 seed) internal pure returns (uint256[] memory expanded) {
        expanded = new uint256[](512);
        for (uint256 i = 0; i < 512; ++i) {
            expanded[i] = uint256(keccak256(abi.encodePacked(seed, i))) % q;
        }
    }

    function testFuzz_P0DataflowMatchesLegacyCore(uint256 seed) public pure {
        uint256[] memory s2 = _randomCompactPolynomial(seed, 0);
        uint256[] memory ntth = _randomCompactPolynomial(seed, 1);
        uint256[] memory hashed = _randomExpandedPolynomial(seed);

        uint256[] memory legacyS1 = _ZKNOX_NTT_Expand(_ZKNOX_NTT_HALFMUL_Compact(s2, ntth));

        uint256[] memory optimizedS1 = _ZKNOX_NTTFW_vectorized(_ZKNOX_NTT_Expand(s2));
        _ZKNOX_VECMULMOD_ExpandedByCompactInPlace(optimizedS1, ntth);
        optimizedS1 = _ZKNOX_NTTINV_vectorized(optimizedS1);

        for (uint256 i = 0; i < 512; ++i) {
            assertEq(optimizedS1[i], legacyS1[i], "P0 must preserve every inverse-NTT coefficient");
        }

        bool legacyResult = falcon_normalize(legacyS1, s2, hashed);
        assertEq(falcon_core(s2, ntth, hashed), legacyResult, "P0 must preserve Falcon acceptance");
    }

    function testCoreRejectsWrongNttLength() public pure {
        uint256[] memory s2 = new uint256[](32);
        uint256[] memory ntth = new uint256[](31);
        uint256[] memory hashed = new uint256[](512);

        assertFalse(falcon_core(s2, ntth, hashed), "a short packed NTT key must be rejected before assembly reads");
    }
}
