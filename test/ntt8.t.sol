// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_NTT_falcon.sol";
import "../src/ZKNOX_NTT_falcon_packed.sol";
import "../src/ZKNOX_NTT_falcon8.sol";

/// Differential test of the eight-lane Montgomery chain s1 = INTT(NTT(s2) o h)
/// against the four-lane packed transforms (themselves asserted against the
/// scalar reference in test/ntt_packed.t.sol).
contract Ntt8Test is Test {
    function _compact(uint256 seed) internal pure returns (uint256[] memory c) {
        c = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            uint256 w;
            for (uint256 j = 0; j < 16; j++) {
                w |= (uint256(keccak256(abi.encodePacked(seed, i, j))) % q) << (16 * j);
            }
            c[i] = w;
        }
    }

    function _saturated() internal pure returns (uint256[] memory c) {
        c = new uint256[](32);
        uint256 w;
        for (uint256 j = 0; j < 16; j++) {
            w |= (q - 1) << (16 * j);
        }
        for (uint256 i = 0; i < 32; i++) {
            c[i] = w;
        }
    }

    function _check(uint256[] memory s2, uint256[] memory h) internal pure {
        uint256[] memory expected =
            _unpackTo512(_nttInvPacked(_vecMulPacked(_nttFwPacked(_packFromCompact(s2)), _packFromCompact(h))));
        uint256[] memory got = falconProduct8(s2, h);
        require(got.length == 64, "length");
        for (uint256 i = 0; i < 512; i++) {
            uint256 lane = 43011 - ((got[i >> 3] >> (32 * (i & 7))) & 0xffffffff);
            require(lane < 3 * q, "lane not below 3q");
            require(lane % q == expected[i], "product differs");
        }
    }

    function test_product8_matches_packed() public pure {
        for (uint256 s = 0; s < 6; s++) {
            _check(_compact(s), _compact(1000 + s));
        }
        _check(_saturated(), _saturated());
        _check(_saturated(), _compact(3));
        _check(_compact(4), _saturated());
        _check(new uint256[](32), _compact(5));
    }

    function testFuzz_product8_matches_packed(uint256 seed) public pure {
        _check(_compact(seed), _compact(uint256(keccak256(abi.encodePacked(seed)))));
    }

    /// keys with fields >= q (the verifier does not range-check ntth): same as the reference mod q
    function test_product8_key_out_of_range() public pure {
        uint256[] memory h = _compact(9);
        h[3] |= uint256(0xffff) << 48;
        h[20] = h[20] | (uint256(q) << 16);
        _check(_compact(8), h);
    }

    function test_gas_product8() public view {
        uint256[] memory a = _compact(7);
        uint256[] memory b = _compact(1007);
        uint256 g = gasleft();
        falconProduct8(a, b);
        console.log("falconProduct8 (fw + pointwise + inv, 8 lanes):", g - gasleft());
    }
}
