// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_NTT_falcon.sol";
import "../src/ZKNOX_NTT_falcon_packed.sol";
import "../src/ZKNOX_falcon_core_packed.sol";

contract NttPackedTest is Test {
    function _compact(uint256 seed) internal pure returns (uint256[] memory c) {
        c = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            uint256 w;
            for (uint256 j = 0; j < 16; j++) {
                uint256 coeff = uint256(keccak256(abi.encodePacked(seed, i, j))) % q;
                w |= coeff << (16 * j);
            }
            c[i] = w;
        }
    }

    function _diff(uint256 seed) internal pure {
        uint256[] memory c = _compact(seed);
        uint256[] memory refIn = _ZKNOX_NTT_Expand(c);
        uint256[] memory expected = _ZKNOX_NTTFW_vectorized(refIn);
        uint256[] memory got = _unpackTo512(_nttFwPacked(_packFromCompact(c)));
        for (uint256 i = 0; i < 512; i++) {
            require(got[i] == expected[i], "packed NTT differs from the reference");
        }
    }

    function test_packed_matches_reference() public pure {
        for (uint256 s = 0; s < 8; s++) _diff(s);
    }

    function testFuzz_packed_matches_reference(uint256 seed) public pure {
        _diff(seed);
    }

    /// worst case for growth: every coefficient at q-1
    function test_packed_matches_reference_saturated() public pure {
        uint256[] memory c = new uint256[](32);
        uint256 w;
        for (uint256 j = 0; j < 16; j++) w |= (q - 1) << (16 * j);
        for (uint256 i = 0; i < 32; i++) c[i] = w;
        uint256[] memory expected = _ZKNOX_NTTFW_vectorized(_ZKNOX_NTT_Expand(c));
        uint256[] memory got = _unpackTo512(_nttFwPacked(_packFromCompact(c)));
        for (uint256 i = 0; i < 512; i++) require(got[i] == expected[i], "saturated case differs");
    }

    /// full HALFMUL pipeline, packed, against _ZKNOX_NTT_HALFMUL_Compact
    function _diffHalfmul(uint256 seed) internal pure {
        uint256[] memory a = _compact(seed);
        uint256[] memory b = _compact(uint256(keccak256(abi.encodePacked(seed))));
        uint256[] memory expected = _ZKNOX_NTT_HALFMUL_Compact(a, b);
        uint256[] memory got = _compactFromPacked(
            _nttInvPacked(_vecMulPacked(_nttFwPacked(_packFromCompact(a)), _packFromCompact(b)))
        );
        for (uint256 i = 0; i < 32; i++) require(got[i] == expected[i], "packed HALFMUL differs");
    }

    function test_packed_halfmul_matches_reference() public pure {
        for (uint256 s = 0; s < 6; s++) _diffHalfmul(s);
    }

    function testFuzz_packed_halfmul_matches_reference(uint256 seed) public pure {
        _diffHalfmul(seed);
    }

    function test_gas_halfmul() public view {
        uint256[] memory a = _compact(7);
        uint256[] memory b = _compact(1007);
        uint256 g = gasleft();
        _ZKNOX_NTT_HALFMUL_Compact(a, b);
        uint256 gRef = g - gasleft();

        uint256[] memory a2 = _compact(7);
        uint256[] memory b2 = _compact(1007);
        g = gasleft();
        _compactFromPacked(
            _nttInvPacked(_vecMulPacked(_nttFwPacked(_packFromCompact(a2)), _packFromCompact(b2)))
        );
        uint256 gNew = g - gasleft();
        console.log("HALFMUL baseline              :", gRef);
        console.log("HALFMUL packed                :", gNew);
    }

    function _diffInv(uint256 seed) internal pure {
        uint256[] memory c = _compact(seed);
        uint256[] memory expected = _ZKNOX_NTTINV_vectorized(_ZKNOX_NTT_Expand(c));
        uint256[] memory got = _unpackTo512(_nttInvPacked(_packFromCompact(c)));
        for (uint256 i = 0; i < 512; i++) require(got[i] == expected[i], "packed NTTINV differs");
    }

    function test_packed_inverse_matches_reference() public pure {
        for (uint256 s = 0; s < 6; s++) _diffInv(s);
    }

    function testFuzz_packed_inverse_matches_reference(uint256 seed) public pure {
        _diffInv(seed);
    }

    function test_gas_inverse() public view {
        uint256[] memory c = _compact(3);
        uint256[] memory e = _ZKNOX_NTT_Expand(c);
        uint256 g = gasleft();
        _ZKNOX_NTTINV_vectorized(e);
        uint256 gRef = g - gasleft();

        uint256[] memory p = _packFromCompact(_compact(3));
        g = gasleft();
        _nttInvPacked(p);
        uint256 gNew = g - gasleft();
        console.log("NTTINV baseline               :", gRef);
        console.log("NTTINV packed                 :", gNew);
    }

    function _hashed(uint256 seed) internal pure returns (uint256[] memory h) {
        h = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) h[i] = uint256(keccak256(abi.encodePacked(seed, i))) % q;
    }

    function _diffCore(uint256 seed) internal pure {
        uint256[] memory s2 = _compact(seed);
        uint256[] memory pk = _compact(uint256(keccak256(abi.encodePacked(seed))));
        uint256[] memory h = _hashed(seed);
        require(falcon_core(s2, pk, h) == falcon_core_packed(s2, pk, h), "falcon_core_packed differs");
    }

    function test_packed_core_matches_reference() public pure {
        for (uint256 s = 0; s < 6; s++) _diffCore(s);
    }

    function testFuzz_packed_core_matches_reference(uint256 seed) public pure {
        _diffCore(seed);
    }

    function test_gas_core() public view {
        uint256[] memory s2 = _compact(11);
        uint256[] memory pk = _compact(22);
        uint256[] memory h = _hashed(33);
        uint256 g = gasleft();
        falcon_core(s2, pk, h);
        uint256 gRef = g - gasleft();
        g = gasleft();
        falcon_core_packed(s2, pk, h);
        uint256 gNew = g - gasleft();
        console.log("falcon_core baseline          :", gRef);
        console.log("falcon_core packed            :", gNew);
    }

    function test_gas() public view {
        uint256[] memory c = _compact(42);
        uint256 g;

        g = gasleft();
        uint256[] memory e = _ZKNOX_NTT_Expand(c);
        uint256 gExpand = g - gasleft();
        g = gasleft();
        _ZKNOX_NTTFW_vectorized(e);
        uint256 gRef = g - gasleft();

        uint256[] memory c2 = _compact(42);
        g = gasleft();
        uint256[] memory p = _packFromCompact(c2);
        uint256 gPack = g - gasleft();
        g = gasleft();
        _nttFwPacked(p);
        uint256 gNew = g - gasleft();

        console.log("baseline  Expand(32->512)     :", gExpand);
        console.log("baseline  NTTFW               :", gRef);
        console.log("baseline  total from compact  :", gExpand + gRef);
        console.log("packed    packFromCompact     :", gPack);
        console.log("packed    nttFwPacked         :", gNew);
        console.log("packed    total from compact  :", gPack + gNew);
    }
}
