// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_NTT_falcon.sol";
import "../src/ZKNOX_falcon_core.sol";

contract ProfileCore is Test {
    uint256[] pkc;
    uint256[] s2;
    uint256[] hashed;

    function setUp() public {
        pkc = new uint256[](32);
        s2 = new uint256[](32);
        hashed = new uint256[](512);
        for (uint256 i = 0; i < 32; i++) {
            pkc[i] = uint256(keccak256(abi.encodePacked("pk", i)));
            s2[i] = uint256(keccak256(abi.encodePacked("s2", i))) % (1 << 200);
        }
        for (uint256 i = 0; i < 512; i++) hashed[i] = i % q;
    }

    function test_profile_core() public view {
        uint256 g;
        // pull storage into memory FIRST: an implicit storage->memory copy of a
        // 512-word array is 512 SLOADs and would swamp every figure below.
        uint256[] memory mh = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) mh[i] = hashed[i];
        uint256[] memory ms2 = new uint256[](32);
        uint256[] memory mpk = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) { ms2[i] = s2[i]; mpk[i] = pkc[i]; }

        g = gasleft();
        uint256[] memory ea = _ZKNOX_NTT_Expand(ms2);
        console.log("Expand (32 -> 512 words)      :", g - gasleft());

        g = gasleft();
        uint256[] memory fa = _ZKNOX_NTTFW_vectorized(ea);
        console.log("NTTFW (512, warm mem)         :", g - gasleft());

        uint256[] memory eb = _ZKNOX_NTT_Expand(mpk);
        g = gasleft();
        uint256[] memory pr = _ZKNOX_VECMULMOD(fa, eb);
        console.log("VECMULMOD (512 pointwise)     :", g - gasleft());

        g = gasleft();
        uint256[] memory iv = _ZKNOX_NTTINV_vectorized(pr);
        console.log("NTTINV (512)                  :", g - gasleft());

        g = gasleft();
        uint256[] memory cp = _ZKNOX_NTT_Compact(iv);
        console.log("Compact (512 -> 32 words)     :", g - gasleft());

        g = gasleft();
        uint256[] memory s1 = _ZKNOX_NTT_Expand(cp);
        console.log("Expand again (32 -> 512)      :", g - gasleft());

        g = gasleft();
        bool ok = falcon_normalize(s1, ms2, mh);
        console.log("falcon_normalize              :", g - gasleft());
        ok;

        g = gasleft();
        falcon_core(ms2, mpk, mh);
        console.log("falcon_core (end to end)      :", g - gasleft());
    }

    /// falcon_core does Compact(...) then Expand(...) back to back on the same
    /// data. Compact/Expand are exact inverses for coefficients < 2^16, which
    /// NTTINV output always is, so the pair is a no-op that costs real gas.
    function test_compact_expand_roundtrip_is_dead_weight() public view {
        uint256[] memory ms2 = new uint256[](32);
        uint256[] memory mpk = new uint256[](32);
        uint256[] memory mh = new uint256[](512);
        for (uint256 i = 0; i < 32; i++) { ms2[i] = s2[i]; mpk[i] = pkc[i]; }
        for (uint256 i = 0; i < 512; i++) mh[i] = hashed[i];

        // what falcon_core does today
        uint256 g = gasleft();
        uint256[] memory viaRoundtrip =
            _ZKNOX_NTT_Expand(_ZKNOX_NTT_Compact(
                _ZKNOX_NTTINV_vectorized(
                    _ZKNOX_VECMULMOD(_ZKNOX_NTTFW_vectorized(_ZKNOX_NTT_Expand(ms2)), _ZKNOX_NTT_Expand(mpk))
                )
            ));
        console.log("s1 with Compact->Expand       :", g - gasleft());

        // the same thing without the round trip
        g = gasleft();
        uint256[] memory direct =
            _ZKNOX_NTTINV_vectorized(
                _ZKNOX_VECMULMOD(_ZKNOX_NTTFW_vectorized(_ZKNOX_NTT_Expand(ms2)), _ZKNOX_NTT_Expand(mpk))
            );
        console.log("s1 without the round trip     :", g - gasleft());

        for (uint256 i = 0; i < 512; i++) {
            assertEq(viaRoundtrip[i], direct[i], "round trip is not the identity");
        }
    }

    /// what a single 512-coefficient pass costs, by reduction style
    function test_reduction_styles() public view {
        uint256 g;
        uint256 acc;

        g = gasleft();
        assembly {
            for { let i := 0 } lt(i, 512) { i := add(i, 1) } { acc := mulmod(acc, 12289, q) }
        }
        console.log("512x MULMOD                   :", g - gasleft());

        g = gasleft();
        assembly {
            for { let i := 0 } lt(i, 512) { i := add(i, 1) } { acc := mul(acc, 12289) }
        }
        console.log("512x plain MUL                :", g - gasleft());

        // one packed word = 16 coefficients of 16 bits; 32 words = 512 coeffs
        g = gasleft();
        assembly {
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } { acc := mul(acc, 12289) }
        }
        console.log("32x MUL (= 512 coeffs packed) :", g - gasleft());
    }
}
