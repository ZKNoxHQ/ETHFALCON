// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon1024.sol";
import "../src/ZKNOX_falcon1024_core.sol";
import "../src/ZKNOX_NTT_falcon1024.sol";

/// Falcon-1024 verifier: the fused product against the standalone transforms
/// (themselves checked against noble, test/ntt1024.t.sol), the exact squared norm
/// against pythonref/gen_falcon1024_vectors.py, the 100 NIST round-3 KAT vectors
/// (also re-verified by noble in jsref/check_falcon1024_kat.mjs), tampering,
/// range and length checks, helper binding.
contract Falcon1024Test is Test {
    uint256 constant Q = 12289;
    ZKNOX_falcon1024 falcon1024;
    address helper;
    string json;

    function _deploy(string memory path) internal returns (address h) {
        string[] memory cmds = new string[](2);
        cmds[0] = "cat";
        cmds[1] = path;
        bytes memory runtime = vm.ffi(cmds);
        bytes memory initCode = abi.encodePacked(hex"61", uint16(runtime.length), hex"8061000b5f395ff3", runtime);
        assembly {
            h := create(0, add(initCode, 32), mload(initCode))
        }
        require(h != address(0), "CREATE failed");
    }

    function setUp() public {
        helper = _deploy("test/f1600_zknox.hex");
        falcon1024 = new ZKNOX_falcon1024(helper);
        json = vm.readFile("test/falcon1024_vectors.json");
    }

    struct Vec {
        bytes msg;
        bytes salt;
        uint256[] s2;
        uint256[] ntth;
        uint256 norm;
    }

    function _vec(string memory kind, uint256 k) internal view returns (Vec memory v) {
        string memory p = string.concat(".", kind, "[", vm.toString(k), "]");
        v.msg = vm.parseJsonBytes(json, string.concat(p, ".msg"));
        v.salt = vm.parseJsonBytes(json, string.concat(p, ".salt"));
        v.s2 = vm.parseJsonUintArray(json, string.concat(p, ".s2"));
        v.ntth = vm.parseJsonUintArray(json, string.concat(p, ".ntth"));
        v.norm = vm.parseJsonUint(json, string.concat(p, ".norm"));
    }

    function _random(uint256 seed, uint256 mask) internal pure returns (uint256[] memory c) {
        c = new uint256[](64);
        for (uint256 i = 0; i < 64; i++) {
            uint256 w;
            for (uint256 j = 0; j < 16; j++) {
                uint256 r = uint256(keccak256(abi.encodePacked(seed, i, j)));
                w |= (mask == 0xffff ? r & 0xffff : r % Q) << (16 * j);
            }
            c[i] = w;
        }
    }

    // ---- product ---------------------------------------------------------------

    function _checkProduct(uint256[] memory s2, uint256[] memory h) internal pure {
        uint256[] memory n = falconNTT1024(s2);
        uint256[] memory hq = new uint256[](64);
        for (uint256 i = 0; i < 1024; i++) {
            uint256 a = (n[i >> 4] >> (16 * (i & 15))) & 0xffff;
            uint256 b = ((h[i >> 4] >> (16 * (i & 15))) & 0xffff) % Q;
            hq[i >> 4] |= mulmod(a, b, Q) << (16 * (i & 15));
        }
        uint256[] memory expected = falconINTT1024(hq);
        uint256[] memory got = falconProduct1024(s2, h);
        require(got.length == 128, "length");
        for (uint256 i = 0; i < 1024; i++) {
            uint256 x = 3 * Q + 6144 - ((got[i >> 3] >> (32 * (i & 7))) & 0xffffffff);
            require(x < 3 * Q, "lane not below 3q");
            require(x % Q == (expected[i >> 4] >> (16 * (i & 15))) & 0xffff, "product differs");
        }
    }

    function test_product1024_matches_transforms() public pure {
        for (uint256 s = 0; s < 4; s++) {
            _checkProduct(_random(s, 0), _random(1000 + s, 0));
        }
        uint256[] memory sat = new uint256[](64);
        uint256[] memory ff = new uint256[](64);
        for (uint256 i = 0; i < 64; i++) {
            sat[i] = 0x3000300030003000300030003000300030003000300030003000300030003000;
            ff[i] = type(uint256).max >> 128 << 128 | type(uint128).max;
        }
        _checkProduct(sat, sat);
        _checkProduct(sat, ff); // key fields 0xffff, above q
        _checkProduct(_random(9, 0), _random(10, 0xffff));
        _checkProduct(new uint256[](64), _random(11, 0));
    }

    function testFuzz_product1024(uint256 seed) public pure {
        _checkProduct(_random(seed, 0), _random(uint256(keccak256(abi.encode(seed))), 0xffff));
    }

    // ---- norm ------------------------------------------------------------------

    function test_norm1024_random_matches_model() public view {
        for (uint256 k = 0; k < 12; k++) {
            Vec memory v = _vec("random", k);
            assertEq(falcon1024_norm(v.salt, v.msg, helper, v.s2, v.ntth), v.norm, vm.toString(k));
        }
    }

    // ---- KAT -------------------------------------------------------------------

    function test_verify1024_all_nist_kat() public view {
        for (uint256 k = 0; k < 100; k++) {
            Vec memory v = _vec("kat", k);
            assertEq(falcon1024_norm(v.salt, v.msg, helper, v.s2, v.ntth), v.norm, "norm");
            assertTrue(falcon1024.verify(v.msg, v.salt, v.s2, v.ntth), vm.toString(k));
        }
    }

    function test_verify1024_tampered() public view {
        Vec memory v = _vec("kat", 7);
        assertTrue(falcon1024.verify(v.msg, v.salt, v.s2, v.ntth));
        bytes memory m2 = abi.encodePacked(v.msg);
        m2[0] ^= 0x01;
        assertFalse(falcon1024.verify(m2, v.salt, v.s2, v.ntth));
        bytes memory salt2 = abi.encodePacked(v.salt);
        salt2[39] ^= 0x01;
        assertFalse(falcon1024.verify(v.msg, salt2, v.s2, v.ntth));
        uint256[] memory s2b = new uint256[](64);
        for (uint256 i = 0; i < 64; i++) {
            s2b[i] = v.s2[i];
        }
        s2b[40] ^= 1 << 80;
        assertFalse(falcon1024.verify(v.msg, v.salt, s2b, v.ntth));
        uint256[] memory hb = new uint256[](64);
        for (uint256 i = 0; i < 64; i++) {
            hb[i] = v.ntth[i];
        }
        hb[63] ^= 1 << 240;
        assertFalse(falcon1024.verify(v.msg, v.salt, v.s2, hb));
        // another key's valid signature
        Vec memory w = _vec("kat", 8);
        assertFalse(falcon1024.verify(v.msg, v.salt, v.s2, w.ntth));
    }

    /// s2 fields >= q are rejected, even when congruent to a valid signature
    function test_verify1024_s2_out_of_range() public view {
        Vec memory v = _vec("kat", 3);
        uint256[] memory s2b = new uint256[](64);
        for (uint256 i = 0; i < 64; i++) {
            s2b[i] = v.s2[i];
        }
        uint256 f = (s2b[5] >> 32) & 0xffff;
        require(f + Q <= 0xffff, "pick another field");
        s2b[5] = (s2b[5] & ~(uint256(0xffff) << 32)) | ((f + Q) << 32);
        assertFalse(falcon1024.verify(v.msg, v.salt, s2b, v.ntth));
        assertEq(falcon1024_norm(v.salt, v.msg, helper, s2b, v.ntth), type(uint256).max);
    }

    function test_verify1024_length_checks() public {
        Vec memory v = _vec("kat", 0);
        vm.expectRevert(bytes("invalid salt length"));
        falcon1024.verify(v.msg, abi.encodePacked(v.salt, bytes1(0)), v.s2, v.ntth);
        vm.expectRevert(bytes("invalid s2 length"));
        falcon1024.verify(v.msg, v.salt, new uint256[](32), v.ntth);
        vm.expectRevert(bytes("invalid ntth length"));
        falcon1024.verify(v.msg, v.salt, v.s2, new uint256[](63));
    }

    function test_binding1024_rejects_other_helper() public {
        vm.expectRevert(ZKNOX_falcon1024.BadHelper.selector);
        new ZKNOX_falcon1024(address(this));
        assertEq(helper.codehash, falcon1024.F1600_CODEHASH_PUBLIC());
    }

    function product(uint256[] memory s2, uint256[] memory h) external pure returns (uint256[] memory) {
        return falconProduct1024(s2, h);
    }

    function s2norm(uint256[] memory s2) external pure returns (uint256 o, uint256 n) {
        return _s2NormCompact1024(s2);
    }

    function test_gas_verify1024() public view {
        uint256 total;
        uint256 maxg;
        for (uint256 k = 0; k < 10; k++) {
            Vec memory v = _vec("kat", k);
            uint256 g = gasleft();
            bool ok = falcon1024.verify(v.msg, v.salt, v.s2, v.ntth);
            g -= gasleft();
            require(ok);
            total += g;
            if (g > maxg) maxg = g;
            if (k == 0) console.log("Verify Falcon-1024 NIST KAT 0 (8 lanes):", g);
        }
        console.log("Verify Falcon-1024, mean over KAT 0..9:", total / 10);
        console.log("Verify Falcon-1024, max over KAT 0..9:", maxg);
        Vec memory v0 = _vec("kat", 0);
        uint256 g0 = gasleft();
        this.product(v0.s2, v0.ntth);
        console.log("falconProduct1024 (fw + pointwise + inv), external call:", g0 - gasleft());
        g0 = gasleft();
        this.s2norm(v0.s2);
        console.log("_s2NormCompact1024, external call:", g0 - gasleft());
    }
}
