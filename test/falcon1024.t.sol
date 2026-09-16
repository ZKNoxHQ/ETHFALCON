// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon1024.sol";
import "../src/ZKNOX_falcon1024_core.sol";
import "../src/ZKNOX_NTT_falcon1024.sol";
import {_absorbResident, _f1600Resident} from "../src/ZKNOX_falcon_core8.sol";

/// @notice the previous sampler (four candidates per state lane, first Falcon-1024
///         delivery), reference of the differential tests below; hashToPointNIST(salt, msgHash) for n = 1024 consumed on the fly: returns
///         sum over i of centred(h_i - s1_i)^2, with s1 packed on eight lanes
///         as 3q + 6144 - s1_i (falconProduct1024).
function hashToPointNormS1_1024_lane4(bytes memory salt, bytes memory msgHash, address helper, uint256[] memory s1)
    view
    returns (uint256 norm)
{
    require(s1.length == 128, "s1 length");
    // replicated state
    uint256[25] memory buf;
    uint256 st;
    assembly ("memory-safe") {
        st := buf
    }
    _absorbResident(st, abi.encodePacked(salt, msgHash), helper);
    uint256 i;
    uint256 s1p;
    assembly ("memory-safe") {
        s1p := add(s1, 32)
    }
    while (true) {
        assembly ("memory-safe") {
            // A block holds at most 68 candidates: when it starts below 957 outputs
            // it cannot reach 1024, so the block runs without output-bound checks.
            switch lt(i, 957)
            case 1 {
                for { let lp := st } lt(lp, add(st, 544)) { lp := add(lp, 32) } {
                    let lane := mload(lp)
                    lane := or(shr(8, and(lane, 0xff00ff00ff00ff00)), shl(8, and(lane, 0x00ff00ff00ff00ff)))
                    switch and(and(add(and(lane, 0x7fff7fff7fff7fff), 0x0ffb0ffb0ffb0ffb), lane), 0x8000800080008000)
                    case 0 {
                        // all four below 5q: the four candidates spread to 32-bit spacing (two
                        // mask/shift steps) are added to the four complement lanes of s1 in one
                        // add, then each sum is reduced, centred and squared
                        let ptr := add(s1p, shl(5, shr(3, i)))
                        let sh := shl(5, and(i, 7))
                        let x := shr(sh, mload(ptr))
                        if gt(sh, 128) { x := or(x, shl(sub(256, sh), mload(add(ptr, 32)))) }
                        let y := or(and(lane, 0xffffffff), shl(32, and(lane, 0xffffffff00000000)))
                        x := add(
                            x,
                            or(
                                and(y, 0x000000000000ffff000000000000ffff),
                                shl(16, and(y, 0x00000000ffff000000000000ffff0000))
                            )
                        )
                        let d := sub(mod(and(x, 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(32, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(64, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(96, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        i := add(i, 4)
                    }
                    default {
                        for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                            let v := and(shr(shl(4, k), lane), 0xffff)
                            if lt(v, 61445) {
                                let d :=
                                    sub(
                                        mod(
                                            add(
                                                v,
                                                and(
                                                    shr(shl(5, and(i, 7)), mload(add(s1p, shl(5, shr(3, i))))),
                                                    0xffffffff
                                                )
                                            ),
                                            12289
                                        ),
                                        6144
                                    )
                                norm := add(norm, mul(d, d))
                                i := add(i, 1)
                            }
                        }
                    }
                }
            }
            default {
                for { let lp := st } lt(lp, add(st, 544)) { lp := add(lp, 32) } {
                    let lane := mload(lp)
                    lane := or(shr(8, and(lane, 0xff00ff00ff00ff00)), shl(8, and(lane, 0x00ff00ff00ff00ff)))
                    switch and(
                        iszero(
                            and(and(add(and(lane, 0x7fff7fff7fff7fff), 0x0ffb0ffb0ffb0ffb), lane), 0x8000800080008000)
                        ),
                        lt(i, 1021)
                    )
                    case 1 {
                        let ptr := add(s1p, shl(5, shr(3, i)))
                        let sh := shl(5, and(i, 7))
                        let x := shr(sh, mload(ptr))
                        if gt(sh, 128) { x := or(x, shl(sub(256, sh), mload(add(ptr, 32)))) }
                        let y := or(and(lane, 0xffffffff), shl(32, and(lane, 0xffffffff00000000)))
                        x := add(
                            x,
                            or(
                                and(y, 0x000000000000ffff000000000000ffff),
                                shl(16, and(y, 0x00000000ffff000000000000ffff0000))
                            )
                        )
                        let d := sub(mod(and(x, 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(32, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(64, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        d := sub(mod(and(shr(96, x), 0xffffffff), 12289), 6144)
                        norm := add(norm, mul(d, d))
                        i := add(i, 4)
                    }
                    default {
                        for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                            let v := and(shr(shl(4, k), lane), 0xffff)
                            if and(lt(v, 61445), lt(i, 1024)) {
                                let d :=
                                    sub(
                                        mod(
                                            add(
                                                v,
                                                and(
                                                    shr(shl(5, and(i, 7)), mload(add(s1p, shl(5, shr(3, i))))),
                                                    0xffffffff
                                                )
                                            ),
                                            12289
                                        ),
                                        6144
                                    )
                                norm := add(norm, mul(d, d))
                                i := add(i, 1)
                            }
                        }
                    }
                    if eq(i, 1024) { lp := add(st, 512) }
                }
            }
        }
        if (i == 1024) break;
        _f1600Resident(st, helper);
    }
}

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

    /// complement lanes 3q + 6144 - x for arbitrary x < 3q (the sampler's whole input domain)
    function _s1Lanes(uint256 seed) internal pure returns (uint256[] memory s1) {
        s1 = new uint256[](128);
        for (uint256 w = 0; w < 128; w++) {
            uint256 word;
            for (uint256 j = 0; j < 8; j++) {
                uint256 x = uint256(keccak256(abi.encodePacked(seed, w, j))) % (3 * Q);
                if (seed % 5 == 1) x = 3 * Q - 1;
                if (seed % 5 == 2) x = 0;
                word |= (3 * Q + 6144 - x) << (32 * j);
            }
            s1[w] = word;
        }
    }

    function testFuzz_sampler1024_matches_lane4(uint256 seed, bytes memory m) public view {
        bytes memory salt = abi.encodePacked(keccak256(abi.encode(seed)), bytes8(uint64(seed)));
        uint256[] memory s1 = _s1Lanes(seed);
        assertEq(hashToPointNormS1_1024(salt, m, helper, s1), hashToPointNormS1_1024_lane4(salt, m, helper, s1));
    }

    function test_sampler1024_matches_lane4_lengths() public view {
        for (uint256 len = 0; len < 300; len += 23) {
            bytes memory m = new bytes(len);
            for (uint256 j = 0; j < len; j++) {
                m[j] = bytes1(uint8(j * 7 + len));
            }
            for (uint256 s = 0; s < 5; s++) {
                bytes memory salt = abi.encodePacked(keccak256(abi.encode(s, len)), bytes8(0));
                uint256[] memory s1 = _s1Lanes(s * 1000 + len);
                assertEq(hashToPointNormS1_1024(salt, m, helper, s1), hashToPointNormS1_1024_lane4(salt, m, helper, s1));
            }
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
