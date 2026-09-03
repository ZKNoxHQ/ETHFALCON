// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_NTT_falcon.sol";
import "../src/ZKNOX_NTT_falcon_packed.sol";
import "../src/ZKNOX_NTT_falcon_fused.sol";
import "../src/ZKNOX_falcon_core.sol";

/// Differential tests of the fused radix-8 transform against the layer by
/// layer packed transform (itself asserted against _ZKNOX_NTTFW_vectorized in
/// test/ntt_packed.t.sol), and of the packed norms against falcon_normalize.
contract NttFusedTest is Test {
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

    function _lane(uint256 w, uint256 j) internal pure returns (uint256) {
        return (w >> (64 * j)) & 0xffffffffffffffff;
    }

    // ---- forward -----------------------------------------------------------

    function _diffFw(uint256[] memory c) internal pure {
        uint256[] memory expected = _nttFwPacked(_packFromCompact(c));
        uint256[] memory got = _nttFwFused(c);
        require(got.length == 128, "length");
        for (uint256 w = 0; w < 128; w++) {
            for (uint256 j = 0; j < 4; j++) {
                uint256 g = _lane(got[w], j);
                require(g < 19 * q, "forward lane exceeds the 19q bound");
                require(g % q == _lane(expected[w], j) % q, "fused forward differs from packed");
            }
        }
    }

    function test_fused_forward_matches_packed() public pure {
        for (uint256 s = 0; s < 8; s++) {
            _diffFw(_compact(s));
        }
    }

    function testFuzz_fused_forward_matches_packed(uint256 seed) public pure {
        _diffFw(_compact(seed));
    }

    function test_fused_forward_saturated() public pure {
        _diffFw(_saturated());
    }

    // ---- product + inverse -------------------------------------------------

    function _diffInv(uint256[] memory a, uint256[] memory b) internal pure {
        uint256[] memory expected =
            _unpackTo512(_nttInvPacked(_vecMulPacked(_nttFwPacked(_packFromCompact(a)), _packFromCompact(b))));
        uint256[] memory got = _nttInvFusedMul(_nttFwFused(a), b);
        for (uint256 w = 0; w < 128; w++) {
            for (uint256 j = 0; j < 4; j++) {
                uint256 g = _lane(got[w], j);
                require(g < q, "inverse lane not canonical");
                require(g == expected[4 * w + j], "fused inverse differs from packed");
            }
        }
    }

    function test_fused_inverse_matches_packed() public pure {
        for (uint256 s = 0; s < 6; s++) {
            _diffInv(_compact(s), _compact(uint256(keccak256(abi.encodePacked(s)))));
        }
    }

    function testFuzz_fused_inverse_matches_packed(uint256 seed) public pure {
        _diffInv(_compact(seed), _compact(uint256(keccak256(abi.encodePacked(seed)))));
    }

    function test_fused_inverse_saturated() public pure {
        _diffInv(_saturated(), _saturated());
        _diffInv(_saturated(), _compact(3));
        _diffInv(_compact(4), _saturated());
    }

    // ---- norms ---------------------------------------------------------------

    /// reference: the two halves of falcon_normalize, written out
    function _refS2(uint256[] memory c) internal pure returns (uint256 oor, uint256 norm) {
        for (uint256 i = 0; i < 32; i++) {
            for (uint256 j = 0; j < 16; j++) {
                uint256 v = (c[i] >> (16 * j)) & 0xffff;
                if (v >= q) oor = 1;
                uint256 centred = v > qs1 ? q - v : v;
                norm += centred * centred;
            }
        }
    }

    function _refS1(uint256[] memory h, uint256[] memory s) internal pure returns (uint256 norm) {
        for (uint256 w = 0; w < 128; w++) {
            for (uint256 j = 0; j < 4; j++) {
                uint256 v = addmod(_lane(h[w], j), q - _lane(s[w], j), q);
                uint256 centred = v > qs1 ? q - v : v;
                norm += centred * centred;
            }
        }
    }

    function test_s2_norm_matches_reference() public pure {
        for (uint256 s = 0; s < 8; s++) {
            uint256[] memory c = _compact(s);
            (uint256 oor, uint256 norm) = _s2NormCompact(c);
            (uint256 roor, uint256 rnorm) = _refS2(c);
            require(oor == 0 && roor == 0, "unexpected range flag");
            require(norm == rnorm, "s2 norm differs");
        }
        (uint256 o2, uint256 n2) = _s2NormCompact(_saturated());
        (, uint256 rn2) = _refS2(_saturated());
        require(o2 == 0 && n2 == rn2, "saturated s2 norm differs");
    }

    function testFuzz_s2_norm_matches_reference(uint256 seed) public pure {
        uint256[] memory c = _compact(seed);
        (uint256 oor, uint256 norm) = _s2NormCompact(c);
        (, uint256 rnorm) = _refS2(c);
        require(oor == 0 && norm == rnorm, "s2 norm differs");
    }

    /// every 16-bit value from q to 0xffff must be flagged, everything below accepted
    function test_s2_range_flag() public pure {
        uint256[] memory c = _compact(11);
        for (uint256 v = q - 3; v < q; v++) {
            c[5] = (c[5] & ~(uint256(0xffff) << 112)) | (v << 112);
            (uint256 oor,) = _s2NormCompact(c);
            require(oor == 0, "in-range value flagged");
        }
        uint256[8] memory bad = [uint256(q), q + 1, 0x3fff, 0x4000, 0x7fff, 0x8000, 0xc001, 0xffff];
        for (uint256 i = 0; i < 8; i++) {
            for (uint256 pos = 0; pos < 16; pos += 5) {
                uint256[] memory d = _compact(12 + i);
                d[7] = (d[7] & ~(uint256(0xffff) << (16 * pos))) | (bad[i] << (16 * pos));
                (uint256 oor,) = _s2NormCompact(d);
                require(oor != 0, "out-of-range value accepted");
            }
        }
    }

    function _packedCanonical(uint256 seed) internal pure returns (uint256[] memory A) {
        A = new uint256[](128);
        for (uint256 w = 0; w < 128; w++) {
            uint256 x;
            for (uint256 j = 0; j < 4; j++) {
                x |= (uint256(keccak256(abi.encodePacked(seed, w, j))) % q) << (64 * j);
            }
            A[w] = x;
        }
    }

    function test_s1_norm_matches_reference() public pure {
        for (uint256 s = 0; s < 8; s++) {
            uint256[] memory h = _packedCanonical(s);
            uint256[] memory x = _packedCanonical(s + 100);
            require(_normS1Packed(h, x) == _refS1(h, x), "s1 norm differs");
        }
        // extremes: h = 0 / s = q-1 and h = q-1 / s = 0 in every lane
        uint256[] memory z = new uint256[](128);
        uint256[] memory m = new uint256[](128);
        for (uint256 w = 0; w < 128; w++) {
            m[w] = (q - 1) * 0x0000000000000001000000000000000100000000000000010000000000000001;
        }
        require(_normS1Packed(z, m) == _refS1(z, m), "s1 norm differs (0, q-1)");
        require(_normS1Packed(m, z) == _refS1(m, z), "s1 norm differs (q-1, 0)");
        require(_normS1Packed(m, m) == 0, "s1 norm of (m, m) not zero");
    }

    function testFuzz_s1_norm_matches_reference(uint256 seed) public pure {
        uint256[] memory h = _packedCanonical(seed);
        uint256[] memory x = _packedCanonical(uint256(keccak256(abi.encodePacked(seed))));
        require(_normS1Packed(h, x) == _refS1(h, x), "s1 norm differs");
    }

    // ---- gas -----------------------------------------------------------------

    function test_gas_fused() public view {
        uint256[] memory a = _compact(7);
        uint256[] memory b = _compact(1007);

        uint256 g = gasleft();
        uint256[] memory fa = _nttFwPacked(_packFromCompact(a));
        console.log("NTTFW packed (from compact)     :", g - gasleft());
        g = gasleft();
        uint256[] memory ia = _unpackTo512(_nttInvPacked(_vecMulPacked(fa, _packFromCompact(b))));
        console.log("pack+VECMUL+NTTINV+unpack packed:", g - gasleft());
        ia;

        g = gasleft();
        uint256[] memory fb = _nttFwFused(a);
        console.log("NTTFW fused (from compact)      :", g - gasleft());
        g = gasleft();
        _nttInvFusedMul(fb, b);
        console.log("mul+NTTINV fused (canonical)    :", g - gasleft());

        g = gasleft();
        (, uint256 n2) = _s2NormCompact(a);
        console.log("s2 norm + range check (compact) :", g - gasleft());
        uint256[] memory h = _packedCanonical(1);
        g = gasleft();
        uint256 n1 = _normS1Packed(h, fb);
        console.log("s1 norm (packed)                :", g - gasleft());
        n1;
        n2;
    }
}
