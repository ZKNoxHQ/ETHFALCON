// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_NTT_falcon1024.sol";
import {Ntt1024Vectors} from "./ntt1024_vectors.sol";

/// Falcon-1024 eight-lane NTT / INTT: vectors from noble post-quantum (jsref/),
/// a scalar reference with its own tables (7^brv10(i) by modexp), round trips.
contract Ntt1024Test is Test {
    uint256 constant Q = 12289;

    function _brv10(uint256 x) internal pure returns (uint256 r) {
        for (uint256 i = 0; i < 10; i++) {
            r = (r << 1) | ((x >> i) & 1);
        }
    }

    function _pow(uint256 b, uint256 e) internal pure returns (uint256 r) {
        r = 1;
        while (e > 0) {
            if (e & 1 == 1) r = mulmod(r, b, Q);
            b = mulmod(b, b, Q);
            e >>= 1;
        }
    }

    function _unpack(uint256[] memory c) internal pure returns (uint256[] memory a) {
        a = new uint256[](1024);
        for (uint256 i = 0; i < 1024; i++) {
            a[i] = (c[i >> 4] >> (16 * (i & 15))) & 0xffff;
        }
    }

    function _pack(uint256[] memory a) internal pure returns (uint256[] memory c) {
        c = new uint256[](64);
        for (uint256 i = 0; i < 1024; i++) {
            c[i >> 4] |= a[i] << (16 * (i & 15));
        }
    }

    /// eprint 2016/504 Alg. 1 (the loops of ZKNOX_NTT.sol), n = 1024
    function _refFw(uint256[] memory a) internal pure returns (uint256[] memory) {
        uint256 t = 1024;
        for (uint256 m = 1; m < 1024; m <<= 1) {
            t >>= 1;
            for (uint256 i = 0; i < m; i++) {
                uint256 S = _pow(7, _brv10(m + i));
                for (uint256 j = 2 * i * t; j < 2 * i * t + t; j++) {
                    uint256 U = a[j];
                    uint256 V = mulmod(a[j + t], S, Q);
                    a[j] = addmod(U, V, Q);
                    a[j + t] = addmod(U, Q - V, Q);
                }
            }
        }
        return a;
    }

    /// eprint 2016/504 Alg. 2, scaled by 1024^-1
    function _refInv(uint256[] memory a) internal pure returns (uint256[] memory) {
        uint256 t = 1;
        for (uint256 m = 1024; m > 1; m >>= 1) {
            uint256 h = m >> 1;
            for (uint256 i = 0; i < h; i++) {
                uint256 S = _pow(_pow(7, _brv10(h + i)), Q - 2);
                for (uint256 j = 2 * i * t; j < 2 * i * t + t; j++) {
                    uint256 U = a[j];
                    uint256 V = a[j + t];
                    a[j] = addmod(U, V, Q);
                    a[j + t] = mulmod(addmod(U, Q - V, Q), S, Q);
                }
            }
            t <<= 1;
        }
        uint256 ninv = _pow(1024, Q - 2);
        for (uint256 j = 0; j < 1024; j++) {
            a[j] = mulmod(a[j], ninv, Q);
        }
        return a;
    }

    function _eq(uint256[] memory x, uint256[] memory y, string memory what) internal pure {
        require(x.length == y.length, "length");
        for (uint256 i = 0; i < x.length; i++) {
            if (x[i] != y[i]) revert(string.concat(what, ": word ", vm.toString(i)));
        }
    }

    function _random(uint256 seed) internal pure returns (uint256[] memory c) {
        c = new uint256[](64);
        for (uint256 i = 0; i < 64; i++) {
            uint256 w;
            for (uint256 j = 0; j < 16; j++) {
                w |= (uint256(keccak256(abi.encodePacked(seed, i, j))) % Q) << (16 * j);
            }
            c[i] = w;
        }
    }

    function test_ntt1024_noble_vectors() public pure {
        for (uint256 k = 0; k < Ntt1024Vectors.COUNT; k++) {
            (string memory name, uint256[] memory a, uint256[] memory n, uint256[] memory inv) = Ntt1024Vectors.get(k);
            _eq(falconNTT1024(a), n, string.concat("NTT ", name));
            _eq(falconINTT1024(a), inv, string.concat("INTT ", name));
            _eq(falconINTT1024(n), a, string.concat("INTT(NTT) ", name));
        }
    }

    function test_ntt1024_scalar_reference() public pure {
        uint256[] memory c = _random(42);
        _eq(falconNTT1024(c), _pack(_refFw(_unpack(c))), "NTT vs scalar");
        _eq(falconINTT1024(c), _pack(_refInv(_unpack(c))), "INTT vs scalar");
    }

    function testFuzz_ntt1024_roundtrip(uint256 seed) public pure {
        uint256[] memory c = _random(seed);
        _eq(falconINTT1024(falconNTT1024(c)), c, "INTT(NTT)");
        _eq(falconNTT1024(falconINTT1024(c)), c, "NTT(INTT)");
    }

    /// product in the ring: INTT(NTT(a) o NTT(b)) against the scalar schoolbook one, a sparse b
    function test_ntt1024_ring_product() public pure {
        uint256[] memory a = _random(7);
        uint256[] memory ua = _unpack(a);
        // b = 3 X^1000 + (q - 5) X^17 + 11
        uint256[] memory ub = new uint256[](1024);
        ub[1000] = 3;
        ub[17] = Q - 5;
        ub[0] = 11;
        uint256[] memory ref = new uint256[](1024);
        uint256[3] memory idx = [uint256(1000), 17, 0];
        for (uint256 s = 0; s < 3; s++) {
            uint256 e = idx[s];
            for (uint256 i = 0; i < 1024; i++) {
                uint256 p = mulmod(ua[i], ub[e], Q);
                uint256 k = i + e;
                if (k < 1024) ref[k] = addmod(ref[k], p, Q);
                else ref[k - 1024] = addmod(ref[k - 1024], Q - p, Q);
            }
        }
        uint256[] memory na = _unpack(falconNTT1024(a));
        uint256[] memory nb = _unpack(falconNTT1024(_pack(ub)));
        for (uint256 i = 0; i < 1024; i++) {
            na[i] = mulmod(na[i], nb[i], Q);
        }
        _eq(falconINTT1024(_pack(na)), _pack(ref), "ring product");
    }

    function _expectRevertNtt(uint256[] memory c, bool inverse) external pure returns (uint256[] memory) {
        return inverse ? falconINTT1024(c) : falconNTT1024(c);
    }

    function test_ntt1024_rejects_non_canonical() public {
        uint256[] memory c = _random(3);
        c[37] |= uint256(0xffff) << 144;
        vm.expectRevert(bytes("coefficient >= q"));
        this._expectRevertNtt(c, false);
        c = _random(3);
        c[5] = (c[5] & ~uint256(0xffff)) | Q;
        vm.expectRevert(bytes("coefficient >= q"));
        this._expectRevertNtt(c, true);
    }

    function test_gas_ntt1024() public view {
        uint256[] memory a = _random(11);
        uint256 g = gasleft();
        uint256[] memory n = falconNTT1024(a);
        console.log("falconNTT1024  (8 lanes):", g - gasleft());
        g = gasleft();
        falconINTT1024(n);
        console.log("falconINTT1024 (8 lanes):", g - gasleft());
        uint256[] memory u = _unpack(a);
        g = gasleft();
        _refFw(u);
        console.log("scalar reference NTT, n = 1024:", g - gasleft());
    }
}
