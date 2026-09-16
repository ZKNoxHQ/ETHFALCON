// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon1024_core.sol";
import "../src/ZKNOX_NTT_falcon1024.sol";

/// gas breakdown of the Falcon-1024 core (not part of the functional tests)
contract Prof1024 {
    address public helper;

    constructor(address h) {
        helper = h;
    }

    function run(bytes memory salt, bytes memory msg_, uint256[] memory s2, uint256[] memory ntth)
        external
        view
        returns (uint256 gNorm, uint256 gProd, uint256 gHash, uint256 gTotal, uint256 norm)
    {
        uint256 g0 = gasleft();
        (, uint256 n2) = _s2NormCompact1024(s2);
        uint256 g1 = gasleft();
        uint256[] memory s1 = falconProduct1024(s2, ntth);
        uint256 g2 = gasleft();
        norm = n2 + hashToPointNormS1_1024(salt, msg_, helper, s1);
        uint256 g3 = gasleft();
        return (g0 - g1, g1 - g2, g2 - g3, g0 - g3, norm);
    }

    function passes(uint256[] memory s2, uint256[] memory h) external view returns (uint256[8] memory g) {
        bytes memory tw = _F10_TW;
        uint256 tb;
        assembly ("memory-safe") {
            tb := add(tw, 32)
        }
        uint256[] memory A = new uint256[](128);
        uint256 x = gasleft();
        _f10ProdA0(s2, A);
        g[0] = x - gasleft();
        x = gasleft();
        _f10FwA(A);
        g[1] = x - gasleft();
        x = gasleft();
        _f10FwB(A, tb);
        g[2] = x - gasleft();
        x = gasleft();
        _f10ProdW(A, h, tb);
        g[3] = x - gasleft();
        x = gasleft();
        _f10ProdInvB(A, tb + 2048);
        g[4] = x - gasleft();
        x = gasleft();
        _f10ProdInvA(A);
        g[5] = x - gasleft();
        x = gasleft();
        _f10ProdA0Inv(A);
        g[6] = x - gasleft();
    }

    function perm(address h) external view returns (uint256 g) {
        uint256[25] memory buf;
        uint256 st;
        assembly ("memory-safe") {
            st := buf
        }
        _f1600Resident(st, h);
        g = gasleft();
        _f1600Resident(st, h);
        g = g - gasleft();
    }
}

contract Profile1024Test is Test {
    function _deploy(string memory path) internal returns (address h) {
        string[] memory cmds = new string[](2);
        cmds[0] = "cat";
        cmds[1] = path;
        bytes memory runtime = vm.ffi(cmds);
        bytes memory initCode = abi.encodePacked(hex"61", uint16(runtime.length), hex"8061000b5f395ff3", runtime);
        assembly {
            h := create(0, add(initCode, 32), mload(initCode))
        }
    }

    function test_profile1024() public {
        address helper = _deploy("test/f1600_zknox.hex");
        Prof1024 p = new Prof1024(helper);
        string memory json = vm.readFile("test/falcon1024_vectors.json");
        uint256[4] memory acc;
        for (uint256 k = 0; k < 10; k++) {
            string memory pre = string.concat(".kat[", vm.toString(k), "]");
            (uint256 a, uint256 b, uint256 c, uint256 d,) = p.run(
                vm.parseJsonBytes(json, string.concat(pre, ".salt")),
                vm.parseJsonBytes(json, string.concat(pre, ".msg")),
                vm.parseJsonUintArray(json, string.concat(pre, ".s2")),
                vm.parseJsonUintArray(json, string.concat(pre, ".ntth"))
            );
            acc[0] += a;
            acc[1] += b;
            acc[2] += c;
            acc[3] += d;
        }
        console.log("mean s2 norm   :", acc[0] / 10);
        console.log("mean product   :", acc[1] / 10);
        console.log("mean hash+norm :", acc[2] / 10);
        console.log("mean core total:", acc[3] / 10);
        console.log("one warm permutation call:", p.perm(helper));
        uint256[8] memory g =
            p.passes(vm.parseJsonUintArray(json, ".kat[0].s2"), vm.parseJsonUintArray(json, ".kat[0].ntth"));
        console.log("A0 ", g[0]);
        console.log("A  ", g[1]);
        console.log("B  ", g[2]);
        console.log("W  ", g[3]);
        console.log("B' ", g[4]);
        console.log("A' ", g[5]);
        console.log("A0'", g[6]);
    }
}
