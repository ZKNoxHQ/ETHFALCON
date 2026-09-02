// SPDX-License-Identifier: MIT
// FILE: test/falcon_fast_helper.t.sol
//
// The verifier delegates Keccak-f[1600] to an external contract. These tests
// establish, in order:
//   1. the attack primitive: a helper that lies makes hashToPointNIST return a
//      point the attacker picks, with the message no longer binding at all;
//   2. that a `code.length != 0` binding accepts such a helper;
//   3. that the shipped EXTCODEHASH binding rejects it at construction;
//   4. that the per-call re-assert catches a helper whose code changes after
//      construction;
//   5. that the honest helper still verifies.
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon_fast.sol";
import "../src/ZKNOX_shake_fast.sol";

/// @dev A "permutation" that ignores its input and returns 800 bytes the
///      attacker chose. Well-formed: correct return size, never reverts, so it
///      passes every liveness check f1600Fast170 makes.
contract LyingHelper {
    fallback(bytes calldata) external returns (bytes memory) {
        uint256[25] memory st;
        for (uint256 i = 0; i < 25; i++) {
            st[i] = uint256(keccak256(abi.encodePacked("attacker-chosen", i))) >> 192;
        }
        return abi.encodePacked(st);
    }
}

/// @dev The binding as it was BEFORE the fix, kept here only so the test can
///      show what it lets through.
contract WeakBindingVerifier {
    address public immutable f1600Helper;

    constructor(address helper) {
        require(helper.code.length != 0, "falcon-fast: helper has no code");
        f1600Helper = helper;
    }
}

contract FalconFastHelperTest is Test {
    address honest;
    address lying;

    bytes saltA = "\x4b\x09\x9f\x8e\x30\x0f\x01\xb8\x65\x0f\x1f\x4b\x1d\x8f\xcf\x3f\x3c\xb5\x3f\xb8\xe9\xeb\x2e\xa2\x03\xbd\xc9\x70\xf5\x0a\xe5\x54\x28\xa9\x1f\x7f\x53\xac\x26\x6b";
    bytes saltB = "\x46\xb9\xdd\x2b\x0b\xa8\x8d\x13\x23\x3b\x3f\xeb\x74\x3e\xeb\x24\x3f\xcd\x52\xea\x62\xb8\x1b\x82\xb5\x0c\x27\x64\x6e\xd5\x76\x2f\xd7\x5d\xc4\xdd\xd8\xc0\xf2\x00";
    bytes msgA = "My name is Renaud from ZKNOX!!!!";
    bytes msgB = "a completely different message!!";

    function setUp() public {
        string[] memory cmds = new string[](2);
        cmds[0] = "cat";
        cmds[1] = "test/f1600_170.hex";
        bytes memory runtime = vm.ffi(cmds);
        bytes memory initCode = abi.encodePacked(hex"61", uint16(runtime.length), hex"8061000b5f395ff3", runtime);
        address h;
        assembly {
            h := create(0, add(initCode, 32), mload(initCode))
        }
        require(h != address(0), "f1600-170: CREATE failed");
        honest = h;
        lying = address(new LyingHelper());
    }

    // ---------------------------------------------------------------- 1. the primitive

    /// With a lying helper the point no longer depends on the message OR the
    /// salt: two different (salt, message) pairs hash to the SAME polynomial.
    /// That is the forgery primitive — one short s2 found once is then valid for
    /// every message, under every public key.
    function test_lying_helper_makes_the_message_stop_binding() public view {
        uint256[] memory pA = hashToPointNISTFast(saltA, msgA, lying);
        uint256[] memory pB = hashToPointNISTFast(saltB, msgB, lying);
        for (uint256 i = 0; i < n; i++) {
            assertEq(pA[i], pB[i], "attacker-controlled point must be message-independent");
        }
        // and it is not what the honest helper produces
        uint256[] memory honestPoint = hashToPointNISTFast(saltA, msgA, honest);
        assertTrue(honestPoint[0] != pA[0] || honestPoint[1] != pA[1], "lying helper must diverge");
    }

    // ---------------------------------------------------------------- 2. the old binding

    /// `code.length != 0` accepts the lying helper without complaint.
    function test_weak_binding_accepts_the_lying_helper() public {
        WeakBindingVerifier weak = new WeakBindingVerifier(lying);
        assertEq(weak.f1600Helper(), lying, "the old check let a hostile helper through");
    }

    // ---------------------------------------------------------------- 3. the fix, at construction

    function test_codehash_binding_rejects_the_lying_helper() public {
        vm.expectRevert(ZKNOX_falcon_fast.BadHelper.selector);
        new ZKNOX_falcon_fast(lying);
    }

    function test_codehash_binding_rejects_an_empty_address() public {
        vm.expectRevert(ZKNOX_falcon_fast.BadHelper.selector);
        new ZKNOX_falcon_fast(address(0xdead));
    }

    /// One byte off is enough.
    function test_codehash_binding_rejects_a_one_byte_mutation() public {
        bytes memory runtime = honest.code;
        runtime[1000] = bytes1(uint8(runtime[1000]) ^ 0x01);
        address mutant = address(0xBEEF);
        vm.etch(mutant, runtime);
        assertEq(mutant.code.length, honest.code.length, "same size");
        vm.expectRevert(ZKNOX_falcon_fast.BadHelper.selector);
        new ZKNOX_falcon_fast(mutant);
    }

    // ---------------------------------------------------------------- 4. the fix, per call

    /// Construction-time-only checking would be defeated by any code change at
    /// the bound address. The per-call re-assert catches it.
    function test_per_call_recheck_catches_a_swapped_helper() public {
        ZKNOX_falcon_fast v = new ZKNOX_falcon_fast(honest);

        // swap the code under the bound address
        vm.etch(honest, address(new LyingHelper()).code);

        uint256[] memory s2 = new uint256[](32);
        uint256[] memory ntth = new uint256[](32);
        vm.expectRevert(ZKNOX_falcon_fast.BadHelper.selector);
        v.verify(msgA, saltA, s2, ntth);
    }

    // ---------------------------------------------------------------- 5. no false positive

    function test_honest_helper_is_accepted_and_verifies() public {
        ZKNOX_falcon_fast v = new ZKNOX_falcon_fast(honest);
        assertEq(v.f1600Helper(), honest);
        // the honest point is unchanged by the binding
        uint256[] memory p = hashToPointNISTFast(saltA, msgA, honest);
        assertEq(p[0], 2578);
        assertEq(p[511], 11296);
    }
}
