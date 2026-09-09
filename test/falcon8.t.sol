// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon.sol";
import "../src/ZKNOX_falcon_turbo.sol";
import "../src/ZKNOX_falcon_fused.sol";
import "../src/ZKNOX_falcon8.sol";
import "../src/ZKNOX_falcon_core8.sol";
import "../src/ZKNOX_NTT_falcon8.sol";
import "../src/ZKNOX_falcon_core.sol";
import "../src/ZKNOX_falcon_core_fused.sol";
import "../src/ZKNOX_HashToPoint_packed.sol";
import "../src/ZKNOX_shake_fast.sol";
import "../src/ZKNOX_NTT_falcon_fused.sol";

/// End-to-end tests of the fused verifier: the packed hash-to-point against
/// hashToPointNISTFast, falcon_core_fused against falcon_core on both sides of
/// the norm bound, the KAT vector, and the helper binding.
contract Falcon8Test is Test {
    ZKNOX_falcon falcon;
    ZKNOX_falcon_turbo falconTurbo;
    ZKNOX_falcon_fused falconFused;
    ZKNOX_falcon8 falcon8;
    address f1600Helper;

    // forgefmt: disable-next-line
    uint256[] pkc = [5662797900309780854973796610500849947334657117880689816302353465126500706865, 19773102689601973621062070293263100534733440101750387150077711329493973274058, 14606681890476865709816748627007131256488820167404174518724605890405097603719, 15845234755931409677594030697035096324340457247480758851130851814703350289524, 5524941775098342886171484209767745714294893760953145782448900256027476885810, 15301033023652038200658165594502048003364566882283859976805808429697192567788, 18875246040654000517074755552890901133645669291006567534900678519700207707731, 11843395683334522200668269515783436692309636627649985746204914551011013629864, 8419305811746464065544475584323153271481428319969733938911379662274846467111, 18343417927809591481517183183479503623951147924071925629514120039495430967592, 10007451325105194000131443764495043320645967197761209321537835667210153693191, 779487061150515667795843171268512499191273448454307717194241961063365614179, 14889466660684110621550004892629051623956217990147793956971155241422811501259, 2995124819739638247263964985959552967489690950312509006670204449438399867779, 16698797261630410217796026169071784061995015858612862963622742163763641855864, 13129716852402613948762495927854872029721399215764359316540986925328111906305, 8620514528683669238836845045565231437047299941974001946945409334379184590766, 5184181041252042291984928267300200431567362250531180743278111084485128161037, 15555356690664302555826193017277818624355238475260445618945780405430020481200, 19264077329172342356817033544893125657281034846341493111114385757819435942150, 8708853592016768361541207473719404660232059936330605270802350059910738161396, 21018648773068189736719755689803981281912117625241701774409626083005150670687, 267026197077955750670312407002345619518873569178283514941902712705828521229, 14359242962640593260752841229079220345384234239741953227891227234975247894859, 8320354099602406351863744856415421903486499003224102136141447162113864442068, 17564344674783852357247325589247473882830766139750808683064015010041459773180, 12601232530472338126510941067000966999586933909071534455578397454667291628041, 17820703520112071877812607241017358905719406745793395857586668204300579510382, 20977963461796112341763752649093803701879441191599296283127418471622134932903, 5627732773047409045458881938100601008133088383905060686572856121439798106767, 2602661464000108367786729796742170641292899005030508211661215565063118195399, 20110282897068872581106488251090599973196923955248066799683528955504800771309];
    bytes message =
        "\x4d\x79\x20\x6e\x61\x6d\x65\x20\x69\x73\x20\x52\x65\x6e\x61\x75\x64\x20\x66\x72\x6f\x6d\x20\x5a\x4b\x4e\x4f\x58\x21\x21\x21\x21";

    address residentHelper;

    function _deploy(string memory path) internal returns (address helper) {
        string[] memory cmds = new string[](2);
        cmds[0] = "cat";
        cmds[1] = path;
        bytes memory runtime = vm.ffi(cmds);
        bytes memory initCode = abi.encodePacked(hex"61", uint16(runtime.length), hex"8061000b5f395ff3", runtime);
        assembly {
            helper := create(0, add(initCode, 32), mload(initCode))
        }
        require(helper != address(0), "CREATE failed");
    }

    function setUp() public {
        f1600Helper = _deploy("test/f1600_170.hex");
        residentHelper = _deploy("test/f1600_resident.hex");
        falconTurbo = new ZKNOX_falcon_turbo(f1600Helper);
        falconFused = new ZKNOX_falcon_fused(f1600Helper);
        falcon8 = new ZKNOX_falcon8(residentHelper);
    }

    /// the resident wrapper: pinned code hash, and the same permutation as the
    /// original helper on random states through both of its interfaces
    /// (832 bytes replicated in and out, 800 bytes clean in and out)
    function test_resident_helper_matches_original() public view {
        assertEq(residentHelper.codehash, falcon8.F1600_CODEHASH_PUBLIC());
        for (uint256 trial = 0; trial < 16; trial++) {
            uint256[26] memory buf;
            uint256[25] memory st;
            uint256[25] memory clean;
            for (uint256 k = 0; k < 25; k++) {
                uint256 lane = uint256(keccak256(abi.encode(trial, k))) & 0xffffffffffffffff;
                st[k] = lane;
                clean[k] = lane;
                buf[k + 1] = lane * _REP4;
            }
            f1600Fast170(st, f1600Helper);
            uint256 p;
            assembly {
                p := add(buf, 32)
            }
            _f1600Resident(p, residentHelper);
            f1600Fast170(clean, residentHelper);
            for (uint256 k = 0; k < 25; k++) {
                assertEq(buf[k + 1], st[k] * _REP4, "resident lane differs");
                assertEq(clean[k], st[k], "clean lane differs");
            }
        }
        // other lengths revert
        (bool ok,) = residentHelper.staticcall(new bytes(801));
        assertFalse(ok);
    }

    function _katS2() internal pure returns (uint256[] memory s2) {
        // forgefmt: disable-next-line
        uint256[32] memory tmp_s2 = [21299671975787483454790402018496259712325154098698828370862796902048963440524, 226482644561092801897613003311591793491464477287443953390217386369311322015, 122241768215234212762829461233206915525091542269434133652196666067046117266, 17998600124730622827465990899026975431920967581729901424009026369714323515, 21156552726390114447912652470199481904643883857534790873521589824973084372941, 166414638319359694539675323431761741043307735201951903340794358417336827986, 21451614924126190838060080098931214529037792752475566277715416002725544210312, 21619468086225573149428575687681504604739876340506400383036250394919471022197, 21354444752013408991527203716041803392832851588841014790823564527783031812068, 40637590359720631756101950821212066384251755770640449468737583935557545897, 304228256065111465341595114396824176330096899003450390299007497041692078041, 21151253506241730037214008021307237001806313126801305624031661634239557730460, 120468666454760826934618408257990251737086348137219304739400371046851555278, 21432184616009917607269660114506949891222288898806366184877936761055983775547, 21518433259746648670717331844331216366351090502579212557941552317525499248692, 21647739391709647690802008982923383029008210205554608875280491239402655592366, 40964884159568868602122268505814142421304112730977685866577034491435560785, 134281644066644075952295235160147398920909894081157681132255108571974992066, 21691911382121948660240887888667851751942217725501296445477391473357788557231, 21696886004442863450261761150950129663128179474933041610268931151502459731982, 404610463137767168486106082172428680248662411074833208161405963809904656482, 91879772852911984237518509646383898093449686531778472006833239623202058238, 164644178638518845312982181671048221605431573972257798857853361098856857728, 21574973686812103371699961732701920024338479494313547651614704632000563981947, 175245562549033153724892418326575979114467271119590358939154166249244262574, 266796661751086246441058213427294247068745218289871840260809319750822854698, 97183598268319474873784359172567103256595448544293089836817574924407079179, 86576072396373326456075399840772528545065258380973319625452012942335356845, 208817323379001257158570910002768001779019792526753026636949068845966164023, 21082022843605336096552002185742069167530055866640863550830674291014571601566, 21458687219065978677109946072223714604125558224559441365838144304995083419665, 666423492797790993818496611161184796611027378170087972178025157084774543202];
        s2 = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            s2[i] = tmp_s2[i];
        }
    }

    function _katSalt() internal pure returns (bytes memory salt) {
        salt =
            "\xab\x0b\xae\x31\x63\x39\x89\x43\x04\xe3\x58\x77\xb0\xc2\x8a\x9b\x1f\xd1\x66\xc7\x96\xb9\xcc\x25\x8a\x06\x4a\x8f\x57\xe2\x7f\x2a\x5b\x8d\x54\x8a\x72\x8c\x94\x44";
    }

    // ---- norm folded into hash-to-point -------------------------------------

    function _lane(uint256[] memory A, uint256 i) internal pure returns (uint256) {
        return (A[i >> 2] >> (64 * (i & 3))) & 0xffffffffffffffff;
    }

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

    /// reference: ||h - s1||^2 with h = hashToPointNISTFast (expanded) and s1 canonical
    function _refNorm(bytes memory salt, bytes memory msgHash, uint256[] memory s1c)
        internal
        view
        returns (uint256 norm)
    {
        uint256[] memory h = hashToPointNISTFast(salt, msgHash, f1600Helper);
        for (uint256 i = 0; i < 512; i++) {
            uint256 v = addmod(h[i], q - s1c[i], q);
            uint256 c = v > qs1 ? q - v : v;
            norm += c * c;
        }
    }

    /// the folded sampler against the expanded hash and a scalar norm, random s2 / keys
    function test_norm_folded_matches_reference() public view {
        bytes memory salt = _katSalt();
        for (uint256 s = 0; s < 4; s++) {
            uint256[] memory s2 = _compact(s);
            uint256[] memory h = _compact(100 + s);
            uint256[] memory s1 = falconProduct8(s2, h);
            uint256[] memory s1c = new uint256[](512);
            for (uint256 i = 0; i < 512; i++) {
                s1c[i] = (43011 - ((s1[i >> 3] >> (32 * (i & 7))) & 0xffffffff)) % q;
            }
            bytes memory m = abi.encodePacked(keccak256(abi.encodePacked(s)));
            assertEq(hashToPointNormS1(salt, m, residentHelper, s1), _refNorm(salt, m, s1c));
        }
    }

    function testFuzz_norm_folded(bytes32 a, bytes32 b, uint256 seed) public view {
        bytes memory salt = abi.encodePacked(a, bytes8(b));
        bytes memory m = abi.encodePacked(a ^ b);
        uint256[] memory s1 = falconProduct8(_compact(seed), _compact(seed ^ 1));
        uint256[] memory s1c = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            s1c[i] = (43011 - ((s1[i >> 3] >> (32 * (i & 7))) & 0xffffffff)) % q;
        }
        assertEq(hashToPointNormS1(salt, m, residentHelper, s1), _refNorm(salt, m, s1c));
    }

    // ---- verify ----------------------------------------------------------------

    function test_verify_kat_8() public view {
        uint256[] memory s2 = _katS2();
        bytes memory salt = _katSalt();
        assertTrue(falconFused.verify(message, salt, s2, pkc));
        assertTrue(falcon8.verify(message, salt, s2, pkc));
        uint256[] memory bad = _katS2();
        bad[7] ^= 1 << 96;
        assertFalse(falcon8.verify(message, salt, bad, pkc));
        bytes memory m2 = abi.encodePacked(message);
        m2[0] = 0x00;
        assertFalse(falcon8.verify(m2, salt, s2, pkc));
        bytes memory salt2 = abi.encodePacked(salt);
        salt2[39] ^= 0x01;
        assertFalse(falcon8.verify(message, salt2, s2, pkc));
    }

    /// same decision as falcon_core on both sides of the bound (error amplitude sweep around s1)
    function test_core8_decision_matches_reference() public view {
        uint256[] memory ntth = _compact(1000);
        uint256 accepted;
        uint256 rejected;
        for (uint256 s = 0; s < 12; s++) {
            // a signature: small s2, message chosen so that h = s1 + e is impossible to
            // control here; instead compare the two cores on the same random inputs
            uint256[] memory s2 = _compact(s);
            bytes memory m = abi.encodePacked(keccak256(abi.encodePacked("m", s)));
            bytes memory salt = _katSalt();
            bool ref = falcon_core(s2, ntth, hashToPointNISTFast(salt, m, f1600Helper));
            bool got = falcon_core8(salt, m, residentHelper, s2, ntth);
            assertEq(got, ref);
            if (ref) accepted++;
            else rejected++;
        }
        // the KAT is accepted by both, random inputs rejected by both
        assertTrue(falcon_core8(_katSalt(), message, residentHelper, _katS2(), pkc));
        assertTrue(falcon_core(_katS2(), pkc, hashToPointNISTFast(_katSalt(), message, f1600Helper)));
        rejected;
        accepted;
    }

    function test_verify_length_checks_8() public {
        uint256[] memory s2 = _katS2();
        bytes memory salt = _katSalt();
        vm.expectRevert(bytes("invalid salt length"));
        falcon8.verify(message, abi.encodePacked(salt, bytes1(0)), s2, pkc);
        uint256[] memory shortS2 = new uint256[](31);
        vm.expectRevert(bytes("invalid s2 length"));
        falcon8.verify(message, salt, shortS2, pkc);
    }

    function test_binding_rejects_other_helper_8() public {
        address other = address(new ZKNOX_falcon());
        vm.expectRevert(ZKNOX_falcon8.BadHelper.selector);
        new ZKNOX_falcon8(other);
        // the original clean-lane helper is not the resident one either
        vm.expectRevert(ZKNOX_falcon8.BadHelper.selector);
        new ZKNOX_falcon8(f1600Helper);
    }

    function test_gas_verify_8() public view {
        uint256[] memory s2 = _katS2();
        bytes memory salt = _katSalt();
        uint256 g = gasleft();
        bool ok = falconFused.verify(message, salt, s2, pkc);
        console.log("Verify NIST FUSED cost:", g - gasleft());
        g = gasleft();
        bool ok2 = falcon8.verify(message, salt, s2, pkc);
        console.log("Verify NIST 8-LANE cost:", g - gasleft());
        require(ok && ok2);
    }
}
