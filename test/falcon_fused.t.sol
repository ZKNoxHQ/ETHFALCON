// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon.sol";
import "../src/ZKNOX_falcon_turbo.sol";
import "../src/ZKNOX_falcon_fused.sol";
import "../src/ZKNOX_falcon_core.sol";
import "../src/ZKNOX_falcon_core_fused.sol";
import "../src/ZKNOX_HashToPoint_packed.sol";
import "../src/ZKNOX_shake_fast.sol";
import "../src/ZKNOX_NTT_falcon_fused.sol";

/// End-to-end tests of the fused verifier: the packed hash-to-point against
/// hashToPointNISTFast, falcon_core_fused against falcon_core on both sides of
/// the norm bound, the KAT vector, and the helper binding.
contract FalconFusedTest is Test {
    ZKNOX_falcon falcon;
    ZKNOX_falcon_turbo falconTurbo;
    ZKNOX_falcon_fused falconFused;
    address f1600Helper;

    // forgefmt: disable-next-line
    uint256[] pkc = [5662797900309780854973796610500849947334657117880689816302353465126500706865, 19773102689601973621062070293263100534733440101750387150077711329493973274058, 14606681890476865709816748627007131256488820167404174518724605890405097603719, 15845234755931409677594030697035096324340457247480758851130851814703350289524, 5524941775098342886171484209767745714294893760953145782448900256027476885810, 15301033023652038200658165594502048003364566882283859976805808429697192567788, 18875246040654000517074755552890901133645669291006567534900678519700207707731, 11843395683334522200668269515783436692309636627649985746204914551011013629864, 8419305811746464065544475584323153271481428319969733938911379662274846467111, 18343417927809591481517183183479503623951147924071925629514120039495430967592, 10007451325105194000131443764495043320645967197761209321537835667210153693191, 779487061150515667795843171268512499191273448454307717194241961063365614179, 14889466660684110621550004892629051623956217990147793956971155241422811501259, 2995124819739638247263964985959552967489690950312509006670204449438399867779, 16698797261630410217796026169071784061995015858612862963622742163763641855864, 13129716852402613948762495927854872029721399215764359316540986925328111906305, 8620514528683669238836845045565231437047299941974001946945409334379184590766, 5184181041252042291984928267300200431567362250531180743278111084485128161037, 15555356690664302555826193017277818624355238475260445618945780405430020481200, 19264077329172342356817033544893125657281034846341493111114385757819435942150, 8708853592016768361541207473719404660232059936330605270802350059910738161396, 21018648773068189736719755689803981281912117625241701774409626083005150670687, 267026197077955750670312407002345619518873569178283514941902712705828521229, 14359242962640593260752841229079220345384234239741953227891227234975247894859, 8320354099602406351863744856415421903486499003224102136141447162113864442068, 17564344674783852357247325589247473882830766139750808683064015010041459773180, 12601232530472338126510941067000966999586933909071534455578397454667291628041, 17820703520112071877812607241017358905719406745793395857586668204300579510382, 20977963461796112341763752649093803701879441191599296283127418471622134932903, 5627732773047409045458881938100601008133088383905060686572856121439798106767, 2602661464000108367786729796742170641292899005030508211661215565063118195399, 20110282897068872581106488251090599973196923955248066799683528955504800771309];
    bytes message =
        "\x4d\x79\x20\x6e\x61\x6d\x65\x20\x69\x73\x20\x52\x65\x6e\x61\x75\x64\x20\x66\x72\x6f\x6d\x20\x5a\x4b\x4e\x4f\x58\x21\x21\x21\x21";

    function setUp() public {
        falcon = new ZKNOX_falcon();
        string[] memory cmds = new string[](2);
        cmds[0] = "cat";
        cmds[1] = "test/f1600_170.hex";
        bytes memory runtime = vm.ffi(cmds);
        bytes memory initCode = abi.encodePacked(hex"61", uint16(runtime.length), hex"8061000b5f395ff3", runtime);
        address helper;
        assembly {
            helper := create(0, add(initCode, 32), mload(initCode))
        }
        require(helper != address(0), "f1600-170: CREATE failed");
        f1600Helper = helper;
        falconTurbo = new ZKNOX_falcon_turbo(helper);
        falconFused = new ZKNOX_falcon_fused(helper);
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

    // ---- hash-to-point -------------------------------------------------------

    function _assertPackedEq(uint256[] memory packed, uint256[] memory expanded) internal pure {
        require(packed.length == 128 && expanded.length == 512, "lengths");
        for (uint256 i = 0; i < 512; i++) {
            require((packed[i >> 2] >> (64 * (i & 3))) & 0xffffffffffffffff == expanded[i], "packed hash differs");
        }
    }

    function test_hashToPointPacked_matches_fast_kat() public view {
        bytes memory salt = _katSalt();
        _assertPackedEq(
            hashToPointNISTPacked(salt, message, f1600Helper), hashToPointNISTFast(salt, message, f1600Helper)
        );
        // the vector of testBenchHashToPointNIST: first and last coefficients
        bytes memory salt2 =
            "\x4b\x09\x9f\x8e\x30\x0f\x01\xb8\x65\x0f\x1f\x4b\x1d\x8f\xcf\x3f\x3c\xb5\x3f\xb8\xe9\xeb\x2e\xa2\x03\xbd\xc9\x70\xf5\x0a\xe5\x54\x28\xa9\x1f\x7f\x53\xac\x26\x6b";
        uint256[] memory hp = hashToPointNISTPacked(salt2, message, f1600Helper);
        assertEq(hp[0] & 0xffffffffffffffff, 2578);
        assertEq(hp[127] >> 192, 11296);
        _assertPackedEq(hp, hashToPointNISTFast(salt2, message, f1600Helper));
    }

    function testFuzz_hashToPointPacked_matches_fast(bytes32 a, bytes32 b, bytes32 m) public view {
        bytes memory salt = abi.encodePacked(a, bytes8(b));
        bytes memory msgHash = abi.encodePacked(m);
        _assertPackedEq(
            hashToPointNISTPacked(salt, msgHash, f1600Helper), hashToPointNISTFast(salt, msgHash, f1600Helper)
        );
    }

    /// messages of assorted lengths (absorb padding paths)
    function test_hashToPointPacked_lengths() public view {
        bytes memory salt = _katSalt();
        for (uint256 len = 0; len < 300; len += 37) {
            bytes memory m = new bytes(len);
            for (uint256 i = 0; i < len; i++) {
                m[i] = bytes1(uint8(i * 7 + len));
            }
            _assertPackedEq(hashToPointNISTPacked(salt, m, f1600Helper), hashToPointNISTFast(salt, m, f1600Helper));
        }
    }

    // ---- core, both sides of the bound --------------------------------------

    function _lane(uint256 w, uint256 j) internal pure returns (uint256) {
        return (w >> (64 * j)) & 0xffffffffffffffff;
    }

    /// s2 with small centred coefficients, so that ||s2||^2 alone is under the bound
    function _smallCompact(uint256 seed, uint256 amp) internal pure returns (uint256[] memory c) {
        c = new uint256[](32);
        for (uint256 i = 0; i < 32; i++) {
            uint256 w;
            for (uint256 j = 0; j < 16; j++) {
                uint256 r = uint256(keccak256(abi.encodePacked(seed, i, j)));
                uint256 mag = r % (amp + 1);
                uint256 coeff = (r >> 128) & 1 == 1 ? (q - mag) % q : mag;
                w |= coeff << (16 * j);
            }
            c[i] = w;
        }
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

    /// builds hashed = s1 + e with ||e||^2 = about eNorm, returns it packed and expanded
    function _hashedAround(uint256[] memory s1, uint256 seed, uint256 amp)
        internal
        pure
        returns (uint256[] memory packed, uint256[] memory expanded)
    {
        packed = new uint256[](128);
        expanded = new uint256[](512);
        for (uint256 i = 0; i < 512; i++) {
            uint256 r = uint256(keccak256(abi.encodePacked(seed, i)));
            uint256 mag = r % (amp + 1);
            uint256 e = (r >> 128) & 1 == 1 ? (q - mag) % q : mag;
            uint256 h = addmod(_lane(s1[i >> 2], i & 3), e, q);
            expanded[i] = h;
            packed[i >> 2] |= h << (64 * (i & 3));
        }
    }

    function _bothCores(uint256[] memory s2, uint256[] memory ntth, uint256[] memory packed, uint256[] memory expanded)
        internal
        pure
        returns (bool ref, bool fused)
    {
        ref = falcon_core(s2, ntth, expanded);
        fused = falcon_core_fused(s2, ntth, packed);
    }

    function test_core_accepts_and_rejects_like_reference() public pure {
        uint256 accepted;
        uint256 rejected;
        for (uint256 s = 0; s < 12; s++) {
            uint256[] memory s2 = _smallCompact(s, 150);
            uint256[] memory ntth = _compact(1000 + s);
            uint256[] memory s1 = _nttInvFusedMul(_nttFwFused(s2), ntth);
            // error amplitude sweeping across the bound: ||e||^2 ~ 512 * amp^2 / 3, sigBound = 34034726
            for (uint256 amp = 100; amp <= 700; amp += 60) {
                (uint256[] memory packed, uint256[] memory expanded) = _hashedAround(s1, s * 31 + amp, amp);
                (bool ref, bool fused) = _bothCores(s2, ntth, packed, expanded);
                require(ref == fused, "core decision differs");
                if (ref) accepted++;
                else rejected++;
            }
        }
        require(accepted > 0 && rejected > 0, "sweep did not cross the bound");
    }

    function testFuzz_core_matches_reference(uint256 seed, uint16 amp) public pure {
        uint256 a = 60 + (uint256(amp) % 400);
        uint256[] memory s2 = _smallCompact(seed, 120);
        uint256[] memory ntth = _compact(seed ^ 0xabcdef);
        uint256[] memory s1 = _nttInvFusedMul(_nttFwFused(s2), ntth);
        (uint256[] memory packed, uint256[] memory expanded) = _hashedAround(s1, seed ^ 1, a);
        (bool ref, bool fused) = _bothCores(s2, ntth, packed, expanded);
        require(ref == fused, "core decision differs");
    }

    /// random inputs: both reject (norm far above the bound)
    function testFuzz_core_random_inputs(uint256 seed) public pure {
        uint256[] memory s2 = _compact(seed);
        uint256[] memory ntth = _compact(seed ^ 1);
        uint256[] memory expanded = new uint256[](512);
        uint256[] memory packed = new uint256[](128);
        for (uint256 i = 0; i < 512; i++) {
            uint256 h = uint256(keccak256(abi.encodePacked(seed, i))) % q;
            expanded[i] = h;
            packed[i >> 2] |= h << (64 * (i & 3));
        }
        (bool ref, bool fused) = _bothCores(s2, ntth, packed, expanded);
        require(ref == fused && !fused, "random inputs must be rejected by both");
    }

    /// exact boundary: norm == sigBound accepted, sigBound + 1 rejected
    function test_core_exact_bound() public pure {
        // s2 = 0 except two coefficients, ntth arbitrary => s1 = INTT(NTT(s2) * ntth)
        uint256[] memory s2 = new uint256[](32);
        uint256[] memory ntth = _compact(77);
        uint256[] memory s1 = _nttInvFusedMul(_nttFwFused(s2), ntth); // = 0
        // error: one coefficient carrying the whole budget: 34034726 = 5833^2 + 5 * ... use sqrt decomposition
        // 5833^2 = 34023889, remainder 10837 = 104^2 + 21 = 104^2 + 4^2 + 2^2 + 1^2 (10816 + 16 + 4 + 1 = 10837)
        uint256[5] memory e = [uint256(5833), 104, 4, 2, 1];
        uint256[] memory packed = new uint256[](128);
        uint256[] memory expanded = new uint256[](512);
        for (uint256 i = 0; i < 5; i++) {
            expanded[i] = e[i];
            packed[0] |= e[i] << (64 * (i & 3));
        }
        packed[1] |= e[4];
        // packed[0] holds e0..e3 in lanes 0..3, packed[1] lane 0 holds e4
        s1;
        (bool ref, bool fused) = _bothCores(s2, ntth, packed, expanded);
        require(ref && fused, "norm == sigBound must be accepted");
        // bump one unit: e4 = 1 -> 2 adds 3 => norm = sigBound + 3
        expanded[4] = 2;
        packed[1] = 2;
        (ref, fused) = _bothCores(s2, ntth, packed, expanded);
        require(!ref && !fused, "norm > sigBound must be rejected");
    }

    /// a coefficient >= q in s2 must be rejected even with a small norm
    function test_core_rejects_out_of_range_s2() public pure {
        uint256[] memory s2 = new uint256[](32);
        uint256[] memory ntth = _compact(5);
        uint256[] memory packed = new uint256[](128);
        uint256[] memory expanded = new uint256[](512);
        s2[3] = uint256(q) << 32; // coefficient == q, i.e. -0: norm contribution 0 in a naive centring
        // the reference computes s1 from s2 via its own NTT; build hashed = its s1 so only the range check bites
        uint256[] memory s1ref = _ZKNOX_NTT_Expand(_ZKNOX_NTT_HALFMUL_Compact(s2, ntth));
        for (uint256 i = 0; i < 512; i++) {
            expanded[i] = s1ref[i];
            packed[i >> 2] |= s1ref[i] << (64 * (i & 3));
        }
        (bool ref, bool fused) = _bothCores(s2, ntth, packed, expanded);
        require(!ref && !fused, "out-of-range s2 must be rejected");
    }

    // ---- verify ----------------------------------------------------------------

    function test_verify_kat() public view {
        uint256[] memory s2 = _katS2();
        bytes memory salt = _katSalt();
        assertTrue(falcon.verify(message, salt, s2, pkc));
        assertTrue(falconTurbo.verify(message, salt, s2, pkc));
        assertTrue(falconFused.verify(message, salt, s2, pkc));

        // flipped signature bit
        uint256[] memory bad = _katS2();
        bad[7] ^= 1 << 96;
        assertFalse(falconFused.verify(message, salt, bad, pkc));
        // wrong message
        bytes memory m2 = abi.encodePacked(message);
        m2[0] = 0x00;
        assertFalse(falconFused.verify(m2, salt, s2, pkc));
        // wrong salt
        bytes memory salt2 = abi.encodePacked(salt);
        salt2[39] ^= 0x01;
        assertFalse(falconFused.verify(message, salt2, s2, pkc));
    }

    function test_verify_length_checks() public {
        uint256[] memory s2 = _katS2();
        bytes memory salt = _katSalt();
        vm.expectRevert(bytes("invalid salt length"));
        falconFused.verify(message, abi.encodePacked(salt, bytes1(0)), s2, pkc);
        uint256[] memory shortS2 = new uint256[](31);
        vm.expectRevert(bytes("invalid s2 length"));
        falconFused.verify(message, salt, shortS2, pkc);
        uint256[] memory shortPk = new uint256[](31);
        vm.expectRevert(bytes("invalid ntth length"));
        falconFused.verify(message, salt, s2, shortPk);
    }

    function test_verify_random_signature_rejected() public view {
        uint256[] memory s2 = _compact(99);
        assertFalse(falconFused.verify(message, _katSalt(), s2, pkc));
    }

    function test_binding_rejects_other_helper() public {
        address other = address(new ZKNOX_falcon());
        vm.expectRevert(ZKNOX_falcon_fused.BadHelper.selector);
        new ZKNOX_falcon_fused(other);
        vm.expectRevert(ZKNOX_falcon_fused.BadHelper.selector);
        new ZKNOX_falcon_fused(address(0xdead));
    }

    // ---- gas ---------------------------------------------------------------------

    function test_gas_verify_fused() public view {
        uint256[] memory s2 = _katS2();
        bytes memory salt = _katSalt();
        uint256 g = gasleft();
        bool ok = falconTurbo.verify(message, salt, s2, pkc);
        console.log("Verify NIST TURBO cost:", g - gasleft());
        g = gasleft();
        bool ok2 = falconFused.verify(message, salt, s2, pkc);
        console.log("Verify NIST FUSED cost:", g - gasleft());
        require(ok && ok2);
    }

    function test_gas_components_fused() public view {
        uint256[] memory s2 = _katS2();
        bytes memory salt = _katSalt();
        uint256 g = gasleft();
        uint256[] memory hp = hashToPointNISTPacked(salt, message, f1600Helper);
        console.log("NIST HashToPoint PACKED (fresh mem):", g - gasleft());
        g = gasleft();
        bool ok = falcon_core_fused(s2, pkc, hp);
        console.log("Falcon core FUSED:                 ", g - gasleft());
        require(ok);
    }
}
