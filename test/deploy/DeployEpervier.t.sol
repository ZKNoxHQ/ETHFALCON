// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "../../lib/forge-std/src/Script.sol";
import "../../src/ZKNOX_epervier.sol";

import {console, Test} from "forge-std/Test.sol";

//deploy the precomputed tables for psirev and psiInvrev
contract Script_Deploy_psirev is Test {
    // SPDX-License-Identifier: MIT

    function test_run() external {
        bytes32 salty = keccak256(abi.encodePacked("ZKNOX_v0.14"));
      

        ZKNOX_epervier epervier = new ZKNOX_epervier{salt: salty}();


         // public key expected
        // forgefmt: disable-next-line
        address pk_0 = address(728199263750570446964354330903202655824594974439);

        // signature s1
        // forgefmt: disable-next-line
        uint[512] memory tmp_s1 = [uint(12149), 406,12233,111,12168,12134,11916,12251,12181,12276,12189,12121,32,12146,12191,148,189,14,58,12250,12033,12275,12192,87,155,173,284,92,11998,12279,238,12152,12248,335,11971,12192,90,12226,12225,12055,12197,150,61,303,12127,12272,190,12277,71,234,25,12192,12179,12115,225,119,195,100,12175,10,12097,334,12176,61,12165,52,190,12177,11959,12258,73,12264,255,12056,22,12171,12180,32,12098,109,116,12019,12068,12061,12168,124,5,115,12113,400,11877,96,12269,12200,11923,168,38,12,12234,12263,12284,5,242,199,12049,354,12219,11948,12286,68,12239,12204,13,255,12201,328,44,12203,12227,12,45,386,12282,124,12136,12041,12195,60,12152,29,223,12142,14,12175,12222,153,221,12092,197,12218,98,12136,11935,12055,45,73,12204,12286,216,12276,12008,127,12116,148,12276,12170,12250,202,11915,12169,12231,12184,12163,12170,39,12200,94,235,133,154,100,233,12276,168,87,67,65,12129,12280,12091,123,12046,12257,12137,12136,179,12041,172,12285,111,12203,12095,154,12230,291,12063,12186,12094,12222,12212,12060,11989,313,11885,419,12224,12274,27,12219,205,232,12059,69,12224,83,12152,41,212,12123,12102,22,224,12219,199,109,121,55,12172,12203,12207,12243,14,119,12198,12213,12015,12146,52,191,12226,113,12240,177,241,12138,11971,11969,60,12252,11822,78,47,12190,12159,173,11988,39,199,12255,187,229,12,12245,132,11988,12287,12130,12173,12176,12279,119,12250,12276,335,12012,12216,11998,36,11914,12237,89,335,12206,11997,58,12049,12083,12187,314,12077,72,12265,96,12177,12241,12056,12219,298,12274,12109,17,11998,125,12118,12210,49,12193,12025,90,12252,24,12270,12072,16,79,12222,48,99,12288,156,12258,12003,152,12259,12078,12126,12154,50,12194,12279,194,11908,30,12281,12154,12230,11996,12109,237,103,12261,12276,65,246,12084,80,108,12269,12119,5,12133,104,12091,142,12222,160,12125,100,29,70,59,24,283,12259,151,117,12273,12186,63,12090,12214,11983,12218,12163,12034,251,251,12143,409,12255,199,91,408,97,12223,11861,12157,12073,241,68,52,12084,12280,12227,123,12126,36,12259,12190,12212,12116,11940,2,12174,53,134,74,17,178,328,12254,33,122,65,188,0,68,105,12213,12235,158,69,12152,12251,19,12265,4,119,181,12256,185,109,250,12135,212,12150,12271,12163,50,12264,153,102,12021,52,87,12076,12161,27,1,12231,8,124,12218,12145,12242,12100,12268,12233,12268,19,11928,32,153,12192,4,75,112,12101,149,14,12221,71,138,12177,12168,28,12251,12225,78,61,160,12103,214,178,63,169,12182,8,11993,98,12164,400,12038,40,12101,20,12230,12259,11814,12156,11989,28,12056,26,12244,240,12182,313,193,184,12150,14];

        // signature s2
        // forgefmt: disable-next-line
        uint[512] memory tmp_s2 = [uint(223), 12256,12162,12138,12162,12134,23,12206,35,117,12239,12166,12262,49,91,321,104,91,163,119,12063,98,12142,190,12203,33,12146,12121,12172,12192,12167,32,12001,12255,12222,12250,12279,12230,12284,246,12265,140,12068,12276,12203,12164,12154,12155,141,12190,75,40,12140,12165,141,12063,12258,68,351,12123,12272,96,12179,96,174,12226,134,254,11891,194,12139,51,11999,12088,12236,12179,142,324,104,258,14,210,11913,12152,59,47,208,12179,50,11945,12045,140,23,11949,41,23,21,116,12242,12237,147,172,12107,12165,68,73,50,280,335,12193,12129,11996,40,64,45,12275,207,12104,135,12253,152,45,12165,290,521,185,108,11818,11998,12150,353,94,12025,12287,12228,58,68,12166,12202,98,347,12255,124,12202,11934,53,138,219,10,298,192,12258,12260,243,12156,12062,92,12286,220,279,132,185,12022,98,43,12189,33,12077,12034,12186,150,71,175,236,12167,12177,52,118,12103,12082,5,11998,11973,12143,73,182,12144,363,12163,12149,12282,12254,12188,12220,12038,12163,64,12114,12184,12230,12068,12234,12228,12171,133,156,12272,12196,12269,12022,12170,177,12251,158,42,374,9,12274,187,12163,131,159,54,12161,12175,118,23,133,319,70,12106,183,12130,10,158,12233,12140,111,12193,119,212,116,282,12225,96,12143,12146,12226,71,12200,63,116,12005,11926,12135,50,12283,12216,12137,24,255,12087,177,12258,12195,32,158,12166,52,12185,12262,65,37,60,252,12204,32,11809,388,55,10,12210,12072,12018,320,12285,132,12201,12249,67,12036,31,170,207,70,108,20,49,227,12227,11918,37,190,12147,12092,12232,25,151,129,87,103,135,12045,12270,104,12240,11918,151,20,26,12244,37,454,57,12182,12053,12159,12072,13,88,22,12277,12219,12186,12157,12178,309,12183,12119,12197,397,192,142,12242,12011,12103,12053,114,12130,12142,12221,12079,12159,12226,34,11939,36,12194,150,12223,12234,179,97,12175,64,90,92,258,12173,10,12274,12267,127,12284,59,140,180,139,261,173,12287,316,173,14,12194,12151,85,12065,12215,12047,333,12263,40,12087,12264,12031,12170,125,12244,12092,12032,12255,231,306,12073,12166,12104,12186,12168,11737,21,42,42,369,12249,52,12278,12232,286,399,41,128,311,115,61,12124,75,51,12190,12261,12036,115,12023,12213,12149,12185,12063,12059,0,12186,12276,210,247,197,128,244,12033,106,90,196,48,12212,191,100,12076,12260,5,79,11858,285,12251,12210,12282,137,12216,229,12009,119,12122,12277,12112,12054,93,163,12245,126,12096,12225,12169,12268,12072,12205,12082,12154,54,11971,12177,190,12120,12269,222,11823,12100,11896,12264,61,12156,12258,180,117,4,12278,12067,34,121,12275,260,12214,175,12118,144,12238];

        uint256[] memory s1 = new uint256[](512);
        uint256[] memory s2 = new uint256[](512);

        for (uint256 i = 0; i < 512; i++) {
            s1[i] = tmp_s1[i];
            s2[i] = tmp_s2[i];
        }

        uint256[] memory cs1 = _ZKNOX_NTT_Compact(s1);
        uint256[] memory cs2 = _ZKNOX_NTT_Compact(s2);

        // short hint
        uint256 hint = 11409;
        // message
        bytes memory message = "My name is Renaud";
        bytes memory salt =
            "\x46\xb9\xdd\x2b\x0b\xa8\x8d\x13\x23\x3b\x3f\xeb\x74\x3e\xeb\x24\x3f\xcd\x52\xea\x62\xb8\x1b\x82\xb5\x0c\x27\x64\x6e\xd5\x76\x2f\xd7\x5d\xc4\xdd\xd8\xc0\xf2\x00";
        address recovered_pk_0;
        recovered_pk_0 = epervier.recover(message, salt, cs1, cs2, hint);
        assertEq(pk_0, recovered_pk_0);
    }
}
