/**
 *
 */
/*ZZZZZZZZZZZZZZZZZZZKKKKKKKKK    KKKKKKKNNNNNNNN        NNNNNNNN     OOOOOOOOO     XXXXXXX       XXXXXXX                         ..../&@&#.       .###%@@@#, ..                         
/*Z:::::::::::::::::ZK:::::::K    K:::::KN:::::::N       N::::::N   OO:::::::::OO   X:::::X       X:::::X                      ...(@@* .... .           &#//%@@&,.                       
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::::N      N::::::N OO:::::::::::::OO X:::::X       X:::::X                    ..*@@.........              .@#%%(%&@&..                    
/*Z:::ZZZZZZZZ:::::Z K:::::::K   K::::::KN:::::::::N     N::::::NO:::::::OOO:::::::OX::::::X     X::::::X                   .*@( ........ .  .&@@@@.      .@%%%%%#&@@.                  
/*ZZZZZ     Z:::::Z  KK::::::K  K:::::KKKN::::::::::N    N::::::NO::::::O   O::::::OXXX:::::X   X::::::XX                ...&@ ......... .  &.     .@      /@%%%%%%&@@#                  
/*        Z:::::Z      K:::::K K:::::K   N:::::::::::N   N::::::NO:::::O     O:::::O   X:::::X X:::::X                   ..@( .......... .  &.     ,&      /@%%%%&&&&@@@.              
/*       Z:::::Z       K::::::K:::::K    N:::::::N::::N  N::::::NO:::::O     O:::::O    X:::::X:::::X                   ..&% ...........     .@%(#@#      ,@%%%%&&&&&@@@%.               
/*      Z:::::Z        K:::::::::::K     N::::::N N::::N N::::::NO:::::O     O:::::O     X:::::::::X                   ..,@ ............                 *@%%%&%&&&&&&@@@.               
/*     Z:::::Z         K:::::::::::K     N::::::N  N::::N:::::::NO:::::O     O:::::O     X:::::::::X                  ..(@ .............             ,#@&&&&&&&&&&&&@@@@*               
/*    Z:::::Z          K::::::K:::::K    N::::::N   N:::::::::::NO:::::O     O:::::O    X:::::X:::::X                   .*@..............  . ..,(%&@@&&&&&&&&&&&&&&&&@@@@,               
/*   Z:::::Z           K:::::K K:::::K   N::::::N    N::::::::::NO:::::O     O:::::O   X:::::X X:::::X                 ...&#............. *@@&&&&&&&&&&&&&&&&&&&&@@&@@@@&                
/*ZZZ:::::Z     ZZZZZKK::::::K  K:::::KKKN::::::N     N:::::::::NO::::::O   O::::::OXXX:::::X   X::::::XX               ...@/.......... *@@@@. ,@@.  &@&&&&&&@@@@@@@@@@@.               
/*Z::::::ZZZZZZZZ:::ZK:::::::K   K::::::KN::::::N      N::::::::NO:::::::OOO:::::::OX::::::X     X::::::X               ....&#..........@@@, *@@&&&@% .@@@@@@@@@@@@@@@&                  
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::N       N:::::::N OO:::::::::::::OO X:::::X       X:::::X                ....*@.,......,@@@...@@@@@@&..%@@@@@@@@@@@@@/                   
/*Z:::::::::::::::::ZK:::::::K    K:::::KN::::::N        N::::::N   OO:::::::::OO   X:::::X       X:::::X                   ...*@,,.....%@@@,.........%@@@@@@@@@@@@(                     
/*ZZZZZZZZZZZZZZZZZZZKKKKKKKKK    KKKKKKKNNNNNNNN         NNNNNNN     OOOOOOOOO     XXXXXXX       XXXXXXX                      ...&@,....*@@@@@ ..,@@@@@@@@@@@@@&.                     
/*                                                                                                                                   ....,(&@@&..,,,/@&#*. .                             
/*                                                                                                                                    ......(&.,.,,/&@,.                                
/*                                                                                                                                      .....,%*.,*@%                               
/*                                                                                                                                    .#@@@&(&@*,,*@@%,..                               
/*                                                                                                                                    .##,,,**$.,,*@@@@@%.                               
/*                                                                                                                                     *(%%&&@(,,**@@@@@&                              
/*                                                                                                                                      . .  .#@((@@(*,**                                
/*                                                                                                                                             . (*. .                                   
/*                                                                                                                                              .*/
///* Copyright (C) 2025 - Renaud Dubois, Simon Masson - This file is part of ZKNOX project
///* License: This software is licensed under MIT License
///* This Code may be reused including this header, license and copyright notice.
///* See LICENSE file at the root folder of the project.
///* FILE: ZKNOX_falcon_encodings.sol
///* Description: Decompression function of falcon verification
/**
 *
 */

// code generated using pythonref/generate_falcon_epervier_shorter_zknox_test_vectors.py.
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_falcon_encodings.sol";

contract Encodings_Test is Test {
    function test_encodings_decompress() public view {
        // forgefmt: disable-next-line
        bytes memory compressed_s1=hex"5f687ff977ff368bf4e4775d97ef3731add04b456e46bbf8962c9a7ceb4871ed43ebe1fd4834068b87a7c56ef0b7666218eeb1bd6fee1d86435e3a5ca32afe435e267e895f34cc8d83dd609737f065f98e14265933d11c96d7dd0e510b440887549f83129dcbea0f74cbb07d10c45fa84a62f15ba6bf69134b1b67f2894999460a79e0d034a4a2812dc753db941da48c25bfc9110909cad9d71a3316b095ec4182decea89fbebd8ab668af9d7f1935852b6854a8a033f9db9b0af1ab983ae22e4113962cb14afc921ea3fef3c594797ad8fd7c26976dd39e82e8cde1925266cc8ad67fb18c3e8fcbc5fdbfd40d7bd3bbeeb6fbdfb4151c647bb94c59f798b4d1e4aaec4271f3b7fa068fa6d807caed1782a7e51b6e9bb3e85479b8caadfe0bbd51748d1c0b06498f6fe8fd99fdd3387accd26586e4e6118bfb9498b3fde90479fb9a7a3374192cf2f8eac83c020826f0ae7f658f28061208ec6a287fd47e54a7a8d6c8a4c6c6df7cc92cf98e715b98cc5d0155ecf077d193b46c7e645d148d6b64b46139f5fb1827650dac45b19c6f3e11ef9a9ead53b90d140439afcb1ba7b172cfb26e2749826fe45de249df8b385b799ac3f2a056ab9023e90ac7e5aff859dc313442d0525ac14f096a1ddfc52abe072be4a699a9472999c11f7beeb78ac09a2b3a64761fbdcbcff9d40456552ab89a89a62f731e21e253004dcb9cf74aa5ccfc79cfeae78a3998c7a3c4f3201e7c6d4977515005d1802d55aa2261cd9fac9d56760b4fd788e9a6e7e1e12e4d95982efa763362f5abb236b2fdc1703f195ecba9cf61d36df1f09f352ca579d21bd6246667b8567e68bac1317de48af38e821cb97b5688367000000000000000000000";
        // forgefmt: disable-next-line
        int[512] memory decompressed_s1=  [int(223), -33, -127, -151, -127, -155, 23, -83, 35, 117, -50, -123, -27, 49, 91, 321, 104, 91, 163, 119, -226, 98, -147, 190, -86, 33, -143, -168, -117, -97, -122, 32, -288, -34, -67, -39, -10, -59, -5, 246, -24, 140, -221, -13, -86, -125, -135, -134, 141, -99, 75, 40, -149, -124, 141, -226, -31, 68, 351, -166, -17, 96, -110, 96, 174, -63, 134, 254, -398, 194, -150, 51, -290, -201, -53, -110, 142, 324, 104, 258, 14, 210, -376, -137, 59, 47, 208, -110, 50, -344, -244, 140, 23, -340, 41, 23, 21, 116, -47, -52, 147, 172, -182, -124, 68, 73, 50, 280, 335, -96, -160, -293, 40, 64, 45, -14, 207, -185, 135, -36, 152, 45, -124, 290, 521, 185, 108, -471, -291, -139, 353, 94, -264, -2, -61, 58, 68, -123, -87, 98, 347, -34, 124, -87, -355, 53, 138, 219, 10, 298, 192, -31, -29, 243, -133, -227, 92, -3, 220, 279, 132, 185, -267, 98, 43, -100, 33, -212, -255, -103, 150, 71, 175, 236, -122, -112, 52, 118, -186, -207, 5, -291, -316, -146, 73, 182, -145, 363, -126, -140, -7, -35, -101, -69, -251, -126, 64, -175, -105, -59, -221, -55, -61, -118, 133, 156, -17, -93, -20, -267, -119, 177, -38, 158, 42, 374, 9, -15, 187, -126, 131, 159, 54, -128, -114, 118, 23, 133, 319, 70, -183, 183, -159, 10, 158, -56, -149, 111, -96, 119, 212, 116, 282, -64, 96, -146, -143, -63, 71, -89, 63, 116, -284, -363, -154, 50, -6, -73, -152, 24, 255, -202, 177, -31, -94, 32, 158, -123, 52, -104, -27, 65, 37, 60, 252, -85, 32, -480, 388, 55, 10, -79, -217, -271, 320, -4, 132, -88, -40, 67, -253, 31, 170, 207, 70, 108, 20, 49, 227, -62, -371, 37, 190, -142, -197, -57, 25, 151, 129, 87, 103, 135, -244, -19, 104, -49, -371, 151, 20, 26, -45, 37, 454, 57, -107, -236, -130, -217, 13, 88, 22, -12, -70, -103, -132, -111, 309, -106, -170, -92, 397, 192, 142, -47, -278, -186, -236, 114, -159, -147, -68, -210, -130, -63, 34, -350, 36, -95, 150, -66, -55, 179, 97, -114, 64, 90, 92, 258, -116, 10, -15, -22, 127, -5, 59, 140, 180, 139, 261, 173, -2, 316, 173, 14, -95, -138, 85, -224, -74, -242, 333, -26, 40, -202, -25, -258, -119, 125, -45, -197, -257, -34, 231, 306, -216, -123, -185, -103, -121, -552, 21, 42, 42, 369, -40, 52, -11, -57, 286, 399, 41, 128, 311, 115, 61, -165, 75, 51, -99, -28, -253, 115, -266, -76, -140, -104, -226, -230, 0, -103, -13, 210, 247, 197, 128, 244, -256, 106, 90, 196, 48, -77, 191, 100, -213, -29, 5, 79, -431, 285, -38, -79, -7, 137, -73, 229, -280, 119, -167, -12, -177, -235, 93, 163, -44, 126, -193, -64, -120, -21, -217, -84, -207, -135, 54, -318, -112, 190, -169, -20, 222, -466, -189, -393, -25, 61, -133, -31, 180, 117, 4, -11, -222, 34, 121, -14, 260, -75, 175, -171, 144, -51];

        uint256[512] memory expected_s1;
        for (uint256 i = 0; i < 512; i++) {
            if (decompressed_s1[i] < 0) {
                expected_s1[i] = uint256(int256(q) + (decompressed_s1[i]));
            } else {
                expected_s1[i] = uint256(decompressed_s1[i]);
            }
        }

        uint256 gasStart = gasleft();
        uint256[] memory res = _decompress_sig(compressed_s1, 0);
        uint256 gasUsed = gasStart - gasleft();

        console.log("gas used by decompress:", gasUsed);

        for (uint256 i = 0; i < 512; i++) {
            assertEq(expected_s1[i], res[i]);
        }
    }

    //kat vector 0 from NIST submission
    function test_encodings_decompress_kat() public {
        // forgefmt: disable-next-line
        bytes memory pk=hex"096BA86CB658A8F445C9A5E4C28374BEC879C8655F68526923240918074D0147C03162E4A49200648C652803C6FD7509AE9AA799D6310D0BD42724E0635920186207000767CA5A8546B1755308C304B84FC93B069E265985B398D6B834698287FF829AA820F17A7F4226AB21F601EBD7175226BAB256D8888F009032566D6383D68457EA155A94301870D589C678ED304259E9D37B193BC2A7CCBCBEC51D69158C44073AEC9792630253318BC954DBF50D15028290DC2D309C7B7B02A6823744D463DA17749595CB77E6D16D20D1B4C3AAD89D320EBE5A672BB96D6CD5C1EFEC8B811200CBB062E473352540EDDEF8AF9499F8CDD1DC7C6873F0C7A6BCB7097560271F946849B7F373640BB69CA9B518AA380A6EB0A7275EE84E9C221AED88F5BFBAF43A3EDE8E6AA42558104FAF800E018441930376C6F6E751569971F47ADBCA5CA00C801988F317A18722A29298925EA154DBC9024E120524A2D41DC0F18FD8D909F6C50977404E201767078BA9A1F9E40A8B2BA9C01B7DA3A0B73A4C2A6B4F518BBEE3455D0AF2204DDC031C805C72CCB647940B1E6794D859AAEBCEA0DEB581D61B9248BD9697B5CB974A8176E8F910469CAE0AB4ED92D2AEE9F7EB50296DAF8057476305C1189D1D9840A0944F0447FB81E511420E67891B98FA6C257034D5A063437D379177CE8D3FA6EAF12E2DBB7EB8E498481612B1929617DA5FB45E4CDF893927D8BA842AA861D9C50471C6D0C6DF7E2BB26465A0EB6A3A709DE792AAFAAF922AA95DD5920B72B4B8856C6E632860B10F5CC08450003671AF388961872B466400ADB815BA81EA794945D19A100622A6CA0D41C4EA620C21DC125119E372418F04402D9FA7180F7BC89AFA54F8082244A42F46E5B5ABCE87B50A7D6FEBE8D7BBBAC92657CBDA1DB7C25572A4C1D0BAEA30447A865A2B1036B880037E2F4D26D453E9E913259779E9169B28A62EB809A5C744E04E260E1F2BBDA874F1AC674839DDB47B3148C5946DE0180148B7973D63C58193B17CD05D16E80CD7928C2A338363A23A81C0608C87505589B9DA1C617E7B70786B6754FBB30A5816810B9E126CFCC5AA49326E9D842973874B6359B5DB75610BA68A98C7B5E83F125A82522E13B83FB8F864E2A97B73B5D544A7415B6504A13939EAB1595D64FAF41FAB25A864A574DE524405E878339877886D2FC07FA0311508252413EDFA1158466667AFF78386DAF7CB4C9B850992F96E20525330599AB601D454688E294C8C3E";
        // forgefmt: disable-next-line
        bytes memory sm=hex"026833B3C07507E4201748494D832B6EE2A6C93BFF9B0EE343B550D1F85A3D0DE0D704C6D17842951309D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8290765843D1E460D17A527D2BCA405BD55BBC7DA09A8C620BE0AF4A767D9DB96B80F55E466676751EAABA7B93B86D71132DAA0EB376782B9EEE37519CE10FDD33FE9F29312C31D8736206D165CF4C528AA3DDC017845E1F0DD5B0A44FF961C42D874A95533E5B438982F524CA954D87533BFBE42C63FF2ABC77A34C79DB55A99171BBCB72C842A6530AF2F753F0C34AC632F9F1E7949F0BF6C67665B27722A8857D626B6FF1A136D923A39F4069B7477FF946E5247A6627791D49B59EDC9E2525A860E6E9828D18F64A9F17222E8166A02453859BBDA0B8186D8C9928BB571E4146401D7430E225904673AD21CCAC54C146C248A1DD69AB6491E901D6D71B152155BE97DE057F3916A3F1B4273308C29B2F4D9697167B90681B1583ED930A71E990467DEA368134BECEEBD597F9BEC922E816F1B0570D728F4AE0464C1F797657F87A4E52DCDCAEB9272662EA66D7C6CD8781B31AF555AD93F5F65E75816CB8DC306BB67E592B5261BACA7C509629EA2AF8ABB80CBA89EE535B76DFD9CCBBE3BF48F2BC8AA34B26E1103291053F5CB8DE3A45AFA5A76DF8B2122ED2C82FBCF2259290D41A14F86B12F35F5D49762B34CFF13EE7E42EDEC70201D7F37C33316288FA3078E36E58108865C3CFE263D563692043DECC62F3426F86061285B7B1B336F56FF41BB65E9CD6D9B92FD90F864AA1C923CB8C755F5CDE1770D862595427149D7721AAAB5D194AEA9ACDECA15BE43CBA6A62B5A33909E9FC4DA1C5814FBD7CD6A2FA572E318B42C6C319140B86E66392580A11A2B431F44C1F9270E4F7B2490F3B325A9977A71A575915636635B9969DBD6D220B24C3D99CEBBBD834B88222BD08C3ABE124E80";

        uint256[] memory h;
        uint256[] memory s2;
        bytes memory salt;
        bytes memory message;

        (h, s2, salt, message) = decompress_KAT(pk, sm);
    }
}
