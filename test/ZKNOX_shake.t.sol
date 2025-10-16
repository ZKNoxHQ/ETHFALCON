// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

import "../src/ZKNOX_shake.sol";
import {Test, console} from "forge-std/Test.sol";

contract ZKNOX_ShakeTest is Test {
    function test_shake_F1600Zero() public view {
        uint64[25] memory zeroes = [uint64(0), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // forgefmt: disable-next-line
        uint64[25] memory TEST_F1600_ZERO = [
            0xF1258F7940E1DDE7,
            0x84D5CCF933C0478A,
            0xD598261EA65AA9EE,
            0xBD1547306F80494D,
            0x8B284E056253D057,
            0xFF97A42D7F8E6FD4,
            0x90FEE5A0A44647C4,
            0x8C5BDA0CD6192E76,
            0xAD30A6F71B19059C,
            0x30935AB7D08FFC64,
            0xEB5AA93F2317D635,
            0xA9A6E6260D712103,
            0x81A57C16DBCF555F,
            0x43B831CD0347C826,
            0x01F22F1A11A5569F,
            0x05E5635A21D9AE61,
            0x64BEFEF28CC970F2,
            0x613670957BC46611,
            0xB87C5A554FD00ECB,
            0x8C3EE88A1CCF32C8,
            0x940C7922AE3A2614,
            0x1841F924A2C509E4,
            0x16F53526E70465C2,
            0x75F644E97F30A13B,
            0xEAF1FF7B5CECA249
        ];

        uint64[25] memory res = F1600(zeroes);

        for (uint256 i = 0; i < 25; i++) {
            assertEq(res[i], TEST_F1600_ZERO[i]);
        }
    }

    function test_absorb() public pure {
        uint64[25] memory state;
        uint8[200] memory buff;
        uint256 offset;

        //vector of size 136 from official kats
        bytes memory message =
            hex"B32D95B0B9AAD2A8816DE6D06D1F86008505BD8C14124F6E9A163B5A2ADE55F835D0EC3880EF50700D3B25E42CC0AF050CCD1BE5E555B23087E04D7BF9813622780C7313A1954F8740B6EE2D3F71F768DD417F520482BD3A08D4F222B4EE9DBD015447B33507DD50F3AB4247C5DE9A8ABD62A8DECEA01E3B87C8B927F5B08BEB37674C6F8E380C04";

        // forgefmt: disable-next-line
        uint64[25] memory expected=[0xf2a3a3057654e665,0xce044847fc85f48e,  0xec3bd70f31a2866a,  0x7bada64d3aa28d05,  0xdf2d6ae3aa215523,  0x18b3f802c1c29a3f,  0x6044c64141c18ca1,  0x867be8cca2f1a54,  0x73773b337ce4e5eb,  0x7b8b093e6cc376c6,  0x3ed5eb2ef9295a2a,  0xd6ab08c040f891d2,  0x329ec3f446ae8bc6,  0x21ce09a9142a7a7d,  0xc5d90ada910c2965,  0xefa939add08954f4,  0xdfd33eee70e98a5a,  0x69c21fbc22c1f12a,  0x99e8f946ed7c1708,  0xc47ef08b0c9f3f9f,  0x5a102b80ec0fb414,  0x52d66d1377cf6219,  0x3a79068ab1f1288,  0x17a59fb049fd9130,  0x9fccb95c262e9e76];

        (offset, buff, state) = shake_absorb(0, buff, state, message);

        for (uint256 i = 0; i < 25; i++) {
            assertEq(state[i], expected[i]);
        }
    }

    function test_update() public pure {
        ctx_shake memory ctx;// forgefmt: disable-next-line
        uint64[25] memory expected=[0xf2a3a3057654e665,0xce044847fc85f48e,  0xec3bd70f31a2866a,  0x7bada64d3aa28d05,  0xdf2d6ae3aa215523,  0x18b3f802c1c29a3f,  0x6044c64141c18ca1,  0x867be8cca2f1a54,  0x73773b337ce4e5eb,  0x7b8b093e6cc376c6,  0x3ed5eb2ef9295a2a,  0xd6ab08c040f891d2,  0x329ec3f446ae8bc6,  0x21ce09a9142a7a7d,  0xc5d90ada910c2965,  0xefa939add08954f4,  0xdfd33eee70e98a5a,  0x69c21fbc22c1f12a,  0x99e8f946ed7c1708,  0xc47ef08b0c9f3f9f,  0x5a102b80ec0fb414,  0x52d66d1377cf6219,  0x3a79068ab1f1288,  0x17a59fb049fd9130,  0x9fccb95c262e9e76];

        //vector of size 136 from official kats
        bytes memory message =
            hex"B32D95B0B9AAD2A8816DE6D06D1F86008505BD8C14124F6E9A163B5A2ADE55F835D0EC3880EF50700D3B25E42CC0AF050CCD1BE5E555B23087E04D7BF9813622780C7313A1954F8740B6EE2D3F71F768DD417F520482BD3A08D4F222B4EE9DBD015447B33507DD50F3AB4247C5DE9A8ABD62A8DECEA01E3B87C8B927F5B08BEB37674C6F8E380C04";

        ctx = shake_update(ctx, message);

        for (uint256 i = 0; i < 25; i++) {
            assertEq(ctx.state[i], expected[i]);
        }
    }

    function test_shake_digest136() public pure {
        ctx_shake memory ctx;
        //vector of size 136 from official kats
        bytes memory message =
            hex"B32D95B0B9AAD2A8816DE6D06D1F86008505BD8C14124F6E9A163B5A2ADE55F835D0EC3880EF50700D3B25E42CC0AF050CCD1BE5E555B23087E04D7BF9813622780C7313A1954F8740B6EE2D3F71F768DD417F520482BD3A08D4F222B4EE9DBD015447B33507DD50F3AB4247C5DE9A8ABD62A8DECEA01E3B87C8B927F5B08BEB37674C6F8E380C04";
        ctx = shake_update(ctx, message);

        bytes memory output = shake_digest(ctx, 512);
        bytes memory expected =
            hex"cc2eaa04eef8479cdae8566eb8ffa1100a407995bf999ae97ede526681dc3490616f28442d20da92124ce081588b81491aedf65caaf0d27e82a4b0e1d1cab23833328f1b8da430c8a08766a86370fa848a79b5998db3cffd057b96e1e2ee0ef229eca133c15548f9839902043730e44bc52c39fadc1ddeead95f9939f220ca300661540df7edd9af378a5d4a19b2b93e6c78f49c353343a0b5f119132b5312d004831d01769a316d2f51bf64ccb20a21c2cf7ac8fb6f6e90706126bdae0611dd13962e8b53d6eae26c7b0d2551daf6248e9d65817382b04d23392d108e4d3443de5adc7273c721a8f8320ecfe8177ac067ca8a50169a6e73000ebcdc1e4ee6339fc867c3d7aeab84146398d7bade121d1989fa457335564e975770a3a00259ca08706108261aa2d34de00f8cac7d45d35e5aa63ea69e1d1a2f7dab3900d51e0bc65348a25554007039a52c3c309980d17cad20f1156310a39cd393760cfe58f6f8ade42131288280a35e1db8708183b91cfaf5827e96b0f774c45093b417aff9dd6417e59964a01bd2a612ffcfba18a0f193db297b9a6cc1d270d97aae8f8a3a6b26695ab66431c202e139d63dd3a24778676cefe3e21b02ec4e8f5cfd66587a12b44078fcd39eee44bbef4a949a63c0dfd58cf2fb2cd5f002e2b0219266cfc031817486de70b4285a8a70f3d38a61d3155d99aaf4c25390d73645ab3e8d80f0";

        for (uint256 i = 0; i < 25; i++) {
            assertEq(expected[i], output[i]);
        }
    }

    function test_shake_digest72() public pure {
        ctx_shake memory ctx;
        //vector of size 136 from official kats
        bytes memory message =
            hex"1EED9CBA179A009EC2EC5508773DD305477CA117E6D569E66B5F64C6BC64801CE25A8424CE4A26D575B8A6FB10EAD3FD1992EDDDEEC2EBE7150DC98F63ADC3237EF57B91397AA8A7";

        bytes memory expected =
            hex"2fce215362a523d7b76fb836eb458667099c58bc51d7ee6f6deb9894b6a337576b0daf9a806488c3d238762b7a2e7b12aacd1d696517eed142aa5dc5a0747f08e5e39a2486d75f497cbd6c4899d6f5bf2aaac9189a6abc6e787b0d9c5283c840e518c6ab0393cf60337369251df935a02de0463dbfa4dcdc1de9034fc9c21ffb9dbd7c48384dff31012bd5f5a9cdfdb7139c3c35f560913d643ddb728910413f1267bf1bf1586c5ee69dad26b53154934762d4c80c34d511bdd8a391f83d224f9f8f83b61daa046c542bc78f153a3aed27e1268058f6952258d274f11c8d9634a5bdd4e69c60dcf1f89df2238eadfe783cba652a554186d9e8307c7773722d1049c3815526f583612bbd8f6c587d058b80fbd38113957e60212777a9f67b612312583fefb67533c065286cf371001440b1a7a43de2405e5e92d633f12a63ee2ebc408164545df22803ff239dee66eaa20780d103d940880e8bf68b9d815efcf16f59e0d858af33fe4d287a2b8e61c6ebf26e16e354b3ef63774ee01a14691b149d81f010a655f308e966c990e1befcb6e4253ff43bf473afa78aa88c36ebbe735b6b2f92ba9d07a738e000c9b42bf8a3a4d8fb6c38aa36b3329f909676183fbb520196d0dedc80dc6ba0db4d72ac6544551cc38b23afe000a91f10a89956d2120494543e3ff5d7d1b2791207860a0b921debbae769e55713a1d611f6b1175bd0";

        ctx = shake_update(ctx, message);

        bytes memory output = shake_digest(ctx, 1200);

        for (uint256 i = 0; i < 512; i++) {
            assertEq(expected[i], output[i]);
        }
    }

    //test that digest is equivalent to pad, followed by squeezes
    function test_shake_digestVSpadsqueeze() public pure {
        ctx_shake memory ctx;
        //vector of size 136 from official kats
        bytes memory message =
            hex"1EED9CBA179A009EC2EC5508773DD305477CA117E6D569E66B5F64C6BC64801CE25A8424CE4A26D575B8A6FB10EAD3FD1992EDDDEEC2EBE7150DC98F63ADC3237EF57B91397AA8A7";

        bytes memory expected =
            hex"2fce215362a523d7b76fb836eb458667099c58bc51d7ee6f6deb9894b6a337576b0daf9a806488c3d238762b7a2e7b12aacd1d696517eed142aa5dc5a0747f08e5e39a2486d75f497cbd6c4899d6f5bf2aaac9189a6abc6e787b0d9c5283c840e518c6ab0393cf60337369251df935a02de0463dbfa4dcdc1de9034fc9c21ffb9dbd7c48384dff31012bd5f5a9cdfdb7139c3c35f560913d643ddb728910413f1267bf1bf1586c5ee69dad26b53154934762d4c80c34d511bdd8a391f83d224f9f8f83b61daa046c542bc78f153a3aed27e1268058f6952258d274f11c8d9634a5bdd4e69c60dcf1f89df2238eadfe783cba652a554186d9e8307c7773722d1049c3815526f583612bbd8f6c587d058b80fbd38113957e60212777a9f67b612312583fefb67533c065286cf371001440b1a7a43de2405e5e92d633f12a63ee2ebc408164545df22803ff239dee66eaa20780d103d940880e8bf68b9d815efcf16f59e0d858af33fe4d287a2b8e61c6ebf26e16e354b3ef63774ee01a14691b149d81f010a655f308e966c990e1befcb6e4253ff43bf473afa78aa88c36ebbe735b6b2f92ba9d07a738e000c9b42bf8a3a4d8fb6c38aa36b3329f909676183fbb520196d0dedc80dc6ba0db4d72ac6544551cc38b23afe000a91f10a89956d2120494543e3ff5d7d1b2791207860a0b921debbae769e55713a1d611f6b1175bd0";

        ctx = shake_update(ctx, message);

        bytes memory output = shake_digest(ctx, 1024);

        for (uint256 i = 0; i < 512; i++) {
            assertEq(expected[i], output[i]);
        }

        ctx_shake memory ctx2;

        ctx2 = shake_update(ctx2, message);
        ctx2 = shake_pad(ctx2);
        bytes memory output2;
        (ctx2, output2) = shake_squeeze(ctx2, 512);
        bytes memory output3;
        (ctx2, output3) = shake_squeeze(ctx2, 512);

        for (uint256 i = 0; i < 512; i++) {
            assertEq(output[i], output2[i]);
            assertEq(output[512 + i], output3[i]);
        }
    }
}
