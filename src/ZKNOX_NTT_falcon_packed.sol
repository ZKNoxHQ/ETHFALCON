// SPDX-License-Identifier: MIT
// FILE: ZKNOX_NTT_falcon_packed.sol
//
// Packed-SWAR forward NTT for Falcon-512 (q = 12289, n = 512).
//
// Layout: 128 words of four 64-bit lanes; coefficient 4w+j sits in lane j of
// word w. q is 14 bits, so a 64-bit lane leaves 50 bits of headroom: sums stay
// UNREDUCED across all nine layers and only the twiddle multiply is reduced,
// with one Barrett step.
//
// Growth: Barrett leaves a residue < 2q (max 12316 measured, = 1.001q), the
// subtract branch adds a packed 4q bias to stay non-negative per lane, so the
// per-layer bound grows by 4q. Nine layers from q gives 37q = 454,693 < 2^19.
// The twiddle product is then < 2^19 * 2^14 = 2^33, and the Barrett multiply
// < 2^33 * M40 = 2^59.4, both inside a 64-bit lane. No lane ever carries into
// its neighbour.
//
// Layers t = 256..4 are word-aligned (t/4 >= 1 whole words), so one scalar
// multiply drives four butterflies. Layers t = 2 and t = 1 fall inside a word:
// t = 2 still shares one twiddle across the word, t = 1 needs two.
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";

uint256 constant _M40 = 89471204; // floor(2^40 / q)
uint256 constant _MASK24L = 0x0000000000ffffff0000000000ffffff0000000000ffffff0000000000ffffff;
uint256 constant _BIG4Q = 0x000000000000c004000000000000c004000000000000c004000000000000c004;
uint256 constant _LANE = 0xffffffffffffffff;
uint256 constant _L01 = 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff;
uint256 constant _L0 = 0x000000000000000000000000000000000000000000000000ffffffffffffffff;

/// @notice 32 compact words (16 x 16-bit) -> 128 packed words (4 x 64-bit lanes).
function _packFromCompact(uint256[] memory c) pure returns (uint256[] memory A) {
    A = new uint256[](128);
    assembly ("memory-safe") {
        let src := add(c, 32)
        let dst := add(A, 32)
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            let ci := mload(add(src, shl(5, i)))
            let base := add(dst, shl(7, i)) // 4 words per source word
            // source word i holds coefficients 16i .. 16i+15, four per dest word
            for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                let s := shl(6, k) // 64 bits of source consumed per dest word
                let v := shr(s, ci)
                mstore(
                    add(base, shl(5, k)),
                    or(
                        or(and(v, 0xffff), shl(64, and(shr(16, v), 0xffff))),
                        or(shl(128, and(shr(32, v), 0xffff)), shl(192, and(shr(48, v), 0xffff)))
                    )
                )
            }
        }
    }
}

/// @notice 128 packed words -> 512 one-per-word coefficients, fully reduced.
function _unpackTo512(uint256[] memory A) pure returns (uint256[] memory b) {
    b = new uint256[](512);
    assembly ("memory-safe") {
        let src := add(A, 32)
        let dst := add(b, 32)
        for { let w := 0 } lt(w, 128) { w := add(w, 1) } {
            let word := mload(add(src, shl(5, w)))
            let o := add(dst, shl(7, w))
            mstore(o, mod(and(word, _LANE), q))
            mstore(add(o, 32), mod(and(shr(64, word), _LANE), q))
            mstore(add(o, 64), mod(and(shr(128, word), _LANE), q))
            mstore(add(o, 96), mod(shr(192, word), q))
        }
    }
}

/// @notice Forward NTT, in place on 128 packed words.
function _nttFwPacked(uint256[] memory A) pure returns (uint256[] memory) {
    uint256[32] memory psirev = [
        uint256(0x16e40c7b04bc29930e25261022510dd61fdb166802d22ae80fcb1be72a3a0001),
        0x5471c8f1970230116c4139f1e1216602549244324622dce2c4c25c00a4f1d2c,
        0x270b2bdb222012c50e8023c2254612ee2ad313de0bc623802ceb2c462b6f090f,
        0x2d2b1dfe28c42f752531299e1f622b68093e24161ce1246e2c191f212fb00c13,
        0x27d81c1d0cd40b410ca902d9232807dd06a00594014e097a19861218112404ec,
        0x18ea1ce720a525561a5b00910d830e351f7a260d2e9e0d36218629221bc62193,
        0x2624056522011fb01c841b2e10b629780220169f0153265d000903fe01e024e7,
        0x1b030b1500821eff095c116423210f6d1c360895007609ac1687033b215d2c48,
        0x2bec0b2b26501394164224a112fd01620ec22108030501862bd61c1401ba0961,
        0x2de0139b0e78258b1fd2126a00f206012a61214e2407001b1c2506601cec03f9,
        0x268b186a277625fb0bab17860e3e267c2c96213d29ba1c911f4513e0139303ea,
        0x77805622e4e1f10094d1abd200101ed0cb02b4a149d04901ddc2e6d085f2bd8,
        0x2910067f1dd32a6f0a9014ab134a0e3411552ffe0c4d2f611cca2f900f4b0876,
        0x5cc1ce22525144b0a550fd527001c4f1114087e1ec324e2233a0fd906990d24,
        0x2031273824bd2b800c72151f27b3065e0db614d40b3126bf2468207725832352,
        0x1dc0dcb13290f910608277f01a41a4a00f30bc8029f244923c11bba22b926a2,
        0x118d237f27f814f9150728ea015e05e818cb29d22a30263d05cb171b04ef0031,
        0x129207422e57230e0b6d015b2154284a02d300ae069d24400a5f199a1915254f,
        0x28f424bf27fe07a2267217fe02400f7b22380d6a00da0b5c28ce093910130bd6,
        0x50d1d801d5b15352e3c171401a20ebc14d5281216f408e9009c253220800f97,
        0x20302171048717662c4d2b872a850145249a214f0fed2051028c168617d30127,
        0x14b1181a0f7405502b511bc126061817063a28571c0f17490a842f5910ca0d01,
        0x2cbe1850220f1090052723b302c50fce081e045810e207a601b9039a2bdf2012,
        0x1b780efa18e21eb01a932413292e23ce263a247d169629e32fc10e4802ab099b,
        0x2800133005292f41228c12ac125a13c10313226703f21aa523ca1fb824991b88,
        0x27b2009724ea0f75171226382e52062b0c662fcd2533052b22f9185a190f02a5,
        0x10742c320d6e24e52bb0008e19d00d9518892c8c1c7007a42c160dcc2f102fc7,
        0x1df117bd0cbf21f117b40e1220112e5c2da408fe01f81f8c16fe12ae1a27242c,
        0x2be71e4915450f14258604a6211717e621342f6e1ab11161128d1a601d4c1e8e,
        0x2c0717252bf022471a3b07b526d92b0314c3201613341f1d2df70879234313d7,
        0x294101901808135421c61ada191b17f82fc90c7f14561a6807c306a60ded028e,
        0x2b1b03cd1ac62ab207820f27206328102e83013c206d01d417cd0e7e154614db
    ];

    assembly ("memory-safe") {
        let base := add(A, 32)

        // ---- layers t = 256, 128, 64, 32, 16, 8, 4  (twds = t/4 whole words)
        let m := 1
        for { let twds := 64 } gt(twds, 0) { twds := shr(1, twds) } {
            let step := shl(5, twds) // twds words, in bytes
            for { let i := 0 } lt(i, m) { i := add(i, 1) } {
                let mi := add(m, i)
                let S := and(shr(shl(4, and(mi, 0xf)), mload(add(psirev, shl(5, shr(4, mi))))), 0xffff)
                let p := add(base, shl(1, mul(i, step))) // word i*2*twds
                let pend := add(p, step)
                for {} lt(p, pend) { p := add(p, 32) } {
                    let pt := add(p, step)
                    let U := mload(p)
                    let x := mul(mload(pt), S)
                    let V := sub(x, mul(and(shr(40, mul(x, 89471204)), _MASK24L), 12289))
                    mstore(pt, sub(add(U, _BIG4Q), V))
                    mstore(p, add(U, V))
                }
            }
            m := shl(1, m)
        }

        // ---- t = 2, m = 128: lanes (0,1) against lanes (2,3), one twiddle
        for { let w := 0 } lt(w, 128) { w := add(w, 1) } {
            let p := add(base, shl(5, w))
            let W := mload(p)
            let mi := add(128, w)
            let S := and(shr(shl(4, and(mi, 0xf)), mload(add(psirev, shl(5, shr(4, mi))))), 0xffff)
            let U := and(W, _L01)
            let x := mul(and(shr(128, W), _L01), S)
            let V := sub(x, mul(and(shr(40, mul(x, 89471204)), _MASK24L), 12289))
            mstore(p, or(and(add(U, V), _L01), shl(128, and(sub(add(U, _BIG4Q), V), _L01))))
        }

        // ---- t = 1, m = 256: two twiddles inside the word
        for { let w := 0 } lt(w, 128) { w := add(w, 1) } {
            let p := add(base, shl(5, w))
            let W := mload(p)
            let ia := add(256, shl(1, w))
            let Sa := and(shr(shl(4, and(ia, 0xf)), mload(add(psirev, shl(5, shr(4, ia))))), 0xffff)
            let ib := add(ia, 1)
            let Sb := and(shr(shl(4, and(ib, 0xf)), mload(add(psirev, shl(5, shr(4, ib))))), 0xffff)
            let Ua := and(W, _L0)
            let xa := mul(and(shr(64, W), _L0), Sa)
            let Va := sub(xa, mul(and(shr(40, mul(xa, 89471204)), _MASK24L), 12289))
            let Ub := and(shr(128, W), _L0)
            let xb := mul(shr(192, W), Sb)
            let Vb := sub(xb, mul(and(shr(40, mul(xb, 89471204)), _MASK24L), 12289))
            mstore(
                p,
                or(
                    or(and(add(Ua, Va), _LANE), shl(64, and(sub(add(Ua, _BIG4Q), Va), _LANE))),
                    or(shl(128, and(add(Ub, Vb), _LANE)), shl(192, and(sub(add(Ub, _BIG4Q), Vb), _LANE)))
                )
            )
        }
    }
    return A;
}

/// @notice Lane-wise product of two packed polynomials, fully Barrett-reduced.
/// @dev SWAR cannot multiply two packed vectors (lanes cross-contaminate), so
///      each of the four lanes is extracted and multiplied on its own. The win
///      over _ZKNOX_VECMULMOD is not the arithmetic, it is never materialising
///      the 512-word expanded form.
function _vecMulPacked(uint256[] memory A, uint256[] memory B) pure returns (uint256[] memory C) {
    C = new uint256[](128);
    assembly ("memory-safe") {
        let pa := add(A, 32)
        let pb := add(B, 32)
        let pcw := add(C, 32)
        let endp := add(pcw, 4096) // 128 words
        for {} lt(pcw, endp) {} {
            let x := mload(pa)
            let y := mload(pb)
            mstore(
                pcw,
                or(
                    or(
                        mulmod(and(x, _LANE), and(y, _LANE), 12289),
                        shl(64, mulmod(and(shr(64, x), _LANE), and(shr(64, y), _LANE), 12289))
                    ),
                    or(
                        shl(128, mulmod(and(shr(128, x), _LANE), and(shr(128, y), _LANE), 12289)),
                        shl(192, mulmod(shr(192, x), shr(192, y), 12289))
                    )
                )
            )
            pa := add(pa, 32)
            pb := add(pb, 32)
            pcw := add(pcw, 32)
        }
    }
}

/// @notice Inverse NTT (Gentleman-Sande), in place on 128 packed words.
/// @dev Mirror image of the forward pass: here t = 1 and t = 2 come FIRST and
///      are the in-word layers, then t = 4..256 are word-aligned. Both branches
///      are Barrett-reduced every layer, which pins the lane bound at 2q instead
///      of letting the additive branch double nine times (2^24, past what a
///      single 2^40 Barrett can take). Worst observed Barrett product is 2^56.
function _nttInvPacked(uint256[] memory A) pure returns (uint256[] memory) {
    uint256[32] memory psirev = [
        0x222b0db009f121dc066e2b452386191d05192d2f19991026141a203605c70001,
        0x12d525b20a4103b502330b9f0bbe0ab819a111ef1c62193d0d00169113722aba,
        0x23ee005110e003e80b9313200beb26c30499109f06630ad0008c073d120302d6,
        0x26f2049203bb03160c81243b1c23052e1d130abb0c3f21811d3c0de1042608f6,
        0x3b90ea42cc6197a26552f8b276c13cb20940ce01e9d26a511022f7f24ec14fe,
        0xb1a2e212c032ff809a42eae19622de106891f4b14d3137d10510e002a9c09dd,
        0xe6e143b06df0e7b22cb016309f4108721cc227e2f7015a60aab0f5c131a1717,
        0x2b151edd1de9167b26872eb32a6d296128240cd92d28235824c0232d13e40829,
        0x95f0d4814470c400bb82d6224392f0e15b72e5d088229f920701cd822362e25,
        0xcaf0a7e0f8a0b99094224d01b2d224b29a3084e1ae2238f04810b4408c90fd0,
        0x22dd296820280cc70b1f113e27831eed13b20901202c25ac1bb60adc131f2a35,
        0x278b20b60071133700a023b400031eac21cd1cb71b5625710592122e298206f1,
        0x42927a2019412252b711b6404b723512e141000154426b410f101b32a9f2889,
        0x2c171c6e1c2110bc137006470ec4036b098521c3187b24560a06088b17970976,
        0x2c08131529a113dc2fe60bfa0eb305a02a002f0f1d97102f0a7621891c660221,
        0x26a02e4713ed042b2e7b2cfc0ef9213f2e9f1d040b6019bf1c6d09b124d60415,
        0x1b261abb218318342e2d0f942ec5017e07f10f9e20da287f054f153b2c3404e6,
        0x2d732214295b283e15991bab23820038180916e615270e3b1cad17f92e7106c0,
        0x1c2a0cbe2788020a10e41ccd0feb1b3e04fe0928284c15c60dba041118dc03fa,
        0x117312b515a11d741ea0155000930ecd181b0eea2b5b0a7b20ed1abc11b8041a,
        0xbd515da1d53190310752e092703025d01a50ff021ef184d0e10234218441210,
        0x3a00f1223503eb285d139103751778226c16312f7304510b1c229303cf1f8d,
        0x2d5c16f217a70d082ad60ace0034239b29d601af09c918ef208c0b172f6a084f,
        0x14790b6810490c37155c2c0f0d9a2cee1c401da71d550d7500c02ad81cd10801,
        0x26662d5621b90040061e196b0b8409c70c3306d30bee156e1151171f21071489,
        0xfef04222c672e48285b1f1f2ba927e320332d3c0c4e2ada1f710df217b10343,
        0x23001f3700a8257d18b813f207aa29c717ea09fb144004b02ab1208d17e71b50,
        0x2eda182e197b2d750fb020140eb20b672ebc057c047a03b4189b2b7a0e900fd1,
        0x206a0f810acf2f652718190d07ef1b2c21452e5f18ed01c51acc12a612812af4,
        0x242b1fee26c8073324a52f2722970dc920862dc11803098f285f08030b42070d,
        0xab216ec166725a20bc129642f532d2e07b70ead2ea624940cf301aa28bf1d6f,
        0x2fd02b1218e62a3609c405d1062f17362a192ea307171afa1b0808090c821e74
    ];

    assembly ("memory-safe") {
        let base := add(A, 32)

        // ---- t = 1, m = 512: each lane pair is its own group, two twiddles
        for { let w := 0 } lt(w, 128) { w := add(w, 1) } {
            let p := add(base, shl(5, w))
            let W := mload(p)
            let l0 := and(W, _LANE)
            let l1 := and(shr(64, W), _LANE)
            let l2 := and(shr(128, W), _LANE)
            let l3 := shr(192, W)

            let ia := add(256, shl(1, w))
            let Sa := and(shr(shl(4, and(ia, 0xf)), mload(add(psirev, shl(5, shr(4, ia))))), 0xffff)
            let ib := add(ia, 1)
            let Sb := and(shr(shl(4, and(ib, 0xf)), mload(add(psirev, shl(5, shr(4, ib))))), 0xffff)

            let s0 := add(l0, l1)
            s0 := sub(s0, mul(and(shr(40, mul(s0, 89471204)), _MASK24L), 12289))
            let d0 := mul(sub(add(l0, 49156), l1), Sa)
            d0 := sub(d0, mul(and(shr(40, mul(d0, 89471204)), _MASK24L), 12289))
            let s1 := add(l2, l3)
            s1 := sub(s1, mul(and(shr(40, mul(s1, 89471204)), _MASK24L), 12289))
            let d1 := mul(sub(add(l2, 49156), l3), Sb)
            d1 := sub(d1, mul(and(shr(40, mul(d1, 89471204)), _MASK24L), 12289))

            mstore(
                p,
                or(
                    or(and(s0, _LANE), shl(64, and(d0, _LANE))),
                    or(shl(128, and(s1, _LANE)), shl(192, and(d1, _LANE)))
                )
            )
        }

        // ---- t = 2, m = 256: lanes (0,1) against lanes (2,3), one twiddle
        for { let w := 0 } lt(w, 128) { w := add(w, 1) } {
            let p := add(base, shl(5, w))
            let W := mload(p)
            let mi := add(128, w)
            let S := and(shr(shl(4, and(mi, 0xf)), mload(add(psirev, shl(5, shr(4, mi))))), 0xffff)
            let U := and(W, _L01)
            let V := and(shr(128, W), _L01)
            let s := add(U, V)
            s := sub(s, mul(and(shr(40, mul(s, 89471204)), _MASK24L), 12289))
            let d := mul(and(sub(add(U, _BIG4Q), V), _L01), S)
            d := sub(d, mul(and(shr(40, mul(d, 89471204)), _MASK24L), 12289))
            mstore(p, or(and(s, _L01), shl(128, and(d, _L01))))
        }

        // ---- t = 4 .. 256, word aligned
        let m := 128
        for { let twds := 1 } gt(m, 1) { twds := shl(1, twds) } {
            let h := shr(1, m)
            let step := shl(5, twds)
            let stride := shl(1, step)
            let g := base
            for { let i := 0 } lt(i, h) { i := add(i, 1) } {
                let hi := add(h, i)
                let S := and(shr(shl(4, and(hi, 0xf)), mload(add(psirev, shl(5, shr(4, hi))))), 0xffff)
                let p := g
                let pend := add(p, step)
                for {} lt(p, pend) { p := add(p, 32) } {
                    let pt := add(p, step)
                    let U := mload(p)
                    let V := mload(pt)
                    let s := add(U, V)
                    s := sub(s, mul(and(shr(40, mul(s, 89471204)), _MASK24L), 12289))
                    let d := mul(sub(add(U, _BIG4Q), V), S)
                    d := sub(d, mul(and(shr(40, mul(d, 89471204)), _MASK24L), 12289))
                    mstore(p, s)
                    mstore(pt, d)
                }
                g := add(g, stride)
            }
            m := shr(1, m)
        }

        // ---- final scaling by n^-1 mod q
        let p := base
        let pend := add(base, 4096)
        for {} lt(p, pend) { p := add(p, 32) } {
            let x := mul(mload(p), nm1modq)
            mstore(p, sub(x, mul(and(shr(40, mul(x, 89471204)), _MASK24L), 12289)))
        }
    }
    return A;
}

/// @notice 128 packed words -> 32 compact words (16 x 16-bit), fully reduced.
function _compactFromPacked(uint256[] memory A) pure returns (uint256[] memory c) {
    c = new uint256[](32);
    assembly ("memory-safe") {
        let src := add(A, 32)
        let dst := add(c, 32)
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            let acc := 0
            let base := add(src, shl(7, i))
            for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                let word := mload(add(base, shl(5, k)))
                let v :=
                    or(
                        or(mod(and(word, _LANE), q), shl(16, mod(and(shr(64, word), _LANE), q))),
                        or(shl(32, mod(and(shr(128, word), _LANE), q)), shl(48, mod(shr(192, word), q)))
                    )
                acc := or(acc, shl(shl(6, k), v))
            }
            mstore(add(dst, shl(5, i)), acc)
        }
    }
}
