// SPDX-License-Identifier: UNLICENSED
//this is a direct translation from https://github.com/coruus/py-keccak/blob/master/fips202/keccak.py
pragma solidity ^0.8.25;

contract Falcon {
    uint256[24] _KECCAK_RHO =
        [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];

    uint256[24] _KECCAK_PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

    uint64[24] _KECCAK_RC = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008
    ];

    uint256 constant _SPONGE_ABSORBING = 1;
    uint256 _SPONGE_SQUEEZING = 2;

    // """Rotate uint64 x left by s.""
    function rol64(uint256 x, uint256 s) public pure returns (uint64) {
        return (uint64)(x << s ^ (x >> (64 - s)));
    }

    function F1600(uint64[25] memory state) public view returns (uint64[25] memory) {
        uint64[5] memory bc = [uint64(0), 0, 0, 0, 0];

        for (uint256 i = 0; i < 24; i++) {
            //range(24):
            uint64 t;
            //# Parity
            for (uint256 x = 0; x < 5; x++) {
                //range(5):
                bc[x] = 0;
                for (uint256 y = 0; y < 25; y += 5) {
                    // range(0, 25, 5):
                    bc[x] ^= state[x + y];
                }
            }
            //# Theta
            for (uint256 x = 0; x < 5; x++) {
                //range(5):
                t = bc[(x + 4) % 5] ^ rol64(bc[(x + 1) % 5], 1);
                for (uint64 y = 0; y < 25; y += 5) {
                    // in range(0, 25, 5):
                    state[y + x] ^= t;
                }
            }

            //# Rho and pi
            t = state[1];
            for (uint256 x = 0; x < 24; x++) {
                bc[0] = state[_KECCAK_PI[x]];
                state[_KECCAK_PI[x]] = rol64(t, _KECCAK_RHO[x]);
                t = bc[0];
            }

            for (uint256 y = 0; y < 25; y += 5) {
                // in range(0, 25, 5):
                for (uint256 x = 0; x < 5; x++) {
                    //range(5):
                    bc[x] = state[y + x];
                }
                for (uint256 x = 0; x < 5; x++) {
                    //range(5):
                    state[y + x] = bc[x] ^ ((bc[(x + 1) % 5] ^ 0xffffffffffffffff) & bc[(x + 2) % 5]);
                }
                state[0] ^= _KECCAK_RC[i];
            }
        } //end loop i
        return state;
    } //end F1600
}
