import hashlib
from falcon import HEAD_LEN, SALT_LEN, Params, decompress, SecretKey, PublicKey
from common import q
from keccak_prng import KeccakPRNG


def deterministic_salt(x, seed="deterministic_salt"):
    # This function is used for generating deterministic salt for the tests.
    # Don't use this for a PRNG!
    first_bytes = hashlib.sha256(f"{seed}{x}".encode()).digest()
    last_bytes = hashlib.sha256(f"{seed}".encode()+first_bytes).digest()
    return first_bytes + last_bytes[0:8]


file = open("../test/ZKNOXFalconTestVectors.sol", 'w')
n = 512
# An example of secret key
f = [0, -7, -2, -1, 0, 0, 1, -2, 0, -2, -3, 0, 1, 8, 3, 2, -3, -3, 2, -6, 0, -7, 0, -6, 0, 5, 0, 2, 7, 3, 3, -1, -4, -2, -4, -1, -1, 3, 1, 1, -1, -1, 6, -1, -3, 4, 4, -7, 6, -2, 6, 4, 1, 5, 5, -2, -6, -1, -1, 6, 2, 4, -2, -3, 0, 5, 8, 1, 6, -1, -5, -1, 3, 2, -2, -2, -1, 0, -2, 8, 4, 9, 1, 1, -4, 1, 0, 3, -1, 0, -4, 0, 0, -2, 0, -5, 3, 4, 1, 2, 6, 3, 0, -3, 3, -5, -2, 2, 4, 0, -2, 0, -3, 4, 1, -3, -1, -5, 1, -5, 0, -4, -4, 5, -6, 10, -1, -8, -2, 8, -7, 2, 0, 3, 2, -1, -3, -5, -2, -3, 6, -5, 1, 1, 2, -6, 2, -1, -6, -2, -8, -1, -1, -5, 0, -6, -6, 1, -7, 9, 0, 1, 9, 5, 2, 3, 2, 1, 2, 3, -1, -2, 2, 6, -3, 6, -1, 3, 0, 3, 1, 3, 2, -5, -4, -1, 0, -2, 1, 8, -5, 1, 1, -4, -2, 9, -4, 3, -2, -6, -1, -3, 2, 9, -3, 0, -6, -1, -1, -6, 4, -2, -1, -2, 3, 2, -2, 5, 8, -6, 3, -5, -1, -1, -2, -2, -3, 1, 5, -1, 4, -2, -3, 6, -2, 3, -9, 10, -3, -3, -7, -5, 3, -7, -5, 1, 0, -2, -3, -6, -10,
     2, -1, 1, 3, 3, 2, 4, -3, 4, -2, -1, 1, 2, 5, 3, 3, -2, 0, 6, 1, -3, 4, 2, -2, -2, 3, 3, -1, -5, 3, 1, -1, -5, 0, 0, -2, -3, -1, 4, -2, 6, -8, -1, -1, 1, -3, -2, -2, -1, -8, 2, 5, 1, -2, 0, -10, 1, 0, -1, 9, -2, 0, -3, 5, 2, 1, 3, -2, -3, -1, -2, -4, 3, 3, 1, 4, 3, 7, -6, -2, -1, -5, -2, 0, -4, 1, 4, -3, 3, -5, -4, 0, 4, 1, 2, -3, -2, 5, -2, 7, 2, -2, 5, 4, -6, -2, -1, 0, 3, -2, 3, 7, 0, 2, 3, -3, -2, 3, 2, 2, 1, 5, 0, 4, 1, 4, 7, -3, 3, 7, -1, 0, 1, 7, -6, -4, -3, 1, -4, 1, 2, 2, 5, 0, -1, 0, -4, 0, 9, -4, 4, -5, -3, 8, 1, 3, 3, 0, -6, 0, -3, 0, -1, 4, 2, 2, 16, -5, -1, 0, 3, -2, 0, 3, -6, -1, 8, -1, 2, 0, 0, -1, 5, 3, 2, 4, 2, -3, 1, -6, 5, 0, 3, 6, 8, 4, 0, 2, -2, 11, 4, 1, -4, 2, 3, -1, 2, -6, -1, -1, 3, 2, 1, -6, -1, -5, 4, -1, -10, -3, -3, 6, 0, 6, 1, 3, 5, 2, 5, 4, 5, -3, 3, 2, -2, -1, -6, 4, 5, 1, -5, 8, -3, 4, 1, 1, 3, -9, 8, 0, 2, -2, 4, 9, 4, 1, 0, -2, 2, -1, 1]
g = [6, -1, 4, 0, 0, -2, -2, -4, 1, 4, -4, -3, 6, 2, -2, 0, 2, 0, 7, 3, -7, -3, 4, -1, -3, 7, 2, -1, 6, -5, 5, 1, -2, 6, -6, 4, -3, 8, 0, -1, -11, 7, 5, -3, 0, 1, 5, 6, -4, 0, -3, -1, -4, 0, 1, 3, 5, -1, 7, -3, -3, -3, 1, 3, 0, 2, 0, -2, -6, 4, -4, -1, 0, 6, -4, 0, 2, 2, -10, 5, -3, 4, 0, 4, -6, 5, -2, -3, 1, -6, 2, 1, -5, -2, -8, 7, -1, 1, 1, 2, 3, 0, 3, 0, -1, 2, -4, 0, 2, 3, 1, 0, 2, 0, -4, 3, -4, 5, -4, 1, 3, -4, -2, 1, 4, 2, -3, 5, -1, 5, -4, 2, 2, 3, 0, -1, -1, 4, -1, -4, -1, 2, 5, 3, -3, 9, -2, -8, 3, 1, 6, 2, 5, 2, -3, 8, 3, -2, -6, 1, 2, -2, -7, -3, -2, 6, 2, -2, 1, -2, -4, -3, 0, -2, 4, -2, 8, -11, -2, 4, 6, -1, 0, 2, -6, 11, 3, -2, -1, -2, 1, -5, 6, 7, -3, -3, 0, 1, 2, -5, -1, 1, 2, 2, 2, -2, -10, 1, 1, -8, 2, 0, -8, 0, -7, 1, 2, -1, -3, -2, 0, -7, -3, 1, 0, 1, -6, 2, 4, 1, 0, 2, -8, 0, -9, 1, 2, 4, 2, 1, -4, -9, 5, -1, 6, -4, -2, -9, 5, -1, 1, -1, 5, 1, -1, 1,
     3, -2, -3, -1, -3, 4, -5, 6, 0, -12, -4, -5, -2, 1, -7, -4, -2, -3, -3, 2, -1, -5, -1, 8, 3, 0, -1, -4, 1, 0, -7, 6, -9, 2, -2, 1, 6, -4, -3, -2, -5, 3, -5, 0, 3, -12, 4, 2, 4, -2, -3, 0, -1, 2, 7, 1, 2, 11, -6, 3, 2, -4, -3, 5, -3, 0, -2, 4, 7, 3, 3, 1, 7, 2, 1, 5, 8, -1, 2, 0, 6, -6, -6, -8, 1, 2, -5, 7, -5, 1, -5, 2, -1, 1, -3, 4, -7, -3, -2, -8, 7, 11, 0, -3, -3, -2, 2, 2, 4, 1, 0, -2, 5, 0, -2, 4, 5, 3, -1, -4, -4, -3, 0, 0, 2, -4, 3, 3, -1, -3, 1, 0, 2, 14, 7, 0, -4, 3, -1, -2, -1, -2, 2, -5, 4, 3, 6, -4, 2, -4, -2, -1, 2, 3, -4, -3, -1, 6, 1, -4, 4, 5, 1, -1, 3, -6, 5, 9, 8, -5, 2, 4, 1, 9, 5, -4, -1, 1, 0, 3, -4, 1, 0, -4, -6, 8, 1, 2, 5, 8, -2, 5, -6, -6, 1, -5, 0, -3, -3, 3, 1, 1, -2, -7, 8, 1, 1, 2, -1, 5, 6, -3, -1, 6, -3, -7, 5, -1, -3, 2, 0, -4, 4, 4, 8, 0, -8, 4, 0, 3, 2, -3, 0, 2, -5, 1, 1, 6, -3, -6, 3, -1, -2, 4, -3, 0, -4, 4, 3, -3, -3, 13, -5, -3, -3, -2]
F = [-23, 22, -11, -5, -18, 61, -2, 3, 1, -4, 12, -5, 3, -35, -49, 4, 14, -18, -16, 30, -11, -16, 4, -33, -7, -22, 15, 3, -7, -8, -9, -62, 44, 41, 15, -7, -10, 17, 37, 46, 30, -38, 36, 8, -14, 25, -29, 39, -27, 21, 26, -8, 18, -7, 31, -8, -33, 5, -4, 14, 18, -49, -15, -51, 16, -53, -10, -3, -12, 10, -29, 20, -13, 27, -12, 28, -9, 12, -25, -23, -45, -16, 11, -7, -6, 6, 27, -22, 48, 44, 60, 13, 10, 37, -1, 28, 1, -3, 2, 7, 24, 22, -14, 11, -1, 33, 2, 22, -26, -21, 15, -1, 12, 15, 14, -20, -3, -40, -1, 6, -7, 3, 15, 16, 31, -12, -23, 34, -11, -3, 29, -51, 42, -32, 29, -52, -22, -11, -11, 19, -12, 37, 45, -4, -3, 11, -18, 72, -6, 41, 44, -16, 24, -47, -35, -4, 13, 7, 35, -33, 12, 2, 1, -5, -10, -52, -27, -6, -4, 26, -21, -22, -2, 11, -1, -36, -11, 2, 41, -25, 19, 3, -47, 11, 12, 8, 26, -10, 10, 29, -10, 33, -46, 16, -11, 2, 2, -19, 26, -22, -12, -41, 22, -10, 22, -1, -1, 6, -22, -6, -9, 36, -7, -8, -1, 27, -26, -22, -36, 6, 20, 26, -44, 3, 24, 0, 18, -15, 17, -11, 1, -64, 4, 9, 7, 21, -15, -9, -11, -36, 48, 56, 8, 19, -35, 41, -13, -42, -9, -6, 53, -37, 24, -33, 12, 0, 20,
     26, 48, -19, -22, 4, 34, 44, 16, -13, -4, 14, -22, 29, -37, 43, -12, 16, 40, -21, 64, 5, 33, 0, 10, -11, -15, -13, 28, 22, -47, -11, -22, -1, -77, 27, 11, -8, 59, -31, -3, -29, -48, -42, 13, 27, 10, -55, 14, -2, -37, 17, 4, 23, -20, 34, 3, -10, 24, 23, -39, -26, -5, 6, -31, -6, 5, -5, 16, 13, -23, -27, 5, -31, -6, 8, -38, 30, -11, -13, 17, 8, 3, 7, -7, -15, -29, -32, 15, -36, 40, -6, 17, -12, 6, -15, 23, -14, 13, 31, -6, 85, -6, 9, -26, 21, 7, 11, 31, -49, -6, -9, -12, 6, 3, 16, 23, 9, -2, -6, -32, 5, -11, 54, 44, -9, -28, -24, -18, 44, 39, 20, -2, -35, 11, 5, 42, 10, -24, -24, -30, -27, -36, -2, -23, 39, -9, -6, -12, 16, 36, 5, 51, 17, -9, -25, -8, -17, 7, -4, -51, -44, 34, -2, -38, -14, -26, -12, 16, -12, 27, 15, -33, 30, -9, 8, -40, 4, -33, 27, -40, -22, 13, 11, 4, 6, -1, -50, -2, -7, 5, -23, 1, -11, -17, 6, 0, 2, -13, -8, -23, -24, 6, -4, 14, 12, 24, 4, -17, -10, -8, -40, -42, 32, -21, -19, -27, -1, -23, 16, -24, 34, -43, 7, 24, -34, -13, -6, 10, -16, 12, 7, -10, -24, 18, -31, 28, 35, 34, 4, 7, 18, -46, 47, -26, -18, -36, -38, -6, -13, -19, -7, -13, 13, -1, -54]
G = [-10, 12, -13, -20, 7, 32, -17, 31, -61, -3, 23, -65, 28, -61, -22, 56, 33, 11, 12, 7, 34, -33, 21, 27, -22, 67, -14, -5, -18, -4, -1, -42, 3, 51, -19, -1, 16, 14, 55, -37, 29, 28, 32, 20, -31, -46, 39, 7, -1, -22, -61, 23, -22, 9, -13, 11, 20, 16, -30, 1, 52, 46, 10, -6, 12, -31, 31, -15, 9, -19, -7, -5, 5, 16, -19, 63, -35, -21, -22, 0, 46, 7, -16, -12, 5, 3, -8, -43, 21, 21, 47, -30, -29, 16, 9, 14, -21, -9, 8, -26, -9, 20, -42, 59, -14, 6, 20, -31, -37, 14, 39, 0, 2, -40, 43, -3, -32, -27, -21, -15, 2, 0, -23, -5, -3, -9, 12, -27, -36, 4, -22, 23, -1, -12, 32, -39, -4, -33, -20, -7, -12, -22, 35, -21, 4, 2, 8, 26, -24, 12, -2, -39, -3, 8, 59, 12, -16, -8, -5, 36, 11, 16, 45, 19, -50, -32, -7, 27, 3, -17, 52, -27, -64, -12, -9, 6, -13, -29, -10, 2, 44, -16, -12, -9, -19, -6, -6, 6, 24, -55, 42, 38, -15, 38, -16, -22, -4, -9, 38, 21, 12, 50, -11, 9, 31, -33, 46, -12, 40, 2, -15, 6, -41, 27, 44, -1, -10, -9, -17, 24, 4, -5, 2, -22, 32, -51, -2, -23, 18, 27, -15, -17, 34, -15, 13, 1, -5, 36, 3, 36, -7, -8, 33, -19, -14, 4, -7, -8, 15, 0, -32, -7, -31,
     67, -27, -35, -6, 26, 13, -12, 24, 35, -21, 24, -16, 16, 10, 47, -14, 3, -5, 2, 3, -26, 0, -29, 4, 21, -17, -16, -20, 7, -44, -34, 26, 2, 6, -8, -17, 17, -14, 7, -5, 6, -33, 13, 6, 35, 21, -42, 3, 5, 8, 23, 27, -10, -40, 4, -20, 9, -31, -40, 14, 9, 45, -12, -32, 4, 7, 15, 25, 7, 9, 23, 4, 33, -35, 47, 2, 30, -22, 8, -38, -28, 62, -16, 13, -4, 5, 16, 34, -8, 44, 26, -45, 27, -42, 26, 33, -22, -25, 0, -3, -29, 6, 18, 11, 4, 9, -20, -9, 1, 14, -8, -6, -34, -11, -26, -2, -10, 35, -1, -24, 17, 4, 3, 76, -18, -13, 4, 19, 4, -41, 8, -17, -31, -4, -27, 24, -14, -1, 41, -7, -38, 27, 24, 12, 1, -25, 22, 10, -28, 25, 7, 29, -19, 9, 20, 5, -17, -24, 38, 0, 18, -23, 6, -30, -9, -38, -21, -32, 16, -5, 16, 1, -24, -17, 17, 34, -39, -25, -16, 26, 13, -18, -11, -8, -46, 27, 14, -27, -22, -22, -1, -41, -5, 11, -2, 57, 1, -16, -30, 25, 46, -20, 2, 9, 25, -30, 18, 39, -9, -53, 30, 14, 24, -22, 29, -8, 0, -18, 22, -2, -11, -35, -12, 24, 9, -20, -17, -39, 2, -3, -36, 31, -23, -4, 22, -40, 4, 0, 23, 26, -7, -8, 12, -31, -32, -10, -18, 24, 17, 0, 63, -29, 67, 44, 3, 13, 35, 11, -36]

sk = SecretKey(n, [f, g, F, G])
pub = PublicKey(sk)

header = """
// code generated using pythonref/generate_falcon_zknox_test_vectors.py.
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import "../src/ZKNOX_NTT.sol";
import "../src/ZKNOX_falcon.sol";

contract ZKNOX_FalconTest is Test {
    ZKNOX_falcon falcon;
    //exemple of stateless initialisation, no external contract provided
    ZKNOX_NTT ntt = new ZKNOX_NTT(address(0), address(0), 12289, 12265);
    // forgefmt: disable-next-line
    uint256[1024] psi_rev = [uint256(1), 1479, 4043, 7143, 5736, 4134, 1305, 722, 1646, 1212, 6429, 9094, 3504, 8747, 9744, 8668, 4591, 6561, 5023, 6461, 10938, 4978, 6512, 8961, 11340, 9664, 9650, 4821, 563, 9314, 2744, 3006, 1000, 4320, 12208, 3091, 9326, 4896, 2366, 9238, 11563, 7678, 1853, 140, 1635, 9521, 11112, 4255, 7203, 10963, 9088, 9275, 790, 955, 11119, 2319, 9542, 4846, 3135, 3712, 9995, 11227, 3553, 7484, 544, 5791, 11950, 2468, 11267, 9, 9447, 11809, 10616, 8011, 7300, 6958, 1381, 2525, 4177, 8705, 2837, 5374, 4354, 130, 2396, 4452, 3296, 8340, 12171, 9813, 2197, 5067, 11336, 3748, 5767, 827, 3284, 2881, 5092, 10200, 10276, 9000, 9048, 11560, 10593, 10861, 334, 2426, 4632, 5755, 11029, 4388, 10530, 3707, 3694, 7110, 11934, 3382, 2548, 8058, 4890, 6378, 9558, 3932, 5542, 12144, 3459, 3637, 1663, 1777, 1426, 7635, 2704, 5291, 7351, 8653, 9140, 160, 12286, 7852, 2166, 8374, 7370, 12176, 3364, 10600, 9018, 4057, 2174, 7917, 2847, 7875, 7094, 9509, 10805, 4895, 2305, 5042, 4053, 9644, 3985, 7384, 476, 3531, 420, 6730, 2178, 1544, 9273, 243, 9289, 11618, 3136, 5191, 8889, 9890, 9103, 6882, 10163, 1630, 11136, 2884, 8241, 10040, 3247, 9603, 2969, 3978, 6957, 3510, 9919, 9424, 7575, 8146, 1537, 12047, 8585, 2678, 5019, 545, 7404, 1017, 10657, 7205, 10849, 8526, 3066, 12262, 11244, 2859, 2481, 7277, 2912, 5698, 354, 7428, 390, 11516, 3778, 8456, 442, 2401, 5101, 11222, 4976, 10682, 875, 3780, 7278, 11287, 5088, 4284, 6022, 9302, 2437, 3646, 10102, 9723, 6039, 9867, 11854, 7952, 10911, 1912, 11796, 8193, 9908, 5444, 9041, 1207, 5277, 1168, 11885, 4645, 1065, 2143, 3957, 2839, 10162, 151, 11858, 1579, 2505, 5906, 52, 3174, 1323, 2766, 3336, 6055, 6415, 677, 3445, 7509, 4698, 5057, 12097, 10968, 10240, 4912, 5241, 9369, 3127, 4169, 3482, 787, 6821, 11279, 12231, 241, 11286, 3532, 11404, 6008, 10333, 7280, 2844, 3438, 8077, 975, 5681, 8812, 142, 1105, 4080, 421, 3602, 6221, 4624, 6212, 3263, 8689, 5886, 4782, 5594, 3029, 4213, 504, 605, 9987, 2033, 8291, 10367, 8410, 11316, 11035, 10930, 5435, 3710, 6196, 6950, 5446, 8301, 468, 11973, 11907, 6152, 4948, 11889, 10561, 6153, 6427, 3643, 5415, 56, 9090, 5206, 6760, 1702, 10302, 11635, 3565, 5315, 8214, 7373, 4324, 10120, 11767, 5079, 3262, 11011, 2344, 6715, 1973, 5925, 1018, 3514, 11248, 7500, 7822, 5537, 4749, 8500, 12142, 5456, 7840, 6844, 8429, 7753, 1050, 6118, 3818, 9606, 1190, 5876, 2281, 2031, 5333, 8298, 8320, 12133, 2767, 453, 6381, 418, 3772, 5429, 4774, 1293, 7552, 2361, 1843, 9259, 4115, 218, 2908, 8855, 8760, 2882, 10484, 1954, 2051, 2447, 6147, 576, 3963, 1858, 7535, 3315, 11863, 2925, 347, 3757, 1975, 10596, 3009, 174, 11566, 9551, 5868, 2655, 6554, 1512, 11939, 5383, 10474, 9087, 7796, 6920, 10232, 6374, 1483, 49, 11026, 1489, 2500, 10706, 5942, 1404, 11964, 11143, 948, 4049, 3728, 1159, 5990, 652, 5766, 6190, 11994, 4016, 4077, 2919, 3762, 6328, 7183, 10695, 1962, 7991, 8960, 12121, 9597, 7105, 1200, 6122, 9734, 3956, 1360, 6119, 5297, 3054, 6803, 9166, 1747, 5919, 4433, 3834, 5257, 683, 2459, 8633, 12225, 9786, 9341, 6507, 1566, 11454, 6224, 3570, 8049, 3150, 1319, 4046, 11580, 1958, 7967, 2078, 1112, 11231, 8210, 11367, 441, 1826, 9363, 9118, 4489, 3708, 3238, 11153, 3449, 7080, 1092, 3359, 3205, 8024, 8611, 10361, 11825, 2068, 10900, 4404, 346, 3163, 8257, 7449, 6127, 12164, 11749, 10763, 4222, 8051, 11677, 8921, 8062, 7228, 11071, 11851, 3515, 9011, 5993, 6877, 8080, 1536, 10568, 4103, 9860, 11572, 8700, 1373, 2982, 3448, 11946, 4538, 1908, 4727, 11081, 1866, 7078, 10179, 716, 10125, 6873, 1705, 2450, 11475, 416, 10224, 5826, 7725, 8794, 1756, 4145, 8755, 8328, 5063, 4176, 8524, 10771, 2461, 2275, 8022, 5653, 6693, 6302, 11710, 3889, 212, 6323, 9175, 2769, 5734, 1176, 5508, 11014, 4860, 11164, 11158, 10844, 11841, 1014, 7508, 7365, 10962, 3607, 5232, 8347, 12221, 10029, 7723, 5836, 3200, 1535, 9572, 60, 7784, 10032, 10872, 5676, 3087, 6454, 7406, 3975, 7326, 8545, 2528, 3056, 5845, 5588, 11877, 5102, 1255, 506, 10897, 5784, 9615, 2212, 3338, 9013, 1178, 9513, 6811, 8778, 10347, 3408, 1165, 2575, 10453, 425, 11897, 10104, 377, 4578, 375, 1620, 1038, 11366, 6085, 4167, 6092, 2231, 2800, 12096, 1522, 2151, 8946, 8170, 5002, 12269, 7681, 5163, 10545, 1314, 2894, 3654, 11951, 3947, 9834, 6599, 7350, 7174, 1248, 2442, 8330, 6492, 6330, 10141, 5724, 10964, 1945, 1029, 8945, 6691, 10397, 3624, 6825, 4906, 4670, 512, 7735, 11295, 9389, 12050, 1804, 1403, 6195, 7100, 406, 10602, 7021, 12143, 8914, 9998, 7954, 3393, 8464, 8054, 7376, 8761, 11667, 1737, 4499, 5672, 8307, 9342, 11653, 5609, 4605, 2689, 180, 8151, 5219, 1409, 204, 6780, 9806, 2054, 1344, 9247, 463, 8882, 3981, 1468, 4475, 7043, 3017, 1236, 9168, 4705, 2600, 11232, 4739, 4251, 1226, 6771, 11925, 2360, 3028, 5216, 11839, 10345, 11711, 5368, 11779, 7628, 2622, 6903, 8929, 7605, 7154, 12226, 8481, 8619, 2373, 7302, 10891, 9199, 826, 5043, 5789, 8787, 6671, 10631, 9224, 1506, 7806, 5703, 4719, 11538, 6389, 11379, 4693, 9951, 11872, 9996, 6138, 8820, 4443, 8871, 7186, 10398, 1802, 10734, 1590, 4411, 1223, 2334, 2946, 6828, 2637, 4510, 881, 365, 10362, 1015, 7250, 6742, 2485, 904, 24, 10918, 11009, 11675, 980, 11607, 5082, 7699, 5207, 8239, 844, 7087, 3221, 8016, 8452, 2595, 5289, 6627, 567, 2941, 1406, 2633, 6940, 2945, 3232, 11996, 3769, 7434, 3944, 8190, 6759, 5604, 11024, 9282, 10118, 8809, 9169, 6184, 6643, 6086, 8753, 5370, 8348, 8536, 1282, 3572, 9457, 2021, 4730, 3229, 1706, 3929, 5054, 3154, 9004, 7929, 12282, 1936, 8566, 11444, 11520, 5526, 50, 216, 767, 3805, 4153, 10076, 1279, 11424, 9617, 5170, 12100, 3116, 10080, 1763, 3815, 1734, 1350, 5832, 8420, 4423, 1530, 1694, 10036, 10421, 9559, 5411, 4820, 1160, 9195, 7771, 2840, 9811, 4194, 9270, 7315, 4565, 7211, 10506, 944, 7519, 7002, 8620, 7624, 6883, 3020, 5673, 5410, 1251, 10499, 7014, 2035, 11249, 6164, 10407, 8176, 12217, 10447, 3840, 2712, 4834, 2828, 4352, 1241, 4378, 3451, 4094, 3045, 5781, 9646, 11194, 7592, 8711, 8823, 10588, 7785, 11511, 2626, 530, 10808, 9332, 9349, 2046, 8972, 9757, 8957, 12150, 3268, 3795, 1849, 6513, 4523, 4301, 457, 8, 8835, 3758, 8071, 4390, 10013, 982, 2593, 879, 9687, 10388, 11787, 7171, 6063, 8496, 8443, 1573, 5969, 4649, 9360, 6026, 1030, 11823, 10608, 8468, 11415, 9988, 5650, 12119, 648, 12139, 2307, 8000, 11498, 9855, 9416, 2827, 9754, 11169, 21, 6481];
    // forgefmt: disable-next-line
    uint256[1024] psi_inv_rev = [uint256(1), 10810, 5146, 8246, 11567, 10984, 8155, 6553, 3621, 2545, 3542, 8785, 3195, 5860, 11077, 10643, 9283, 9545, 2975, 11726, 7468, 2639, 2625, 949, 3328, 5777, 7311, 1351, 5828, 7266, 5728, 7698, 4805, 8736, 1062, 2294, 8577, 9154, 7443, 2747, 9970, 1170, 11334, 11499, 3014, 3201, 1326, 5086, 8034, 1177, 2768, 10654, 12149, 10436, 4611, 726, 3051, 9923, 7393, 2963, 9198, 81, 7969, 11289, 8652, 8830, 145, 6747, 8357, 2731, 5911, 7399, 4231, 9741, 8907, 355, 5179, 8595, 8582, 1759, 7901, 1260, 6534, 7657, 9863, 11955, 1428, 1696, 729, 3241, 3289, 2013, 2089, 7197, 9408, 9005, 11462, 6522, 8541, 953, 7222, 10092, 2476, 118, 3949, 8993, 7837, 9893, 12159, 7935, 6915, 9452, 3584, 8112, 9764, 10908, 5331, 4989, 4278, 1673, 480, 2842, 12280, 1022, 9821, 339, 6498, 11745, 10146, 11224, 7644, 404, 11121, 7012, 11082, 3248, 6845, 2381, 4096, 493, 10377, 1378, 4337, 435, 2422, 6250, 2566, 2187, 8643, 9852, 2987, 6267, 8005, 7201, 1002, 5011, 8509, 11414, 1607, 7313, 1067, 7188, 9888, 11847, 3833, 8511, 773, 11899, 4861, 11935, 6591, 9377, 5012, 9808, 9430, 1045, 27, 9223, 3763, 1440, 5084, 1632, 11272, 4885, 11744, 7270, 9611, 3704, 242, 10752, 4143, 4714, 2865, 2370, 8779, 5332, 8311, 9320, 2686, 9042, 2249, 4048, 9405, 1153, 10659, 2126, 5407, 3186, 2399, 3400, 7098, 9153, 671, 3000, 12046, 3016, 10745, 10111, 5559, 11869, 8758, 11813, 4905, 8304, 2645, 8236, 7247, 9984, 7394, 1484, 2780, 5195, 4414, 9442, 4372, 10115, 8232, 3271, 1689, 8925, 113, 4919, 3915, 10123, 4437, 3, 12129, 3149, 3636, 4938, 6998, 9585, 4654, 10863, 10512, 10626, 11848, 922, 4079, 1058, 11177, 10211, 4322, 10331, 709, 8243, 10970, 9139, 4240, 8719, 6065, 835, 10723, 5782, 2948, 2503, 64, 3656, 9830, 11606, 7032, 8455, 7856, 6370, 10542, 3123, 5486, 9235, 6992, 6170, 10929, 8333, 2555, 6167, 11089, 5184, 2692, 168, 3329, 4298, 10327, 1594, 5106, 5961, 8527, 9370, 8212, 8273, 295, 6099, 6523, 11637, 6299, 11130, 8561, 8240, 11341, 1146, 325, 10885, 6347, 1583, 9789, 10800, 1263, 12240, 10806, 5915, 2057, 5369, 4493, 3202, 1815, 6906, 350, 10777, 5735, 9634, 6421, 2738, 723, 12115, 9280, 1693, 10314, 8532, 11942, 9364, 426, 8974, 4754, 10431, 8326, 11713, 6142, 9842, 10238, 10335, 1805, 9407, 3529, 3434, 9381, 12071, 8174, 3030, 10446, 9928, 4737, 10996, 7515, 6860, 8517, 11871, 5908, 11836, 9522, 156, 3969, 3991, 6956, 10258, 10008, 6413, 11099, 2683, 8471, 6171, 11239, 4536, 3860, 5445, 4449, 6833, 147, 3789, 7540, 6752, 4467, 4789, 1041, 8775, 11271, 6364, 10316, 5574, 9945, 1278, 9027, 7210, 522, 2169, 7965, 4916, 4075, 6974, 8724, 654, 1987, 10587, 5529, 7083, 3199, 12233, 6874, 8646, 5862, 6136, 1728, 400, 7341, 6137, 382, 316, 11821, 3988, 6843, 5339, 6093, 8579, 6854, 1359, 1254, 973, 3879, 1922, 3998, 10256, 2302, 11684, 11785, 8076, 9260, 6695, 7507, 6403, 3600, 9026, 6077, 7665, 6068, 8687, 11868, 8209, 11184, 12147, 3477, 6608, 11314, 4212, 8851, 9445, 5009, 1956, 6281, 885, 8757, 1003, 12048, 58, 1010, 5468, 11502, 8807, 8120, 9162, 2920, 7048, 7377, 2049, 1321, 192, 7232, 7591, 4780, 8844, 11612, 5874, 6234, 8953, 9523, 10966, 9115, 12237, 6383, 9784, 10710, 431, 12138, 2127, 9450, 8332, 5808, 12268, 1120, 2535, 9462, 2873, 2434, 791, 4289, 9982, 150, 11641, 170, 6639, 2301, 874, 3821, 1681, 466, 11259, 6263, 2929, 7640, 6320, 10716, 3846, 3793, 6226, 5118, 502, 1901, 2602, 11410, 9696, 11307, 2276, 7899, 4218, 8531, 3454, 12281, 11832, 7988, 7766, 5776, 10440, 8494, 9021, 139, 3332, 2532, 3317, 10243, 2940, 2957, 1481, 11759, 9663, 778, 4504, 1701, 3466, 3578, 4697, 1095, 2643, 6508, 9244, 8195, 8838, 7911, 11048, 7937, 9461, 7455, 9577, 8449, 1842, 72, 4113, 1882, 6125, 1040, 10254, 5275, 1790, 11038, 6879, 6616, 9269, 5406, 4665, 3669, 5287, 4770, 11345, 1783, 5078, 7724, 4974, 3019, 8095, 2478, 9449, 4518, 3094, 11129, 7469, 6878, 2730, 1868, 2253, 10595, 10759, 7866, 3869, 6457, 10939, 10555, 8474, 10526, 2209, 9173, 189, 7119, 2672, 865, 11010, 2213, 8136, 8484, 11522, 12073, 12239, 6763, 769, 845, 3723, 10353, 7, 4360, 3285, 9135, 7235, 8360, 10583, 9060, 7559, 10268, 2832, 8717, 11007, 3753, 3941, 6919, 3536, 6203, 5646, 6105, 3120, 3480, 2171, 3007, 1265, 6685, 5530, 4099, 8345, 4855, 8520, 293, 9057, 9344, 5349, 9656, 10883, 9348, 11722, 5662, 7000, 9694, 3837, 4273, 9068, 5202, 11445, 4050, 7082, 4590, 7207, 682, 11309, 614, 1280, 1371, 12265, 11385, 9804, 5547, 5039, 11274, 1927, 11924, 11408, 7779, 9652, 5461, 9343, 9955, 11066, 7878, 10699, 1555, 10487, 1891, 5103, 3418, 7846, 3469, 6151, 2293, 417, 2338, 7596, 910, 5900, 751, 7570, 6586, 4483, 10783, 3065, 1658, 5618, 3502, 6500, 7246, 11463, 3090, 1398, 4987, 9916, 3670, 3808, 63, 5135, 4684, 3360, 5386, 9667, 4661, 510, 6921, 578, 1944, 450, 7073, 9261, 9929, 364, 5518, 11063, 8038, 7550, 1057, 9689, 7584, 3121, 11053, 9272, 5246, 7814, 10821, 8308, 3407, 11826, 3042, 10945, 10235, 2483, 5509, 12085, 10880, 7070, 4138, 12109, 9600, 7684, 6680, 636, 2947, 3982, 6617, 7790, 10552, 622, 3528, 4913, 4235, 3825, 8896, 4335, 2291, 3375, 146, 5268, 1687, 11883, 5189, 6094, 10886, 10485, 239, 2900, 994, 4554, 11777, 7619, 7383, 5464, 8665, 1892, 5598, 3344, 11260, 10344, 1325, 6565, 2148, 5959, 5797, 3959, 9847, 11041, 5115, 4939, 5690, 2455, 8342, 338, 8635, 9395, 10975, 1744, 7126, 4608, 20, 7287, 4119, 3343, 10138, 10767, 193, 9489, 10058, 6197, 8122, 6204, 923, 11251, 10669, 11914, 7711, 11912, 2185, 392, 11864, 1836, 9714, 11124, 8881, 1942, 3511, 5478, 2776, 11111, 3276, 8951, 10077, 2674, 6505, 1392, 11783, 11034, 7187, 412, 6701, 6444, 9233, 9761, 3744, 4963, 8314, 4883, 5835, 9202, 6613, 1417, 2257, 4505, 12229, 2717, 10754, 9089, 6453, 4566, 2260, 68, 3942, 7057, 8682, 1327, 4924, 4781, 11275, 448, 1445, 1131, 1125, 7429, 1275, 6781, 11113, 6555, 9520, 3114, 5966, 12077, 8400, 579, 5987, 5596, 6636, 4267, 10014, 9828, 1518, 3765, 8113, 7226, 3961, 3534, 8144, 10533, 3495, 4564, 6463, 2065, 11873, 814, 9839, 10584, 5416, 2164, 11573, 2110, 5211, 10423, 1208, 7562, 10381, 7751, 343, 8841, 9307, 10916, 3589, 717, 2429, 8186, 1721, 10753, 4209, 5412, 6296, 3278, 8774, 438, 1218, 5061, 4227, 3368, 612, 4238, 8067, 1526, 540, 125, 6162, 4840, 4032, 9126, 11943, 7885, 1389, 10221, 464, 1928, 3678, 4265, 9084, 8930, 11197, 5209, 8840, 1136, 9051, 8581, 7800, 3171, 2926, 10463];

    //stateful initialisation
    function setUp() public {
        bytes memory bytecode_psirev = abi.encodePacked(psi_rev);

        address a_psirev; //address of the precomputations bytecode contract
        a_psirev = address(uint160(0xcaca)); //here it is etched, use create in the future
        vm.etch(a_psirev, bytecode_psirev); //pushing psirev bytecode into contract todo : replace with create

        bytes memory bytecode_psiInvrev = abi.encodePacked(psi_inv_rev);

        address a_psiInvrev; //address of the precomputations bytecode contract
        a_psiInvrev = address(uint160(0xa5a5)); //here it is etched, use create in the future
        vm.etch(a_psiInvrev, bytecode_psiInvrev); //pushing psirev bytecode into contract todo : replace with create

        ntt.update(a_psirev, a_psiInvrev, 12289, 12265); //update ntt with outer contract

        falcon = new ZKNOX_falcon(ntt);
    }
"""
file.write(header)

for (i, message) in enumerate(["My name is Renaud", "My name is Simon", "My name is Nicolas", "We are ZKNox"]):
    sig = sk.sign(message.encode(),
                  randombytes=lambda x: deterministic_salt(x, seed=str(i)), xof=KeccakPRNG)
    salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
    enc_s = sig[HEAD_LEN + SALT_LEN:]
    s2 = decompress(enc_s, sk.sig_bytelen - HEAD_LEN - SALT_LEN, sk.n)
    s2 = [elt % q for elt in s2]
    assert sk.verify(message.encode(), sig, xof=KeccakPRNG)

    file.write("function testVector{}() public {{\n".format(i))
    file.write("// public key\n")
    file.write("// forgefmt: disable-next-line\n")
    file.write("uint[512] memory tmp_pk = [uint({}), {}];\n".format(
        sk.h[0], ','.join(map(str, sk.h[1:]))))
    file.write("uint[] memory pk = new uint[](512);\n")
    file.write("for (uint i = 0; i < 512; i++) {\n")
    file.write("\tpk[i] = tmp_pk[i];\n")
    file.write("}\n")

    file.write("// signature s2\n")
    file.write("// forgefmt: disable-next-line\n")
    file.write("uint[512] memory tmp_s2 = [uint({}), {}];\n".format(
        s2[0], ','.join(map(str, s2[1:]))))

    file.write("ZKNOX_falcon.Signature memory sig;\n")
    file.write("for (uint i = 0; i < 512; i++) {\n")
    file.write("\tsig.s2[i] = tmp_s2[i];\n")
    file.write("}\n")

    file.write("// message\n")
    file.write("bytes memory message  = \"{}\"; \n".format(message))
    file.write("sig.salt = \"{}\"; \n".format(
        "".join(f"\\x{b:02x}" for b in salt)))
    file.write("bool result = falcon.verify(message, sig, pk);\n")
    file.write("assertEq(true, result);")
    file.write("}\n")
file.write("}\n")
