import hashlib
from falcon import HEAD_LEN, SALT_LEN, Params, decompress, SecretKey, PublicKey
from falcon_epervier import EpervierSecretKey
from polyntt.poly import Poly
from common import q


def deterministic_salt(x, seed="deterministic_salt"):
    # This function is used for generating deterministic salt for the tests.
    # Don't use this for a PRNG!
    first_bytes = hashlib.sha256(f"{seed}{x}".encode()).digest()
    last_bytes = hashlib.sha256(f"{seed}".encode()+first_bytes).digest()
    return first_bytes + last_bytes[0:8]


file = open("../test/EpervierTestVectors.sol", 'w')
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

sk = EpervierSecretKey(n, [f, g, F, G])

header = """
// code generated using pythonref/generate_epervier_test_vectors.py.
// XOF: KeccakPRNG
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Falcon} from "../src/ETHFalcon_Recursive.sol";

contract EpervierTestVectors is Test {
    int constant q = 12289;
    Falcon falcon;

    function setUp() public {
        falcon = new Falcon();
    }
"""
file.write(header)

for (i, message) in enumerate(["My name is Renaud", "My name is Simon", "My name is Nicolas", "We are ZKNox"]):
    sig = sk.sign(message.encode(),
                  randombytes=deterministic_salt)
    salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
    enc_s = sig[HEAD_LEN + SALT_LEN:-sk.n*3]
    s = decompress(enc_s, sk.sig_bytelen*2 - HEAD_LEN - SALT_LEN, sk.n*2)
    mid = len(s)//2
    s = [elt % q for elt in s]
    s0, s1 = s[:mid], s[mid:]
    s1_inv_ntt = Poly(s1, q).inverse().ntt()
    h = sk.hash_to_point(salt, message.encode())
    h_ntt = Poly(h, q).ntt()
    assert sk.verify(message.encode(), sig)

    file.write("function testVector{}() public view {{\n".format(i))
    file.write("// public key\n")
    file.write("// forgefmt: disable-next-line\n")
    file.write("uint[512] memory tmp_pk = [uint({}), {}];\n".format(
        sk.pk[0], ','.join(map(str, sk.pk[1:]))))
    file.write("uint[] memory pk = new uint[](512);\n")
    file.write("for (uint i = 0; i < 512; i++) {\n")
    file.write("\tpk[i] = tmp_pk[i];\n")
    file.write("}\n")

    file.write("// signature s0\n")
    file.write("// forgefmt: disable-next-line\n")
    file.write("int[512] memory tmp_s0 = [int({}), {}];\n".format(
        s0[0], ','.join(map(str, s0[1:]))))
    file.write("// signature s1\n")
    file.write("// forgefmt: disable-next-line\n")
    file.write("int[512] memory tmp_s1 = [int({}), {}];\n".format(
        s1[0], ','.join(map(str, s1[1:]))))
    file.write("Epervier.Signature memory sig;\n")
    file.write("sig.s0 = new int256[](512);\n")
    file.write("for (uint i = 0; i < 512; i++) {\n")
    file.write("\tsig.s0[i] = tmp_s0[i];\n")
    file.write("}\n")
    file.write("sig.s1 = new int256[](512);\n")
    file.write("for (uint i = 0; i < 512; i++) {\n")
    file.write("\tsig.s1[i] = tmp_s1[i];\n")
    file.write("}\n")

    file.write("// signature s1 inverse ntt\n")
    file.write("// forgefmt: disable-next-line\n")
    file.write("int[512] memory tmp_s1_inv_ntt = [int({}), {}];\n".format(
        s1_inv_ntt[0], ','.join(map(str, s1_inv_ntt[1:]))))

    file.write("// message\n")
    file.write("bytes memory message  = \"{}\"; \n".format(message))
    file.write('// salt and message hack because of Tetration confusion\n')
    file.write("sig.salt = message;\nmessage = \"{}\"; \n".format(
        "".join(f"\\x{b:02x}" for b in salt)))
    file.write("epervier.verify(message, sig, pk);\n")
    file.write("}\n")
file.write("}\n")
