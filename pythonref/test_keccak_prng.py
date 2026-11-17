import unittest
from eth_hash import auto as eth_hash_auto
from falcon import PublicKey, SecretKey, hash_to_point
from keccak import KeccakHash
from keccak_prng import KeccakPRNG
from scripts.sign_KAT import sign_KAT

# Values obtained from `./c/test_prng` in Zhenfei Zhang's repository:
# https://github.com/zhenfeizhang/falcon-go/blob/main/c/test_prng

# Test vector 1:
# with extract(32)
# input "test input"
# input in hex: "7465737420696e707574"
output_test_input_32 = "5b9e99370fa4b753ac6bf0d246b3cec353c84a67839f5632cb2679b4ae565601"

# Test vector 2:
# extract(64), last half
# input "test input"
# input in hex: "7465737420696e707574"
output_test_input_64 = "569857b781dd8b81dd9cb45d06999916742043ff52f1cf165e161bcc9938b705"

# Test vector 3:
# extract(32)
# input "testinput"
# input in hex: "74657374696e707574"
output_testinput_32 = "120f76b5b7198706bc294a942f8d17467aadb2bb1fa2cc1fecadbaba93c0dd74"

# Test vectors 4:
# extract(32) three times (only 16 bytes)
# input "test sequence"
# input in hex: "746573742073657175656e6365"
output_test_sequence_32_1 = "9e96b1e50719da6f0ea5b664ac8bbac5"
output_test_sequence_32_2 = "eb409b4db770b124363b393a0c96b5d6"
output_test_sequence_32_3 = "1be071eca45961aca979e88e3784a751"


class TestKeccakPRNG(unittest.TestCase):
    """
    We follow the tests provided by Zhenfei Zhang here:
    https://github.com/zhenfeizhang/falcon-go/blob/main/c/test_prng.c
    """

    def shortDescription(self):
        return None  # This prevents unittest from printing docstrings

    def test_deterministic(self):
        """The PRNG is deterministic."""
        prng1 = KeccakPRNG()
        prng1.inject(b"test input")
        prng1.flip()
        output1 = prng1.extract(32)
        prng2 = KeccakPRNG()
        prng2.inject(b"test input")
        prng2.flip()
        output2 = prng2.extract(32)
        self.assertEqual(output1, output2)
        self.assertEqual(output1.hex(), output_test_input_32)

    def test_change_with_size(self):
        """The PRNG is outputs different values for different sizes of output."""
        prng1 = KeccakPRNG()
        prng1.inject(b"test input")
        prng1.flip()
        output1 = prng1.extract(32)
        prng2 = KeccakPRNG()
        prng2.inject(b"test input")
        prng2.flip()
        output2 = prng2.extract(64)
        self.assertNotEqual(output1, output2)
        self.assertEqual(output2.hex()[64:], output_test_input_64)

    def test_inject_decomposition(self):
        """Check that injecting `testinput` or `test` and ten `input` produces the same output."""
        prng1 = KeccakPRNG()
        prng1.inject(b"testinput")
        prng1.flip()
        output1 = prng1.extract(32)

        prng2 = KeccakPRNG()
        prng2.inject(b"test")
        prng2.inject(b"input")
        prng2.flip()
        output2 = prng2.extract(32)

        self.assertEqual(output1, output2)
        self.assertEqual(output1.hex(), output_testinput_32)

    def test_extraction(self):
        """Check that three extractions lead to different outputs."""
        prng = KeccakPRNG()
        prng.inject(b"test sequence")
        prng.flip()
        output1 = prng.extract(16)
        output2 = prng.extract(16)
        output3 = prng.extract(16)
        self.assertNotEqual(output1, output2)
        self.assertNotEqual(output2, output3)
        self.assertNotEqual(output1, output3)
        self.assertEqual(output1.hex(), output_test_sequence_32_1)
        self.assertEqual(output2.hex(), output_test_sequence_32_2)
        self.assertEqual(output3.hex(), output_test_sequence_32_3)

    def test_small_read(self):
        """Check that we can read two bytes as in Falcon."""
        prng = KeccakPRNG()
        prng.update(b"Test of update")
        prng.flip()
        prng.read(2)
        self.assertTrue(True)

    def test_extract_2_2_vs_4(self):
        prng1 = KeccakPRNG()
        prng1.update(b"Danette")
        prng1.flip()
        prng2 = KeccakPRNG()
        prng2.update(b"Danette")
        prng2.flip()
        self.assertEqual(prng1.read(2) + prng1.read(2), prng2.read(4))

    def test_long_input_matches_independent_keccak(self):
        """
        No input cap (audit L-6): a > 4096-byte input gives the same stream as
        keccak256(input), then keccak256(state || uint64_be(counter)),
        computed with two independent Keccak implementations.
        """
        salt = bytes(range(40))
        message = bytes((7 * i + 3) % 256 for i in range(10000))
        prng = KeccakPRNG()
        prng.inject(salt)
        for i in range(0, len(message), 1000):
            prng.inject(message[i:i + 1000])
        prng.flip()
        output = prng.read(3) + prng.read(197)
        for keccak256 in (eth_hash_keccak, pure_python_keccak):
            self.assertEqual(output, reference_stream(salt + message, 200, keccak256))

    def test_hash_to_point_long_message(self):
        """hash_to_point(KeccakPRNG) on a long message matches hashToPointEVM's construction."""
        salt = bytes(range(100, 140))
        message = b"ETHFALCON" * 1000  # 9000 bytes
        self.assertEqual(hash_to_point(512, message, salt, xof=KeccakPRNG),
                         reference_hash_to_point_evm(salt, message, eth_hash_keccak))

    def test_sign_verify_long_message(self):
        """ETHFALCON signs and verifies a message larger than the old 4096-byte cap."""
        f, g, F, G = (sign_KAT[512][0][k] for k in ("f", "g", "F", "G"))
        sk = SecretKey(512, [f, g, F, G])
        pk = PublicKey(512, sk.h)
        message = bytes(5000)
        sig = sk.sign(message, xof=KeccakPRNG)
        self.assertTrue(pk.verify(message, sig, xof=KeccakPRNG))
        self.assertFalse(pk.verify(b"", sig, xof=KeccakPRNG))


def eth_hash_keccak(data):
    return eth_hash_auto.keccak(data)


def pure_python_keccak(data):
    # keccak.py: numpy Keccak-f[1600], independent of pycryptodome
    K = KeccakHash(rate=200 - (512 // 8), dsbyte=0x01)
    K.absorb(data)
    K.pad()
    return K.squeeze(32)


def reference_stream(data, length, keccak256):
    state = keccak256(data)
    out, counter = b"", 0
    while len(out) < length:
        out += keccak256(state + counter.to_bytes(8, "big"))
        counter += 1
    return out[:length]


def reference_hash_to_point_evm(salt, message, keccak256, n=512, q=12289):
    """Line-by-line port of hashToPointEVM (src/ZKNOX_HashToPoint.sol)."""
    kq = (1 << 16) // q * q  # 61445
    state = keccak256(salt + message)
    output, counter = [], 0
    while len(output) < n:
        block = keccak256(state + counter.to_bytes(8, "big"))
        for j in range(16):
            chunk = int.from_bytes(block[2 * j:2 * j + 2], "big")
            if chunk < kq:
                output.append(chunk % q)
                if len(output) == n:
                    break
        counter += 1
    return output
