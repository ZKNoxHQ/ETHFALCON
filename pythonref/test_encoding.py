"""
Canonical signature decoding and malformed-input handling (audit L-4, L-5).
"""
import os
import random
import unittest

from common import q
from encoding import compress, decompress, MAX_COMPRESSED_COEF
from falcon import HEAD_LEN, SALT_LEN, PublicKey, SecretKey
from falcon_epervier import EpervierPublicKey, EpervierSecretKey
from falcon_recovery import RecoveryModePublicKey, RecoveryModeSecretKey
from keccak_prng import KeccakPRNG
from scripts.sign_KAT import sign_KAT
from shake import SHAKE

n = 512
KAT = sign_KAT[n][0]
POLYS = [KAT["f"], KAT["g"], KAT["F"], KAT["G"]]
SLEN = 666 - HEAD_LEN - SALT_LEN


def bits_to_bytes(bits):
    bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


class TestDecompress(unittest.TestCase):

    def test_roundtrip_extremes(self):
        v = [MAX_COMPRESSED_COEF, -MAX_COMPRESSED_COEF, 0, 1, -1, 127, -128]
        enc = compress(v, 40)
        self.assertEqual(decompress(enc, 40, len(v)), v)

    def test_compress_rejects_out_of_range(self):
        self.assertIs(compress([MAX_COMPRESSED_COEF + 1], 40), False)
        self.assertIs(compress([-MAX_COMPRESSED_COEF - 1], 40), False)

    def test_unary_limit(self):
        # 2047 = 127 + 15 * 128: 15 zeros in unary is the maximum.
        ok = "0" + "1111111" + "0" * 15 + "1"
        self.assertEqual(decompress(bits_to_bytes(ok), 3, 1), [2047])
        # 16 zeros would be 2048 + low bits: rejected.
        too_long = "0" + "0000000" + "0" * 16 + "1"
        self.assertIs(decompress(bits_to_bytes(too_long), 4, 1), False)

    def test_minus_zero_rejected(self):
        self.assertIs(decompress(bits_to_bytes("1" + "0000000" + "1"), 2, 1), False)

    def test_padding_bits_must_be_zero(self):
        enc = "0" + "0000001" + "1"  # coefficient 1, 9 bits
        self.assertEqual(decompress(bits_to_bytes(enc), 2, 1), [1])
        # non-zero padding bit in the last byte
        self.assertIs(decompress(bits_to_bytes(enc + "0000001"), 2, 1), False)
        # zero padding byte: accepted; non-zero padding byte: rejected
        self.assertEqual(decompress(bits_to_bytes(enc) + b"\x00", 3, 1), [1])
        self.assertIs(decompress(bits_to_bytes(enc) + b"\x01", 3, 1), False)

    def test_malformed_input_returns_false(self):
        # L-5: none of these may raise
        self.assertIs(decompress(b"", SLEN, n), False)
        self.assertIs(decompress(b"\x00", SLEN, n), False)
        self.assertIs(decompress(b"\x00" * SLEN, SLEN, n), False)
        self.assertIs(decompress(b"\xff" * SLEN, SLEN, n), False)
        self.assertIs(decompress(b"\x00" * (SLEN + 1), SLEN, n), False)
        enc = compress([3] * n, SLEN)
        self.assertIs(decompress(enc[:100], SLEN, n), False)

    def test_random_input_never_raises(self):
        rng = random.Random(1)
        for _ in range(300):
            x = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, SLEN + 2)))
            self.assertIn(type(decompress(x, SLEN, n)), (list, bool))


class TestFalconVerifierStrictness(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sk = SecretKey(n, POLYS)
        cls.pk = PublicKey(n, cls.sk.h)
        cls.msg = b"canonical encoding"
        cls.sig = cls.sk.sign(cls.msg, randombytes=cls.sk.signing_randombytes(
            cls.msg, deterministic=True), xof=KeccakPRNG)

    def test_valid(self):
        self.assertTrue(self.pk.verify(self.msg, self.sig, xof=KeccakPRNG))
        self.assertEqual(self.sig[0], 0x29)

    def test_padding_bit_flip_rejected(self):
        self.assertEqual(self.sig[-1], 0)  # the encoding is zero-padded
        forged = self.sig[:-1] + b"\x01"
        self.assertFalse(self.pk.verify(self.msg, forged, xof=KeccakPRNG))

    def test_header_checked(self):
        for header in (0x39, 0x2a, 0x00, 0x59):
            forged = bytes([header]) + self.sig[1:]
            self.assertFalse(self.pk.verify(self.msg, forged, xof=KeccakPRNG))

    def test_malformed_signatures_do_not_raise(self):
        for sig in (b"", b"\x29", b"\x29" + b"\x00" * 40, b"\x29" + b"\x00" * 41,
                    b"\x29" + b"\x00" * 700, self.sig[:41], self.sig + b"\x00"):
            self.assertFalse(self.pk.verify(self.msg, sig, xof=KeccakPRNG))
            self.assertFalse(self.pk.verify(self.msg, sig, xof=SHAKE))


class TestRecoveryVerifierStrictness(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.msg = b"recovery hint"
        cls.cases = []
        for SK, PK, xof in [(EpervierSecretKey, EpervierPublicKey, SHAKE),
                            (RecoveryModeSecretKey, RecoveryModePublicKey, KeccakPRNG)]:
            sk = SK(n, POLYS)
            sig = sk.sign(cls.msg, randombytes=sk.signing_randombytes(
                cls.msg, deterministic=True), xof=xof)
            cls.cases.append((PK(n, sk.pk), sig, xof))

    def test_valid(self):
        for pk, sig, xof in self.cases:
            self.assertTrue(pk.verify(self.msg, sig, xof=xof))
            self.assertEqual(sig[0], 0x39)

    def test_hint_plus_q_rejected(self):
        for pk, sig, xof in self.cases:
            off = len(sig) - 3 * n
            entry = int.from_bytes(sig[off:off + 3], "big")
            self.assertLess(entry, q)
            forged = sig[:off] + (entry + q).to_bytes(3, "big") + sig[off + 3:]
            self.assertFalse(pk.verify(self.msg, forged, xof=xof))

    def test_padding_and_header_rejected(self):
        for pk, sig, xof in self.cases:
            idx = len(sig) - 3 * n - 1  # last byte of the compressed (s0, s1)
            self.assertEqual(sig[idx], 0)
            forged = sig[:idx] + b"\x01" + sig[idx + 1:]
            self.assertFalse(pk.verify(self.msg, forged, xof=xof))
            self.assertFalse(pk.verify(self.msg, b"\x29" + sig[1:], xof=xof))

    def test_malformed_signatures_do_not_raise(self):
        for pk, sig, xof in self.cases:
            for bad in (b"", b"\x39", sig[:-1], sig + b"\x00", b"\x39" + b"\x00" * (len(sig) - 1)):
                self.assertFalse(pk.verify(self.msg, bad, xof=xof))


if __name__ == "__main__":
    unittest.main()
