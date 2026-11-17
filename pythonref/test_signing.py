"""
Signing randomness (audit C-1) and secret key validation / signature
self-check (audit L-10).
"""
import copy
import unittest

from falcon import HEAD_LEN, SALT_LEN, PublicKey, SecretKey, check_ntru_equation
from falcon_epervier import EpervierPublicKey, EpervierSecretKey
from falcon_recovery import RecoveryModePublicKey, RecoveryModeSecretKey
from keccak_prng import KeccakPRNG
from scripts.sign_KAT import sign_KAT
from shake import SHAKE

n = 512
KAT = sign_KAT[n][0]
POLYS = [KAT["f"], KAT["g"], KAT["F"], KAT["G"]]


def salt_of(sig):
    return sig[HEAD_LEN:HEAD_LEN + SALT_LEN]


class TestSigningRandomness(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        sk = SecretKey(n, POLYS)
        cls.cases = [
            (sk, PublicKey(n, sk.h), SHAKE),
            (sk, PublicKey(n, sk.h), KeccakPRNG),
        ]
        for SK, PK, xof in [(EpervierSecretKey, EpervierPublicKey, SHAKE),
                            (RecoveryModeSecretKey, RecoveryModePublicKey, KeccakPRNG)]:
            esk = SK(n, POLYS)
            cls.cases.append((esk, PK(n, esk.pk), xof))
        cls.msg = b"same message"

    def test_hedged_signatures_differ_and_verify(self):
        for sk, pk, xof in self.cases:
            sig1 = sk.sign(self.msg, randombytes=sk.signing_randombytes(self.msg), xof=xof)
            sig2 = sk.sign(self.msg, randombytes=sk.signing_randombytes(self.msg), xof=xof)
            self.assertNotEqual(sig1, sig2)
            self.assertNotEqual(salt_of(sig1), salt_of(sig2))
            self.assertTrue(pk.verify(self.msg, sig1, xof=xof))
            self.assertTrue(pk.verify(self.msg, sig2, xof=xof))

    def test_deterministic_is_reproducible(self):
        for sk, pk, xof in self.cases:
            sig1 = sk.sign(self.msg, randombytes=sk.signing_randombytes(
                self.msg, deterministic=True), xof=xof)
            sig2 = sk.sign(self.msg, randombytes=sk.signing_randombytes(
                self.msg, deterministic=True), xof=xof)
            self.assertEqual(sig1, sig2)
            self.assertTrue(pk.verify(self.msg, sig1, xof=xof))

    def test_deterministic_separation(self):
        sk = self.cases[0][0]

        def stream(msg, **kw):
            return sk.signing_randombytes(msg, **kw)(64)
        base = stream(self.msg, deterministic=True)
        self.assertEqual(base, stream(self.msg, deterministic=True))
        self.assertNotEqual(base, stream(self.msg + b"!", deterministic=True))
        self.assertNotEqual(base, stream(self.msg, deterministic=True, context=b"ethfalcon"))
        self.assertNotEqual(base, stream(self.msg))  # hedged

    def test_stream_is_keyed_by_the_secret_basis(self):
        """
        The old derivation hashed only the public key h and the message. Here
        two keys with the same h but a different secret part (F, G) give
        unrelated streams, so (pk, message) does not determine the coins.
        """
        sk = self.cases[0][0]
        other = copy.copy(sk)
        other.F = [c + 1 for c in sk.F]
        other.G = [c - 1 for c in sk.G]
        self.assertEqual(other.h, sk.h)
        self.assertNotEqual(sk.signing_randombytes(self.msg, deterministic=True)(88),
                            other.signing_randombytes(self.msg, deterministic=True)(88))


class TestKeyValidation(unittest.TestCase):

    def test_valid_keys(self):
        self.assertTrue(check_ntru_equation(*POLYS))
        for SK in (SecretKey, EpervierSecretKey, RecoveryModeSecretKey):
            self.assertTrue(SK(n, POLYS).validate())

    def test_corrupted_key_rejected(self):
        F = POLYS[2][:]
        F[0] += 1
        bad = [POLYS[0], POLYS[1], F, POLYS[3]]
        self.assertFalse(check_ntru_equation(*bad))
        sk = SecretKey(n, bad)
        with self.assertRaises(ValueError):
            sk.validate()
        # Without validation, the signature self-check refuses to return the
        # invalid signature (it would leak a skewed distribution).
        with self.assertRaises(ValueError):
            sk.sign(b"abc", xof=SHAKE)
        with self.assertRaises(ValueError):
            EpervierSecretKey(n, bad).sign(b"abc", xof=SHAKE)

    def test_inconsistent_h_rejected(self):
        sk = SecretKey(n, POLYS)
        sk.h = [(c + 1) % 12289 for c in sk.h]
        with self.assertRaises(ValueError):
            sk.validate()
        with self.assertRaises(ValueError):
            sk.sign(b"abc", xof=KeccakPRNG)


if __name__ == "__main__":
    unittest.main()
