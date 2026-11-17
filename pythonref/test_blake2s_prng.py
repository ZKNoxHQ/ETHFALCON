import unittest
from hashlib import blake2s
from blake2s_prng import Blake2sPRNG


class testBlake2sPRNG(unittest.TestCase):

    def shortDescription(self):
        return None  # This prevents unittest from printing docstrings

    def test_deterministic(self):
        """The PRNG is deterministic."""
        prng1 = Blake2sPRNG()
        prng1.inject(b"test input")
        prng1.flip()
        output1 = prng1.extract(32)
        prng2 = Blake2sPRNG()
        prng2.inject(b"test input")
        prng2.flip()
        output2 = prng2.extract(32)
        self.assertEqual(output1, output2)

    def test_change_with_size(self):
        """The PRNG is outputs different values for different sizes of output."""
        prng1 = Blake2sPRNG()
        prng1.inject(b"test input")
        prng1.flip()
        output1 = prng1.extract(32)
        prng2 = Blake2sPRNG()
        prng2.inject(b"test input")
        prng2.flip()
        output2 = prng2.extract(64)
        self.assertNotEqual(output1, output2)

    def test_inject_decomposition(self):
        """Check that injecting `testinput` or `test` and ten `input` produces the same output."""
        prng1 = Blake2sPRNG()
        prng1.inject(b"testinput")
        prng1.flip()
        output1 = prng1.extract(32)

        prng2 = Blake2sPRNG()
        prng2.inject(b"test")
        prng2.inject(b"input")
        prng2.flip()
        output2 = prng2.extract(32)
        self.assertEqual(output1, output2)

    def test_extraction(self):
        """Check that three extractions lead to different outputs."""
        prng = Blake2sPRNG()
        prng.inject(b"test sequence")
        prng.flip()
        output1 = prng.extract(16)
        output2 = prng.extract(16)
        output3 = prng.extract(16)
        self.assertNotEqual(output1, output2)
        self.assertNotEqual(output2, output3)
        self.assertNotEqual(output1, output3)

    def test_small_read(self):
        """Check that we can read two bytes as in Falcon."""
        prng = Blake2sPRNG()
        prng.update(b"Test of update")
        prng.flip()
        prng.read(2)
        self.assertTrue(True)

    def test_extract_2_2_vs_4(self):
        prng1 = Blake2sPRNG()
        prng1.update(b"Danette")
        prng1.flip()
        prng2 = Blake2sPRNG()
        prng2.update(b"Danette")
        prng2.flip()
        self.assertEqual(prng1.read(2) + prng1.read(2), prng2.read(4))

    def test_long_input_matches_hashlib(self):
        """No input cap (audit L-6): a long input matches one-shot hashlib.blake2s."""
        data = bytes((5 * i + 1) % 256 for i in range(5000))
        prng = Blake2sPRNG()
        prng.inject(data[:1234])
        prng.inject(data[1234:])
        prng.flip()
        output = prng.read(70)
        state = blake2s(data, digest_size=32).digest()
        expected = b"".join(blake2s(state + i.to_bytes(8, "big"), digest_size=32).digest()
                            for i in range(3))[:70]
        self.assertEqual(output, expected)
