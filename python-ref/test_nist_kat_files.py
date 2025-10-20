#!/usr/bin/env python3
"""
Test NIST KAT files for both vanilla Falcon and ETHFALCON.

This test verifies:
1. Vanilla Falcon KAT vectors from test/falcon512-KAT.rsp (SHAKE256)
2. ETHFALCON KAT vectors from test/ethfalcon512-KAT.rsp (Keccak)
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from falcon import PublicKey
from shake import SHAKE
from keccak_prng import KeccakPRNG


def parse_kat_rsp(filepath):
    """Parse a KAT .rsp file and return list of test vectors"""
    vectors = []
    current_vector = {}

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith('#'):
                if current_vector and 'count' in current_vector:
                    vectors.append(current_vector)
                current_vector = {}
                continue

            if ' = ' in line:
                key, value = line.split(' = ', 1)
                current_vector[key.strip()] = value.strip()

    # Add last vector if exists
    if current_vector and 'count' in current_vector:
        vectors.append(current_vector)

    return vectors


def decode_public_key(pk_hex, n=512):
    """Decode NIST public key format (14 bits per coefficient)"""
    pk_bytes = bytes.fromhex(pk_hex)

    if pk_bytes[0] != 0x09:
        raise ValueError(f"Invalid public key header: 0x{pk_bytes[0]:02x}")

    # Decode h coefficients (14 bits each)
    bits = ""
    for byte_val in pk_bytes[1:]:
        bits += format(byte_val, '08b')

    h = []
    q = 12289
    for i in range(0, n * 14, 14):
        if i + 14 <= len(bits):
            coef = int(bits[i:i+14], 2)
            h.append(coef % q)

    return h


def extract_signature_from_sm(sm_hex, mlen):
    """
    Extract signature from signed message format.

    Solidity format: slen(2) + salt(40) + message(mlen) + header(0x29) + compressed_sig
    Python format: header(0x39) + salt(40) + compressed_sig
    """
    sm_bytes = bytes.fromhex(sm_hex)

    # Extract components from Solidity format
    salt = sm_bytes[2:42]  # Skip slen(2), take salt(40)
    compressed_sig = sm_bytes[42 + mlen + 1:]  # Skip slen + salt + message + header

    # Build Python signature format
    python_sig = bytes([0x39]) + salt + compressed_sig

    return python_sig


class TestNISTKATFiles(unittest.TestCase):

    def test_vanilla_falcon_kat(self):
        """Test vanilla Falcon KAT vectors from test/falcon512-KAT.rsp"""
        kat_file = Path(__file__).parent.parent / "test" / "falcon512-KAT.rsp"

        if not kat_file.exists():
            self.skipTest(f"KAT file not found: {kat_file}")

        vectors = parse_kat_rsp(kat_file)
        print(f"\nTesting {len(vectors)} vanilla Falcon KAT vectors...")

        passed = 0
        failed = 0

        for vec in vectors:
            count = int(vec['count'])
            mlen = int(vec['mlen'])
            msg = bytes.fromhex(vec['msg'])
            pk_hex = vec['pk']
            sm_hex = vec['sm']

            # Decode public key
            h = decode_public_key(pk_hex)
            pk = PublicKey(512, h)

            # Extract signature
            sig = extract_signature_from_sm(sm_hex, mlen)

            # Verify with SHAKE (vanilla Falcon)
            if pk.verify(msg, sig, xof=SHAKE):
                passed += 1
                print(f"  ✓ Vector {count} passed")
            else:
                failed += 1
                print(f"  ✗ Vector {count} FAILED")
                self.fail(f"Vanilla Falcon KAT vector {count} failed verification")

        print(f"\nVanilla Falcon KAT: {passed} passed, {failed} failed")
        self.assertEqual(failed, 0, "All vanilla Falcon KAT vectors should pass")

    def test_ethfalcon_kat(self):
        """Test ETHFALCON KAT vectors from test/ethfalcon512-KAT.rsp"""
        kat_file = Path(__file__).parent.parent / "test" / "ethfalcon512-KAT.rsp"

        if not kat_file.exists():
            self.skipTest(f"KAT file not found: {kat_file}")

        vectors = parse_kat_rsp(kat_file)
        print(f"\nTesting {len(vectors)} ETHFALCON KAT vectors...")

        passed = 0
        failed = 0

        for vec in vectors:
            count = int(vec['count'])
            mlen = int(vec['mlen'])
            msg = bytes.fromhex(vec['msg'])
            pk_hex = vec['pk']
            sm_hex = vec['sm']

            # Decode public key
            h = decode_public_key(pk_hex)
            pk = PublicKey(512, h)

            # Extract signature
            sig = extract_signature_from_sm(sm_hex, mlen)

            # Verify with KeccakPRNG (ETHFALCON)
            if pk.verify(msg, sig, xof=KeccakPRNG):
                passed += 1
                print(f"  ✓ Vector {count} passed")
            else:
                failed += 1
                print(f"  ✗ Vector {count} FAILED")
                self.fail(f"ETHFALCON KAT vector {count} failed verification")

        print(f"\nETHFALCON KAT: {passed} passed, {failed} failed")
        self.assertEqual(failed, 0, "All ETHFALCON KAT vectors should pass")


if __name__ == '__main__':
    unittest.main()
