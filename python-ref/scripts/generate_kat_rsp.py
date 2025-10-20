#!/usr/bin/env python3
"""
Generate ETHFALCON KAT Response (.rsp) file from NIST Falcon KAT Request (.req) file.

This script reads a falcon512-KAT.req file and generates the corresponding
ethfalcon512-KAT.rsp file by running the ZKNOX ETHFALCON implementation (RIP variant).

Usage:
    python scripts/generate_kat_rsp.py test/falcon512-KAT.req test/ethfalcon512-KAT.rsp
"""

import sys
from pathlib import Path

# Add python-ref to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from falcon import HEAD_LEN, SALT_LEN, decompress, SecretKey, PublicKey
from keccak_prng import KeccakPRNG
from shake import SHAKE
from ntrugen import ntru_gen
from encoding import compress
from common import q
from falcon_codec import trim_i8_decode, complete_private, MAX_FG_BITS, MAX_FG_BITS_FG


def parse_kat_req(filepath):
    """Parse a KAT .req file and return list of test vectors"""
    vectors = []
    current_vector = {}

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()

            if not line:
                if current_vector and 'count' in current_vector:
                    vectors.append(current_vector)
                current_vector = {}
                continue

            if ' = ' in line:
                key, value = line.split(' = ', 1)
                key = key.strip()
                value = value.strip()

                if key == 'count':
                    current_vector['count'] = int(value)
                elif key == 'seed':
                    current_vector['seed'] = value
                elif key == 'mlen':
                    current_vector['mlen'] = int(value)
                elif key == 'msg':
                    current_vector['msg'] = value

    # Add last vector if exists
    if current_vector and 'count' in current_vector:
        vectors.append(current_vector)

    return vectors


def bytes_from_hex(hex_str):
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_str)


def encode_public_key(h, n):
    """
    Encode public key in NIST Falcon format.
    For Falcon-512: 1 byte header (0x09) + 896 bytes of h (14 bits per coefficient)
    """
    # Header byte for Falcon-512
    header = bytes([0x09])

    # Encode h coefficients as 14 bits each
    bits = ""
    for coef in h:
        # Ensure coefficient is in range [0, q-1]
        coef = coef % q
        # Encode as 14-bit value
        bits += format(coef, '014b')

    # Convert bit string to bytes
    byte_array = []
    for i in range(0, len(bits), 8):
        byte_val = int(bits[i:i+8], 2)
        byte_array.append(byte_val)

    return header + bytes(byte_array)


def encode_secret_key(f, g, F, G, n):
    """
    Encode secret key in NIST Falcon format.
    This is a simplified encoding - just pack the coefficients.
    """
    # For now, pack all coefficients as signed bytes
    data = []
    for poly in [f, g, F, G]:
        for coef in poly:
            # Encode as signed 16-bit values (big endian)
            if coef < 0:
                val = (1 << 16) + coef  # Two's complement
            else:
                val = coef
            data.append((val >> 8) & 0xFF)
            data.append(val & 0xFF)
    return bytes(data)


def decode_secret_key_nist(sk_hex, n=512):
    """
    Decode secret key from NIST Falcon compressed format.

    NIST Format (from codec.c):
    - Header byte: 0x50 + logn (0x59 for n=512, logn=9)
    - f: trim_i8 encoded with MAX_FG_BITS[logn] bits per coefficient
    - g: trim_i8 encoded with MAX_FG_BITS[logn] bits per coefficient
    - F: trim_i8 encoded with MAX_FG_BITS_FG[logn] bits per coefficient
    - G: computed from f, g, F using complete_private()

    Returns: (f, g, F, G) as lists of signed integers
    """
    sk_bytes = bytes.fromhex(sk_hex)

    # Determine logn from header
    header = sk_bytes[0]
    logn = header - 0x50

    if logn < 1 or logn > 10:
        raise ValueError(f"Invalid header byte: 0x{header:02x}, logn={logn}")

    if n != (1 << logn):
        raise ValueError(f"Mismatch: n={n} but logn={logn} implies n={1 << logn}")

    # Get bit widths for this parameter set
    fg_bits = MAX_FG_BITS[logn]
    FG_bits = MAX_FG_BITS_FG[logn]

    # Calculate lengths
    fg_len = ((n * fg_bits) + 7) // 8
    FG_len = ((n * FG_bits) + 7) // 8

    # Decode f, g, F
    offset = 1  # Skip header

    f = trim_i8_decode(sk_bytes[offset:offset + fg_len], n, fg_bits)
    offset += fg_len

    g = trim_i8_decode(sk_bytes[offset:offset + fg_len], n, fg_bits)
    offset += fg_len

    F = trim_i8_decode(sk_bytes[offset:offset + FG_len], n, FG_bits)
    offset += FG_len

    # Compute G from f, g, F
    G = complete_private(f, g, F, n)

    print(f"Decoded NIST secret key: logn={logn}, n={n}, fg_bits={fg_bits}, FG_bits={FG_bits}")
    print(f"  Total bytes: {offset} (expected ~{len(sk_bytes)})")

    return f, g, F, G


def generate_keypair_from_seed(seed_hex):
    """
    Generate keypair from seed.

    IMPORTANT: Both vanilla Falcon and ETHFALCON use the SAME key generation!
    Uses SHAKE for key generation (same as vanilla Falcon).
    The difference is ONLY in signing: ETHFALCON uses Keccak, vanilla uses SHAKE.

    Returns: (pk_hex, sk_hex, sk_obj) where sk_obj is the SecretKey object for signing
    """
    seed = bytes_from_hex(seed_hex)

    # Use SHAKE for key generation (same as vanilla Falcon)
    prng = SHAKE.new(seed)
    prng.flip()

    # Generate secret key (f, g, F, G)
    n = 512
    f, g, F, G = ntru_gen(n, randombytes=prng.read)

    # Create secret key with the generated polys
    sk = SecretKey(n, [f, g, F, G])

    # Encode public key in NIST format
    pk_bytes = encode_public_key(sk.h, n)
    pk_hex = pk_bytes.hex().upper()

    # Encode secret key
    sk_bytes = encode_secret_key(f, g, F, G, n)
    sk_hex = sk_bytes.hex().upper()

    return pk_hex, sk_hex, sk


def sign_message(sk, msg_hex, seed_hex):
    """
    Sign a message using ETHFALCON (RIP/Keccak variant).

    Args:
        sk: SecretKey object
        msg_hex: Message as hex string
        seed_hex: Seed for deterministic signing

    Returns: (sm_hex, smlen) where sm is the signed message in Solidity-compatible format
    """
    msg = bytes_from_hex(msg_hex)
    seed = bytes_from_hex(seed_hex)

    # Use SHAKE for deterministic signing (same as NIST KAT)
    # The seed generates the random salt and nonce for signing
    prng = SHAKE.new(seed + b'_sign')
    prng.flip()

    # Sign using ETHFALCON: xof=KeccakPRNG is the ETHFALCON variant!
    # The xof parameter determines which hash function to use for hash_to_point
    # Python sig format: header(1) + salt(40) + compressed_signature
    sig = sk.sign(msg, randombytes=prng.read, xof=KeccakPRNG)

    # Extract components from Python signature
    python_header = sig[0:1]  # First byte (e.g., 0x39)
    salt = sig[1:41]  # Bytes 1-40
    compressed_sig = sig[41:]  # Rest is compressed signature

    # Calculate signature length for Solidity format
    # slen includes: salt(40) + message + solidity_header(1) + compressed_sig
    slen = 40 + len(msg) + 1 + len(compressed_sig)

    # Build Solidity-compatible format:
    # slen(2) + salt(40) + message(mlen) + solidity_header(1=0x29) + compressed_sig
    slen_bytes = slen.to_bytes(2, 'big')
    solidity_header = bytes([0x29])  # Solidity expects 0x29 as signature header

    sm = slen_bytes + salt + msg + solidity_header + compressed_sig

    sm_hex = sm.hex().upper()
    smlen = len(sm)

    return sm_hex, smlen


def parse_kat_rsp(filepath):
    """Parse a KAT .rsp file and return list of test vectors with all fields"""
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


def generate_rsp(req_file, rsp_file):
    """Generate ETHFALCON .rsp file using pk/sk from vanilla Falcon"""
    # Parse the vanilla Falcon RSP file to get pk and sk
    vanilla_rsp = req_file.replace('-KAT.req', '-KAT.rsp')
    print(f"Reading vanilla Falcon KAT from {vanilla_rsp}")
    vanilla_vectors = parse_kat_rsp(vanilla_rsp)

    # Parse the request file
    req_vectors = parse_kat_req(req_file)

    print(f"Parsed {len(req_vectors)} test vectors from {req_file}")
    print(f"Parsed {len(vanilla_vectors)} vectors from {vanilla_rsp}")

    with open(rsp_file, 'w') as outfile:
        outfile.write("# Falcon-512\n\n")

        for vec, vanilla_vec in zip(req_vectors, vanilla_vectors):
            count = vec['count']
            seed = vec['seed']
            mlen = vec['mlen']
            msg = vec['msg']

            # Verify we're matching the right vectors
            assert count == int(vanilla_vec['count']), f"Vector mismatch: {count} != {vanilla_vec['count']}"

            print(f"Generating vector {count}...")

            # Use pk and sk from vanilla Falcon KAT (decode NIST compressed format)
            pk_hex = vanilla_vec['pk']
            sk_hex = vanilla_vec['sk']

            # Decode the NIST compressed secret key
            poly_f, poly_g, poly_F, poly_G = decode_secret_key_nist(sk_hex)
            sk_obj = SecretKey(512, [poly_f, poly_g, poly_F, poly_G])

            # Sign the message with ETHFALCON (Keccak)
            sm, smlen = sign_message(sk_obj, msg, seed)

            # Verify the signature is valid before writing
            pk_temp = PublicKey(sk_obj.n, sk_obj.h)
            msg_bytes = bytes.fromhex(msg)
            # Reconstruct Python signature format from Solidity format for verification
            python_sig = bytes([0x39]) + bytes.fromhex(sm)[2:42] + bytes.fromhex(sm)[42 + mlen + 1:]
            if not pk_temp.verify(msg_bytes, python_sig, xof=KeccakPRNG):
                raise ValueError(f"Generated signature for vector {count} failed verification!")

            # Write to output file (using NIST keys from vanilla Falcon KAT)
            outfile.write(f"count = {count}\n")
            outfile.write(f"seed = {seed}\n")
            outfile.write(f"mlen = {mlen}\n")
            outfile.write(f"msg = {msg}\n")
            outfile.write(f"pk = {pk_hex}\n")
            outfile.write(f"sk = {sk_hex}\n")
            outfile.write(f"smlen = {smlen}\n")
            outfile.write(f"sm = {sm}\n")
            outfile.write("\n")

    print(f"✓ Generated {rsp_file}")
    print(f"✓ Used ETHFALCON (RIP/Keccak) variant for signing")


def verify_rsp_file(rsp_file):
    """Verify that an .rsp file can be parsed correctly"""
    try:
        vectors = []
        current_vector = {}

        with open(rsp_file, 'r') as f:
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

        if current_vector and 'count' in current_vector:
            vectors.append(current_vector)

        print(f"\n✓ Successfully parsed {len(vectors)} vectors from {rsp_file}")

        # Verify first vector has all required fields
        if vectors:
            required = ['count', 'seed', 'mlen', 'msg', 'pk', 'sk', 'smlen', 'sm']
            missing = [f for f in required if f not in vectors[0]]
            if missing:
                print(f"✗ Missing fields in vector 0: {missing}")
            else:
                print(f"✓ Vector 0 has all required fields")

        return True
    except Exception as e:
        print(f"✗ Error parsing {rsp_file}: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/generate_kat_rsp.py <req_file> [rsp_file]")
        print("       python scripts/generate_kat_rsp.py ../test/falcon512-KAT.req ../test/ethfalcon512-KAT.rsp")
        sys.exit(1)

    req_file = sys.argv[1]

    if len(sys.argv) >= 3:
        rsp_file = sys.argv[2]
    else:
        # Default: replace .req with .rsp
        rsp_file = req_file.replace('.req', '-generated.rsp')

    if not Path(req_file).exists():
        print(f"Error: {req_file} not found")
        sys.exit(1)

    generate_rsp(req_file, rsp_file)
    verify_rsp_file(rsp_file)
