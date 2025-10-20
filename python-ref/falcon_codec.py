"""
NIST Falcon Binary Codec Functions

These functions implement the NIST Falcon encoding/decoding format
for keys and signatures, based on the C implementation in codec.c.
"""

from common import q
from polyntt.poly import Poly
from polyntt.ntt_iterative import NTTIterative


# Encoding parameters from NIST codec.c
# For f, g: smaller bit widths for higher logn (more constrained)
# These MUST match the reference implementation to decode keys correctly
MAX_FG_BITS = {
    1: 8, 2: 8, 3: 8, 4: 8, 5: 8,
    6: 7, 7: 7, 8: 6, 9: 6, 10: 5
}

# For F, G: constant 8 bits across all parameter sets
MAX_FG_BITS_FG = {
    1: 8, 2: 8, 3: 8, 4: 8, 5: 8,
    6: 8, 7: 8, 8: 8, 9: 8, 10: 8
}


def modq_encode(x, n):
    """
    Encode polynomial x (mod q=12289) using 14 bits per coefficient.

    Args:
        x: List of coefficients (mod q)
        n: Polynomial degree

    Returns:
        bytes: Encoded polynomial
    """
    out_len = ((n * 14) + 7) // 8
    buf = bytearray(out_len)
    acc = 0
    acc_len = 0
    buf_pos = 0

    for coef in x:
        if coef >= 12289 or coef < 0:
            raise ValueError(f"Coefficient {coef} out of range for mod q")
        acc = (acc << 14) | coef
        acc_len += 14
        while acc_len >= 8:
            acc_len -= 8
            buf[buf_pos] = (acc >> acc_len) & 0xFF
            buf_pos += 1

    if acc_len > 0:
        buf[buf_pos] = (acc << (8 - acc_len)) & 0xFF

    return bytes(buf)


def modq_decode(data, n):
    """
    Decode polynomial from binary using 14 bits per coefficient.

    Args:
        data: Encoded bytes
        n: Polynomial degree

    Returns:
        list: Decoded coefficients
    """
    in_len = ((n * 14) + 7) // 8
    if len(data) < in_len:
        raise ValueError(f"Input too short: expected {in_len}, got {len(data)}")

    x = []
    acc = 0
    acc_len = 0
    buf_pos = 0

    while len(x) < n:
        acc = (acc << 8) | data[buf_pos]
        buf_pos += 1
        acc_len += 8
        if acc_len >= 14:
            acc_len -= 14
            w = (acc >> acc_len) & 0x3FFF
            if w >= 12289:
                raise ValueError(f"Decoded value {w} >= q")
            x.append(w)

    if (acc & ((1 << acc_len) - 1)) != 0:
        raise ValueError("Non-zero trailing bits")

    return x


def trim_i8_encode(x, n, bits):
    """
    Encode signed int8 array using 'bits' bits per coefficient.

    Args:
        x: List of signed integers
        n: Number of coefficients
        bits: Bits per coefficient

    Returns:
        bytes: Encoded data
    """
    out_len = ((n * bits) + 7) // 8
    buf = bytearray(out_len)
    acc = 0
    acc_len = 0
    mask = (1 << bits) - 1
    buf_pos = 0

    maxv = (1 << (bits - 1)) - 1
    minv = -maxv

    for coef in x:
        if coef < minv or coef > maxv:
            raise ValueError(f"Coefficient {coef} out of range for {bits} bits")
        acc = (acc << bits) | (coef & mask)
        acc_len += bits
        while acc_len >= 8:
            acc_len -= 8
            buf[buf_pos] = (acc >> acc_len) & 0xFF
            buf_pos += 1

    if acc_len > 0:
        buf[buf_pos] = (acc << (8 - acc_len)) & 0xFF

    return bytes(buf)


def trim_i8_decode(data, n, bits):
    """
    Decode signed int8 array from binary.

    Args:
        data: Encoded bytes
        n: Number of coefficients
        bits: Bits per coefficient

    Returns:
        list: Decoded signed integers
    """
    in_len = ((n * bits) + 7) // 8
    if len(data) < in_len:
        raise ValueError(f"Input too short: expected {in_len}, got {len(data)}")

    x = []
    acc = 0
    acc_len = 0
    mask1 = (1 << bits) - 1
    mask2 = 1 << (bits - 1)
    buf_pos = 0

    while len(x) < n:
        acc = (acc << 8) | data[buf_pos]
        buf_pos += 1
        acc_len += 8
        while acc_len >= bits and len(x) < n:
            acc_len -= bits
            w = (acc >> acc_len) & mask1
            # Sign extension (matches C reference: w |= -(w & mask2))
            w |= -(w & mask2)
            # Check for forbidden value -2^(bits-1)
            if w == -mask2:
                raise ValueError(f"Forbidden value -2^(bits-1) at coefficient {len(x)}")
            x.append(w)

    if (acc & ((1 << acc_len) - 1)) != 0:
        raise ValueError("Non-zero trailing bits")

    return x


def complete_private(f, g, F, n):
    """
    Compute G from f, g, F using the NTRU equation: fG - gF = q (mod phi).

    Args:
        f, g, F: Polynomial coefficients (lists)
        n: Polynomial degree

    Returns:
        list: G polynomial coefficients in signed representation
    """
    poly_f = Poly(f, q, ntt=NTTIterative)
    poly_g = Poly(g, q, ntt=NTTIterative)
    poly_F = Poly(F, q, ntt=NTTIterative)

    # Compute G = (q + g*F) / f (mod q, mod phi)
    numerator = poly_g * poly_F
    numerator_coeffs = numerator.coeffs[:]
    numerator_coeffs[0] = (numerator_coeffs[0] + q) % q
    numerator = Poly(numerator_coeffs, q, ntt=NTTIterative)

    poly_G = numerator / poly_f
    G = poly_G.coeffs

    # Convert to signed representation in range (-q/2, q/2]
    G_signed = [(coef + (q >> 1)) % q - (q >> 1) for coef in G]

    return G_signed
