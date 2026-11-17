"""
Compression and decompression routines for signatures.
"""


# Largest absolute value of a coefficient that the compressed format can
# carry, as in the Falcon specification and the NIST reference code
# (`comp_encode` / `comp_decode`): 7 low bits plus at most 15 high-part
# zeros in unary.
MAX_COMPRESSED_COEF = 2047


def compress(v, slen):
    """
    Take as input a list of integers v and a bytelength slen, and
    return a bytestring of length slen that encode/compress v.
    If this is not possible, return False.

    For each coefficient of v:
    - the sign is encoded on 1 bit
    - the 7 lower bits are encoded naively (binary)
    - the high bits are encoded in unary encoding
    """
    u = ""
    for coef in v:
        # Coefficients outside [-2047, 2047] are not encodable (Falcon spec)
        if abs(coef) > MAX_COMPRESSED_COEF:
            return False
        # Encode the sign
        s = "1" if coef < 0 else "0"
        # Encode the low bits
        s += format((abs(coef) % (1 << 7)), '#09b')[2:]
        # Encode the high bits
        s += "0" * (abs(coef) >> 7) + "1"
        u += s
    # The encoding is too long
    if len(u) > 8 * slen:
        return False
    u += "0" * (8 * slen - len(u))
    w = [int(u[8 * i: 8 * i + 8], 2) for i in range(len(u) // 8)]
    x = bytes(w)
    return x


def decompress(x, slen, n):
    """
    Take as input an encoding x, a bytelength slen and a length n, and
    return a list of integers v of length n such that x encode v.
    If such a list does not exist, the encoding is invalid and we output False.

    Only the canonical encoding is accepted (as in the NIST reference code):
    - |coef| <= 2047, i.e. at most 15 zeros in the unary high part;
    - "-0" is rejected;
    - every bit after the n-th coefficient (padding bits of the last byte
      and padding bytes) must be zero.
    Malformed input (empty, all-zero, truncated) returns False and never
    raises.
    """
    if len(x) > slen:
        return False
    max_high = MAX_COMPRESSED_COEF >> 7
    bits = "".join(format(b, "08b") for b in x)
    nbits = len(bits)
    v = []
    pos = 0
    for _ in range(n):
        # Sign bit and the 7 low bits of abs(coef)
        if pos + 8 > nbits:
            return False
        sign = bits[pos]
        low = int(bits[pos + 1:pos + 8], 2)
        pos += 8
        # High bits of abs(coef), in unary, terminated by a "1"
        high = 0
        while True:
            if pos >= nbits:
                return False
            bit = bits[pos]
            pos += 1
            if bit == "1":
                break
            high += 1
            if high > max_high:
                return False
        coef = low + (high << 7)
        if sign == "1":
            # Enforce a unique encoding for coef = 0
            if coef == 0:
                return False
            coef = -coef
        v.append(coef)
    # Padding bits must be zero
    if "1" in bits[pos:]:
        return False
    return v

def decode16(x:bytes, n: int, q=12289):
    """
    Convert a byte array of even length into a list of 16-bit integers.

    Each pair of bytes is interpreted as:
      byte0 + 2^8 * byte1, byte2 + 2^8 * byte3, ...
    """
    if len(x) % 2 != 0:
        raise ValueError("Length of input must be even")

    out = []
    for i in range(0, len(x), 2):
        val = x[i+1] + (x[i] << 8)
        out.append(val)
    return out
