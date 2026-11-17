"""
Demonstration of the salt/message concatenation ambiguity (CVETH-2025-080201)
and of why it does not apply to ETHFALCON.

ETHFALCON hashes salt || message with KeccakPRNG. If a verifier takes the
salt as a separate, variable-length argument (as the vulnerable Tetration
implementation did), a signature on (message, salt) is also a valid
signature on (salt || message, "") or on any other split of the same bytes:
the hash-to-point input is identical.

Every verifier in this repository requires a 40-byte salt:
- Solidity: `ZKNOX_falcon` / `ZKNOX_ethfalcon` revert or return false unless
  `salt.length == 40`;
- Python: `PublicKey.verify` reads the salt at a fixed offset and rejects
  signatures too short to contain a full salt.
So only one split exists and the forgery fails.

Run: python forgery.py
"""
from common import q
from encoding import decompress
from falcon import HEAD_LEN, SALT_LEN, Params, PublicKey, SecretKey, hash_to_point
from keccak_prng import KeccakPRNG
from scripts.sign_KAT import sign_KAT

n = 512
XOF = KeccakPRNG  # ETHFALCON

# A fixed example key (from the Falcon KATs) to avoid key generation time.
kat = sign_KAT[n][0]
sk = SecretKey(n, [kat["f"], kat["g"], kat["F"], kat["G"]])
pk = PublicKey(n, sk.h)

salt = b"Send ______ 1 USDC ______ to vitalik.eth"
message = b" and 50000 USDC to RektMe.eth!"
assert len(salt) == SALT_LEN


def chosen_salt_randombytes(chosen_salt, secret_randombytes):
    """Return `chosen_salt` for the salt, secret randomness for the sampler."""
    state = {"salt_given": False}

    def randombytes(k):
        if not state["salt_given"]:
            state["salt_given"] = True
            assert k == SALT_LEN
            return chosen_salt
        return secret_randombytes(k)
    return randombytes


def verify_detached(public_key, msg, slt, enc_s, require_salt_len):
    """
    Verifier with the salt passed separately, as in the Solidity API
    verify(message, salt, s2, pk). With `require_salt_len=False` it behaves
    like the vulnerable implementation.
    """
    if require_salt_len and len(slt) != SALT_LEN:
        return False
    s1 = decompress(enc_s, Params[n]["sig_bytelen"] - HEAD_LEN - SALT_LEN, n)
    if s1 is False:
        return False
    hashed = hash_to_point(n, msg, slt, xof=XOF)
    # s0 = hashed - s1 * h mod (x^n + 1, q), naive negacyclic product
    s1h = [0] * n
    for i, a in enumerate(s1):
        if a == 0:
            continue
        for j, b in enumerate(public_key.pk):
            k = i + j
            if k < n:
                s1h[k] += a * b
            else:
                s1h[k - n] -= a * b
    s0 = [(hashed[i] - s1h[i]) % q for i in range(n)]
    s0 = [(c + (q >> 1)) % q - (q >> 1) for c in s0]
    norm = sum(c * c for c in s0) + sum(c * c for c in s1)
    return norm <= Params[n]["sig_bound"]


sig = sk.sign(message,
              randombytes=chosen_salt_randombytes(salt, sk.signing_randombytes(message)),
              xof=XOF)
assert sig[HEAD_LEN:HEAD_LEN + SALT_LEN] == salt
enc_s = sig[HEAD_LEN + SALT_LEN:]

# The honest signature verifies.
assert pk.verify(message, sig, xof=XOF)
assert verify_detached(pk, message, salt, enc_s, require_salt_len=True)
print("honest (message, salt)                  : accepted")

# Forged splits of the same bytes salt || message.
forgeries = [
    ("(salt || message, empty salt)", salt + message, b""),
    ("(message[5:], salt || message[:5])", message[5:], salt + message[:5]),
    ("(salt[20:] || message, salt[:20])", salt[20:] + message, salt[:20]),
]
for name, forged_message, forged_salt in forgeries:
    vulnerable = verify_detached(pk, forged_message, forged_salt, enc_s, require_salt_len=False)
    fixed = verify_detached(pk, forged_message, forged_salt, enc_s, require_salt_len=True)
    # In the Python signature format the salt sits at a fixed offset.
    python_format = pk.verify(forged_message, sig[:HEAD_LEN] + forged_salt + enc_s, xof=XOF)
    print("forged {:38s}: variable-length salt verifier {}, 40-byte salt verifier {}, PublicKey.verify {}".format(
        name,
        "ACCEPTS" if vulnerable else "rejects",
        "ACCEPTS" if fixed else "rejects",
        "ACCEPTS" if python_format else "rejects"))
    # The ambiguity is real for a variable-length salt...
    assert vulnerable
    # ...and the fixed 40-byte salt check defeats it.
    assert not fixed
    assert not python_format

print("The 40-byte salt check defeats the concatenation forgery.")
