import sys
from eth_abi import encode
from falcon import HEAD_LEN, SALT_LEN, PublicKey, SecretKey, decompress
from shake import SHAKE
from ntrugen import ntru_gen
from keccak_prng import KeccakPRNG
from common import falcon_compact, q
from scripts.generate_kat_rsp import encode_public_key
from polyntt.poly import Poly

# message to be signed has a prefix `0x`
msg = bytes.fromhex(sys.argv[1][2:])

if sys.argv[2] == 'ETH':
    xof = KeccakPRNG
elif sys.argv[2] == 'NIST':
    xof = SHAKE

seed = bytes.fromhex(sys.argv[3])

n = 512
prng = SHAKE.new(seed)
prng.flip()

f, g, F, G = ntru_gen(n, randombytes=prng.read)

# Create secret key with the generated polys
sk = SecretKey(n, [f, g, F, G])
pk = PublicKey(n, sk.h)

pk_compact = falcon_compact(Poly(sk.h, q).ntt())

prng = SHAKE.new(seed + b'_sign')
prng.flip()

# Falcon signature
sig = sk.sign(msg, randombytes=prng.read, xof=xof)

salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
enc_s = sig[HEAD_LEN + SALT_LEN:]
s2 = decompress(enc_s, sk.sig_bytelen - HEAD_LEN - SALT_LEN, sk.n)
s2 = [elt % q for elt in s2]
s2_compact = falcon_compact(s2)

assert pk.verify(msg, sig, xof=xof)

encoded = encode(
    ['uint256[32]', 'bytes', 'uint256[32]'],
    [pk_compact, salt, s2_compact]
)
print(encoded.hex())