#!myenv/bin/python
import argparse
import ast
from common import deterministic_salt, q
from encoding import decompress
from falcon import HEAD_LEN, SALT_LEN, PublicKey, SecretKey
from falcon_epervier import EpervierPublicKey, EpervierSecretKey
from falcon_recovery import RecoveryModePublicKey, RecoveryModeSecretKey
from polyntt.poly import Poly

import random


def generate_keys(n, version, seed=None):
    # private key
    if version == 'falcon':
        SK = SecretKey
    elif version == 'falconrec':
        SK = RecoveryModeSecretKey
    elif version == 'epervier':
        SK = EpervierSecretKey
    else:
        print("This version does not exist.")
        return

    # public key
    print("This might take few seconds")
    print(".\n.\n.\n")
    print("```")
    print("// Solidity public key:")

    # deterministic random
    if seed == None:
        seed = 0
    rng = random.Random(seed)
    def deterministic_urandom(n): return bytes(
        rng.randint(0, 255) for _ in range(n))
    sk = SK(n, randombytes=deterministic_urandom)

    if version == 'falcon':
        pk = PublicKey(n, sk.h)
        print("// forgefmt: disable-next-line")
        print("uint[512] memory tmp_pk = [uint({}), {}];\n".format(
            pk.pk[0], ','.join(map(str, pk.pk[1:]))))
    elif version == 'falconrec':
        pk = RecoveryModePublicKey(n, sk.pk)
        print("address pk = address({});".format(pk.pk))
    elif version == 'epervier':
        pk = EpervierPublicKey(n, sk.pk)
        print("address pk = address({});".format(pk.pk))
    print("```")

    return sk, pk


def save_pk(pk, filename, version):
    with open(filename, "w") as f:
        f.write("# public key\n")
        f.write("n = {}\n".format(pk.n))
        f.write("pk = {}\n".format(pk.pk))
        f.write("version = {}\n".format(version))


def save_sk(sk, filename, version):
    with open(filename, "w") as f:
        f.write("# private key\n")
        f.write("n = {}\n".format(sk.n))
        f.write("f = {}\n".format(sk.f))
        f.write("g = {}\n".format(sk.g))
        f.write("F = {}\n".format(sk.F))
        f.write("G = {}\n".format(sk.G))
        f.write("version = {}\n".format(version))


def save_signature(sig, filename):
    with open(filename, "w") as f:
        f.write(sig.hex())


def load_pk(filename):
    with open(filename, "r") as f:
        data = f.read()
    variables = dict(line.split("=")
                     # first line is a comment
                     for line in data.splitlines()[1:])
    n = int(variables["n "])
    pk = ast.literal_eval(variables["pk "])
    version = variables["version "].lstrip()
    if version == 'falcon':
        return PublicKey(n, pk)
    elif version == 'falconrec':
        return RecoveryModePublicKey(n, pk)
    elif version == 'epervier':
        return EpervierPublicKey(n, pk)
    else:
        print("This version is not supported.")
        return


def load_sk(filename):
    with open(filename, "r") as f:
        data = f.read()
    variables = dict(line.split("=")
                     # first line is a comment
                     for line in data.splitlines()[1:])
    n = int(variables["n "])
    f = ast.literal_eval(variables["f "])
    g = ast.literal_eval(variables["g "])
    F = ast.literal_eval(variables["F "])
    G = ast.literal_eval(variables["G "])
    version = variables["version "].lstrip()
    if version == 'falcon':
        return SecretKey(n, polys=[f, g, F, G])
    elif version == 'falconrec':
        return RecoveryModeSecretKey(n, polys=[f, g, F, G])
    elif version == 'epervier':
        return EpervierSecretKey(n, polys=[f, g, F, G])
    else:
        print("This version is not supported.")
        return


def load_signature(filename):
    with open(filename, "r") as f:
        signature = f.read()
    return bytes.fromhex(signature)


def signature(sk, message, version, seed=None):
    if seed == None:
        seed = 0
    salt = deterministic_salt(seed)
    sig = sk.sign(
        message.encode(),
        randombytes=lambda x: deterministic_salt(x, seed)
    )
    if version == 'falcon':
        salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
        enc_s = sig[HEAD_LEN + SALT_LEN:]
        s2 = decompress(enc_s, sk.sig_bytelen - HEAD_LEN - SALT_LEN, sk.n)
        s2 = [elt % q for elt in s2]
        print("```")
        print("// Solidity raw signature:")
        print("// s2")
        print("// forgefmt: disable-next-line")
        print("uint[512] memory s2 = [uint({}), {}];\n".format(
            s2[0], ', '.join(map(str, s2[1:]))))
        print("sig.salt = \"{}\"; \n".format(
            "".join(f"\\x{b:02x}" for b in salt)))
        print("```")
    elif version == 'falconrec':
        salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
        enc_s = sig[HEAD_LEN + SALT_LEN:-sk.n*3]
        s = decompress(enc_s, sk.sig_bytelen*2 - HEAD_LEN - SALT_LEN, sk.n*2)
        mid = len(s)//2
        s = [elt % q for elt in s]
        s1, s2 = s[:mid], s[mid:]
        s2_inv_ntt = Poly(s2, q).inverse().ntt()
        print("```")
        print("// Solidity raw signature:")
        print("// s1")
        print("// forgefmt: disable-next-line")
        print("uint[512] memory s1 = [uint({}), {}];\n".format(
            s1[0], ', '.join(map(str, s1[1:]))))
        print("// s2")
        print("// forgefmt: disable-next-line")
        print("uint[512] memory s2 = [uint({}), {}];\n".format(
            s2[0], ', '.join(map(str, s2[1:]))))
        print("")
        print("// s2_inv_ntt")
        print("// forgefmt: disable-next-line")
        print("uint[512] memory s2_inv_ntt = [uint({}), {}];\n".format(
            s2_inv_ntt[0], ', '.join(map(str, s2_inv_ntt[1:]))))
        print("")
        print("sig.salt = \"{}\"; \n".format(
            "".join(f"\\x{b:02x}" for b in salt)))
        print("")
        print("```")
    elif version == 'epervier':
        salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
        enc_s = sig[HEAD_LEN + SALT_LEN:-sk.n*3]
        s = decompress(enc_s, sk.sig_bytelen*2 - HEAD_LEN - SALT_LEN, sk.n*2)
        mid = len(s)//2
        s = [elt % q for elt in s]
        s1, s2 = s[:mid], s[mid:]
        s2_inv_ntt = Poly(s2, q).inverse().ntt()
        s2_inv_ntt_prod = 1
        for elt in s2_inv_ntt:
            s2_inv_ntt_prod = (s2_inv_ntt_prod * elt) % q
        print("```")
        print("// Solidity raw signature:")
        print("// s1")
        print("// forgefmt: disable-next-line")
        print("uint[512] memory s1 = [uint({}), {}];\n".format(
            s1[0], ', '.join(map(str, s1[1:]))))
        print("// s2")
        print("// forgefmt: disable-next-line")
        print("uint[512] memory s2 = [uint({}), {}];\n".format(
            s2[0], ', '.join(map(str, s2[1:]))))
        print("")
        print("// s2_inv_ntt_prod")
        print("uint256 memory s2_inv_ntt_prod = {};".format(s2_inv_ntt_prod))
        print("")
        print("sig.salt = \"{}\"; \n".format(
            "".join(f"\\x{b:02x}" for b in salt)))
        print("")
        print("```")
    else:
        print("This version is not implemented.")
        return
    return sig


def verify_signature(pk, message, sig):
    print(pk.pk[0:5])
    return pk.verify(message.encode(), sig)


def cli():
    parser = argparse.ArgumentParser(description="CLI for Falcon Signature")
    parser.add_argument("action", choices=[
                        "genkeys", "sign", "verify"], help="Action to perform")
    parser.add_argument("--version", type=str,
                        help="Version to use (falcon or falconrec)")
    parser.add_argument("--seed", type=int,
                        help="Choose a seed")
    parser.add_argument("--message", type=str,
                        help="Message to sign or verify")
    parser.add_argument("--privkey", type=str,
                        help="Private key file for signing")
    parser.add_argument("--pubkey", type=str,
                        help="Public key file for verification")
    parser.add_argument("--signature", type=str, help="Signature to verify")

    args = parser.parse_args()

    if args.action == "genkeys":
        if not args.version:
            print("Error: Provide --version")
            return
        # TODO make it parameterizable?
        n = 512
        priv, pub = generate_keys(n, args.version, args.seed)
        save_pk(pub, "public_key.pem", args.version)
        save_sk(priv, "private_key.pem", args.version)
        print("Keys generated and saved.")

    elif args.action == "sign":
        if not args.message or not args.privkey or not args.version:
            print("Error: Provide --message, --privkey and --version")
            return
        sk = load_sk(args.privkey)
        sig = signature(sk, args.message, args.version, args.seed)
        save_signature(sig, 'sig')

    elif args.action == "verify":
        if not args.message or not args.pubkey or not args.signature:
            print("Error: Provide --message, --pubkey and --signature")
            return
        pk = load_pk(args.pubkey)
        sig = load_signature(args.signature)
        if verify_signature(pk, args.message, sig):
            print("Signature is valid.")
        else:
            print("Invalid signature.")


if __name__ == "__main__":
    cli()
