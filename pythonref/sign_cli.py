#!myenv/bin/python
import argparse
import ast
import contextlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, keccak
from Crypto.Protocol.KDF import PBKDF2
from common import falcon_compact, q
from encoding import decompress
from falcon import HEAD_LEN, SALT_LEN, Params, PublicKey, SecretKey, check_ntru_equation
from falcon_epervier import EpervierPublicKey, EpervierSecretKey
from falcon_recovery import RecoveryModePublicKey, RecoveryModeSecretKey
from polyntt.poly import Poly
from shake import SHAKE
from keccak_prng import KeccakPRNG
from keccak import KeccakHash
from eth_abi import encode

N = 512

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
SIGNATURE_FILE = "sig"

# Environment variable holding the Ethereum ECDSA key used by the `*send`
# actions. cast has no environment variable for a raw private key, so the key
# is handed to cast through an ephemeral encrypted keystore (see
# `cast_wallet`), never through a command line.
ETH_PRIVATE_KEY_ENV = "ETH_PRIVATE_KEY"

# Single source of truth for the supported versions:
# version -> (hash-to-point XOF, secret key class, public key class)
VERSIONS = {
    'falcon': (SHAKE, SecretKey, PublicKey),
    'ethfalcon': (KeccakPRNG, SecretKey, PublicKey),
    'epervier': (SHAKE, EpervierSecretKey, EpervierPublicKey),
    'falconrec': (KeccakPRNG, RecoveryModeSecretKey, RecoveryModePublicKey),
}

# Versions whose public key is a list of coefficients (h), and versions whose
# public key is an Ethereum-style address derived from h.
COEFFICIENT_PK_VERSIONS = ('falcon', 'ethfalcon')
ADDRESS_PK_VERSIONS = ('epervier', 'falconrec')

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def version_params(version):
    """Return (xof, secret key class, public key class); unknown versions raise."""
    try:
        return VERSIONS[version]
    except (KeyError, TypeError):
        raise ValueError("Unknown version {!r} (expected one of: {})".format(
            version, ", ".join(VERSIONS)))


def get_xof(version):
    return version_params(version)[0]


def generate_keys(n, version):
    _, SK, _ = version_params(version)
    sk = SK(n)
    return sk, sk.public_key()


# FILES


def _write_file(filename, content, mode, force=False):
    """
    Create `filename` with permissions `mode` and write `content`.
    Refuse to overwrite an existing file unless `force` is set; with `force`,
    the old file is unlinked first and a fresh file is created, so the new
    permissions always apply. Symbolic links are never followed.
    """
    if force:
        try:
            os.unlink(filename)
        except FileNotFoundError:
            pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(filename, flags, mode)
    except FileExistsError:
        raise FileExistsError(
            "{} already exists; refusing to overwrite it (use --force)".format(filename))
    with os.fdopen(fd, "w") as f:
        f.write(content)


def save_pk(pk, filename, version, force=False):
    content = "# public key\n"
    content += "n = {}\n".format(pk.n)
    content += "pk = {}\n".format(pk.pk)
    content += "version = {}\n".format(version)
    _write_file(filename, content, 0o644, force=force)


def save_sk(sk, filename, version, force=False):
    """
    Write the secret key in plaintext, readable by the owner only (0600).
    The matching public key is stored too, and checked by `load_sk`.
    """
    content = "# private key\n"
    content += "n = {}\n".format(sk.n)
    content += "f = {}\n".format(sk.f)
    content += "g = {}\n".format(sk.g)
    content += "F = {}\n".format(sk.F)
    content += "G = {}\n".format(sk.G)
    content += "pk = {}\n".format(sk.public_key().pk)
    content += "version = {}\n".format(version)
    _write_file(filename, content, 0o600, force=force)


def save_signature(sig, filename):
    with open(filename, "w") as f:
        f.write(sig.hex())


def _parse_key_file(filename):
    with open(filename, "r") as f:
        data = f.read()
    variables = {}
    for line in data.splitlines():
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("{}: malformed line".format(filename))
        key, value = line.split("=", 1)
        variables[key.strip()] = value.strip()
    for field in ("n", "version"):
        if field not in variables:
            raise ValueError("{}: missing field {!r}".format(filename, field))
    n = int(variables["n"])
    if n not in Params:
        raise ValueError("{}: unsupported n = {}".format(filename, n))
    version = variables["version"]
    version_params(version)
    return n, version, variables


def _parse_pk_value(value, n, version):
    pk = ast.literal_eval(value)
    if version in COEFFICIENT_PK_VERSIONS:
        if not (isinstance(pk, list) and len(pk) == n
                and all(isinstance(x, int) and 0 <= x < q for x in pk)):
            raise ValueError("Invalid public key: expected {} coefficients in [0, q)".format(n))
    else:
        if not (isinstance(pk, int) and 0 <= pk < (1 << 160)):
            raise ValueError("Invalid public key: expected a 160-bit address")
    return pk


def load_pk(filename):
    n, version, variables = _parse_key_file(filename)
    if "pk" not in variables:
        raise ValueError("{}: missing field 'pk'".format(filename))
    pk = _parse_pk_value(variables["pk"], n, version)
    _, _, PK = version_params(version)
    return [PK(n, pk), version]


def load_sk(filename):
    """
    Load and validate a secret key file:
    f * G - g * F = q, f invertible mod q, Gram-Schmidt norm and LDL tree
    within bounds, and the stored public key (if any) matches.
    """
    mode = os.stat(filename).st_mode
    if mode & 0o077:
        print("Warning: {} is accessible by other users (mode {:o}); "
              "run `chmod 600 {}`".format(filename, mode & 0o777, filename),
              file=sys.stderr)
    n, version, variables = _parse_key_file(filename)
    polys = []
    for name in ("f", "g", "F", "G"):
        if name not in variables:
            raise ValueError("{}: missing field {!r}".format(filename, name))
        poly = ast.literal_eval(variables[name])
        if not (isinstance(poly, list) and len(poly) == n
                and all(isinstance(x, int) for x in poly)):
            raise ValueError("Invalid secret key: {} must be {} integers".format(name, n))
        polys.append(poly)
    if not check_ntru_equation(*polys):
        raise ValueError("Invalid secret key: f*G - g*F != q")
    _, SK, _ = version_params(version)
    try:
        sk = SK(n, polys=polys)
    except (ValueError, ZeroDivisionError, ArithmeticError) as e:
        raise ValueError("Invalid secret key: {}".format(e))
    sk.validate()
    if "pk" in variables:
        stored_pk = _parse_pk_value(variables["pk"], n, version)
        if stored_pk != sk.public_key().pk:
            raise ValueError("Invalid secret key: stored public key does not match")
    return [sk, version]


def load_signature(filename):
    with open(filename, "r") as f:
        signature = f.read()
    return bytes.fromhex(signature.strip())


# SIGNATURE


def signature(sk, data, version, deterministic=False):
    """
    Sign `data`. The salt and the sampler randomness come from
    `sk.signing_randombytes`, keyed by the secret basis (f, g, F, G):
    - hedged (default): 32 fresh bytes from os.urandom are mixed in, so
      signing twice gives two different signatures;
    - deterministic: reproducible for a given (key, version, data), and
      still secret.
    The signature is verified before being returned.
    """
    xof = get_xof(version)
    randombytes = sk.signing_randombytes(
        data, context=b"sign_cli/" + version.encode(), deterministic=deterministic)
    return sk.sign(data, randombytes=randombytes, xof=xof)


def transaction_hash(nonce, to, data, value):
    K = KeccakHash(rate=200-(512 // 8), dsbyte=0x01)
    packed = encode(
        # seem that `to` is considered as uint256
        ["uint256", "uint160", "bytes", "uint256"],
        [nonce, to, data, value]
    )
    K.absorb(packed)
    K.pad()
    return K.squeeze(32)


def falcon_signature_parts(sig, n=N):
    """(SALT, S2) of a FALCON/ETHFALCON signature, formatted for cast."""
    salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
    enc_s = sig[HEAD_LEN + SALT_LEN:]
    s2 = decompress(enc_s, Params[n]["sig_bytelen"] - HEAD_LEN - SALT_LEN, n)
    if s2 is False:
        raise ValueError("Invalid signature encoding")
    s2 = [elt % q for elt in s2]
    return "0x" + salt.hex(), str(falcon_compact(s2))


def epervier_signature_parts(sig, n=N):
    """(SALT, S1, S2, HINT) of an EPERVIER signature, formatted for cast."""
    salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
    enc_s = sig[HEAD_LEN + SALT_LEN:-n*3]
    s = decompress(enc_s, Params[n]["sig_bytelen"]*2 - HEAD_LEN - SALT_LEN, n*2)
    if s is False:
        raise ValueError("Invalid signature encoding")
    mid = len(s)//2
    s = [elt % q for elt in s]
    s1, s2 = s[:mid], s[mid:]
    s2_inv_ntt = Poly(s2, q).inverse().ntt()
    hint = 1
    for elt in s2_inv_ntt:
        hint = (hint * elt) % q
    return "0x" + salt.hex(), str(falcon_compact(s1)), str(falcon_compact(s2)), str(hint)


def pk_compact_str(pk):
    return str(falcon_compact(Poly(pk.pk, q).ntt()))


def print_signature_transaction(sig, pk, tx_hash, version):
    if version not in COEFFICIENT_PK_VERSIONS and version != 'epervier':
        raise ValueError("No on-chain transaction format for version {!r}".format(version))
    print("TX_HASH = 0x{}".format(tx_hash.hex()))
    if version in COEFFICIENT_PK_VERSIONS:
        SALT, S2 = falcon_signature_parts(sig, pk.n)
        print("PK = {}".format(pk_compact_str(pk)))
        print("S2 = {}".format(S2))
        print("SALT = {}".format(SALT))
    elif version == 'epervier':
        SALT, S1, S2, HINT = epervier_signature_parts(sig, pk.n)
        print("ADDRESS = 0x{:040x}".format(pk.pk))
        print("S1 = {}".format(S1))
        print("S2 = {}".format(S2))
        print("HINT = {}".format(HINT))
        print("SALT = {}".format(SALT))


def verify_signature(pk, data, sig, version):
    return pk.verify(data, sig, xof=get_xof(version))


# ON-CHAIN


def _check_contract_address(contract_address):
    if not ADDRESS_RE.match(contract_address or ""):
        raise ValueError("Invalid contract address (expected 0x followed by 40 hex digits)")


def _rpc_arg(rpc):
    # A single `--rpc-url=<value>` token: the value can never be parsed as
    # another cast option, and no shell is involved.
    if not rpc:
        raise ValueError("Missing RPC URL")
    return "--rpc-url={}".format(rpc)


def _run_cast(command):
    return subprocess.run(command, capture_output=True, text=True)


def write_ephemeral_keystore(private_key_hex, directory, iterations=4096):
    """
    Encrypt an Ethereum private key into a Web3 Secret Storage (v3) keystore
    in `directory`, with a random password, and return (keystore, password
    file). Both files are created 0600. The keystore only lives for the
    duration of one cast call; the password is random (256 bits), so the KDF
    cost does not matter here.
    """
    key_hex = private_key_hex.strip()
    if key_hex.startswith(("0x", "0X")):
        key_hex = key_hex[2:]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", key_hex):
        # Never echo the value
        raise ValueError("Invalid Ethereum private key format (expected 32 bytes in hex)")
    key = bytes.fromhex(key_hex)
    password = os.urandom(32).hex()
    salt, iv = os.urandom(32), os.urandom(16)
    derived = PBKDF2(password.encode(), salt, dkLen=32, count=iterations,
                     hmac_hash_module=SHA256)
    ciphertext = AES.new(derived[:16], AES.MODE_CTR,
                         initial_value=iv, nonce=b"").encrypt(key)
    mac = keccak.new(digest_bytes=32, data=derived[16:32] + ciphertext).digest()
    keystore = {
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": iv.hex()},
            "ciphertext": ciphertext.hex(),
            "kdf": "pbkdf2",
            "kdfparams": {"c": iterations, "dklen": 32, "prf": "hmac-sha256", "salt": salt.hex()},
            "mac": mac.hex(),
        },
        "id": str(uuid.uuid4()),
        "version": 3,
    }
    keystore_path = os.path.join(directory, "keystore.json")
    password_path = os.path.join(directory, "password")
    _write_file(keystore_path, json.dumps(keystore), 0o600)
    _write_file(password_path, password, 0o600)
    return keystore_path, password_path


@contextlib.contextmanager
def cast_wallet(account=None, keystore=None, password_file=None, legacy_private_key=None):
    """
    Yield the cast wallet options for `cast send`. The raw private key never
    appears in any argument list:
    - `--account NAME` / `--keystore PATH` (optionally `--password-file`)
      are passed through to cast, which decrypts the keystore itself;
    - otherwise the key is read from $ETH_PRIVATE_KEY (or, deprecated, from
      --privatekey) and written to a temporary 0600 keystore in a 0700
      directory, deleted right after the call.
    """
    if account or keystore:
        wallet = ["--account", account] if account else ["--keystore", keystore]
        if password_file:
            wallet += ["--password-file", password_file]
        yield wallet
        return
    private_key = os.environ.get(ETH_PRIVATE_KEY_ENV) or legacy_private_key
    if not private_key:
        raise ValueError(
            "No Ethereum wallet: set ${} or pass --account/--keystore".format(ETH_PRIVATE_KEY_ENV))
    with tempfile.TemporaryDirectory(prefix="ethfalcon-cast-") as directory:
        keystore_path, password_path = write_ephemeral_keystore(private_key, directory)
        yield ["--keystore", keystore_path, "--password-file", password_path]


def recover_on_chain(data, sig, contract_address, rpc, version):
    """Call `recover` on an EPERVIER contract and return the recovered address (int)."""
    if version != 'epervier':
        raise ValueError("On-chain recovery is only available for 'epervier'")
    _check_contract_address(contract_address)
    MSG = "0x" + data.hex()
    SALT, S1, S2, HINT = epervier_signature_parts(sig)
    command = [
        "cast", "call", contract_address,
        "recover(bytes,bytes,uint256[],uint256[],uint256)", MSG, SALT, S1, S2, HINT,
        _rpc_arg(rpc)
    ]
    result = _run_cast(command)
    if result.returncode != 0:
        raise RuntimeError("cast call failed: {}".format(result.stderr.strip()))
    return int(result.stdout.strip(), 16)


def verify_signature_on_chain(pk, data, sig, contract_address, rpc, version):
    """
    Verify on-chain with `cast call`. Return True/False.
    For EPERVIER, print the recovered address and whether it matches the
    expected one.
    """
    if version == 'epervier':
        recovered = recover_on_chain(data, sig, contract_address, rpc, version)
        print("Recovered address: 0x{:040x}".format(recovered))
        print("Expected address:  0x{:040x}".format(pk.pk))
        if recovered == pk.pk:
            print("MATCH: the signature is valid on-chain.")
            return True
        print("MISMATCH: the signature does not recover the expected address.")
        return False
    elif version in COEFFICIENT_PK_VERSIONS:
        _check_contract_address(contract_address)
        MSG = "0x" + data.hex()
        SALT, S2 = falcon_signature_parts(sig, pk.n)
        command = [
            "cast", "call", contract_address,
            "verify(bytes,bytes,uint256[],uint256[])", MSG, SALT, S2, pk_compact_str(pk),
            _rpc_arg(rpc)
        ]
        result = _run_cast(command)
        if result.stderr:
            print(result.stderr)
        print(result.stdout)
        if result.returncode != 0:
            raise RuntimeError("cast call failed")
        return int(result.stdout.strip(), 16) == 1
    else:
        raise ValueError("On-chain verification is not available for {!r}".format(version))


def recover_on_chain_with_transaction(data, sig, contract_address, rpc, wallet, version):
    """Send a `recover` transaction; `wallet` comes from `cast_wallet`."""
    if version != 'epervier':
        raise ValueError("On-chain recovery is only available for 'epervier'")
    _check_contract_address(contract_address)
    MSG = "0x" + data.hex()
    SALT, S1, S2, HINT = epervier_signature_parts(sig)
    command = [
        "cast", "send", *wallet, contract_address,
        "recover(bytes,bytes,uint256[],uint256[],uint256)", MSG, SALT, S1, S2, HINT,
        _rpc_arg(rpc)
    ]
    result = _run_cast(command)
    print(result.stderr)
    print(result.stdout)
    return result


def verify_signature_on_chain_with_transaction(pk, data, sig, contract_address, rpc, wallet, version):
    """Send a `verify` transaction; `wallet` comes from `cast_wallet`."""
    if version not in COEFFICIENT_PK_VERSIONS:
        raise ValueError("On-chain verification is only available for 'falcon' and 'ethfalcon'")
    _check_contract_address(contract_address)
    MSG = "0x" + data.hex()
    SALT, S2 = falcon_signature_parts(sig, pk.n)
    command = [
        "cast", "send", *wallet, contract_address,
        "verify(bytes,bytes,uint256[],uint256[])", MSG, SALT, S2, pk_compact_str(pk),
        _rpc_arg(rpc)
    ]
    result = _run_cast(command)
    print(result.stderr)
    print(result.stdout)
    return result


# CLI


def _wallet_from_args(args):
    if args.privatekey:
        print("Warning: --privatekey is deprecated: the key is visible in the process "
              "list and in your shell history. Set ${} or use --account/--keystore."
              .format(ETH_PRIVATE_KEY_ENV), file=sys.stderr)
    return cast_wallet(account=args.account, keystore=args.keystore,
                       password_file=args.password_file,
                       legacy_private_key=args.privatekey)


def _has_wallet(args):
    return bool(args.account or args.keystore or args.privatekey
                or os.environ.get(ETH_PRIVATE_KEY_ENV))


def error(message):
    print("Error: {}".format(message), file=sys.stderr)
    return 1


def cli(argv=None):
    parser = argparse.ArgumentParser(description="CLI for Falcon Signature")
    parser.add_argument("action", choices=[
                        "genkeys", "sign", "sign_tx", "verify", "verifyonchain", "verifyonchainsend", "recoveronchain", "recoveronchainsend"], help="Action to perform")
    parser.add_argument("--version", type=str,
                        help="Version to use for genkeys: " + ", ".join(VERSIONS))
    parser.add_argument("--nonce", type=str,
                        help="nonce in hexadecimal to sign the transaction")
    parser.add_argument("--to", type=str,
                        help="Destination in hexadecimal address for the transaction")
    parser.add_argument("--data", type=str,
                        help="Data to be signed in hexadecimal")
    parser.add_argument("--value", type=str,
                        help="Value in hexadecimal for the transaction")
    parser.add_argument("--privkey", type=str,
                        help="Private key file for signing")
    parser.add_argument("--pubkey", type=str,
                        help="Public key file for verification")
    parser.add_argument("--contractaddress", type=str,
                        help="Contract address for on-chain verification")
    parser.add_argument("--rpc", type=str,
                        help="RPC for on-chain verification")
    parser.add_argument("--account", type=str,
                        help="cast keystore account (~/.foundry/keystores) for sending a transaction")
    parser.add_argument("--keystore", type=str,
                        help="cast keystore file for sending a transaction")
    parser.add_argument("--password-file", dest="password_file", type=str,
                        help="Password file for --account/--keystore")
    parser.add_argument("--privatekey", type=str,
                        help="DEPRECATED (visible in the process list): Ethereum ECDSA private key; "
                             "set ${} instead".format(ETH_PRIVATE_KEY_ENV))
    parser.add_argument("--signature", type=str, help="Signature to verify")
    parser.add_argument("--deterministic", action="store_true",
                        help="Deterministic signature (no fresh randomness; still keyed by the secret key)")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing key files with genkeys")

    args = parser.parse_args(argv)

    try:
        return _run(args)
    except (ValueError, FileExistsError, RuntimeError) as e:
        return error(e)


def _run(args):
    if args.action == "genkeys":
        if not args.version:
            return error("Provide --version")
        version_params(args.version)
        if not args.force:
            for filename in (PRIVATE_KEY_FILE, PUBLIC_KEY_FILE):
                if os.path.lexists(filename):
                    return error("{} already exists; refusing to overwrite it (use --force)"
                                 .format(filename))
        priv, pub = generate_keys(N, args.version)
        save_sk(priv, PRIVATE_KEY_FILE, args.version, force=args.force)
        save_pk(pub, PUBLIC_KEY_FILE, args.version, force=args.force)
        print("Keys generated and saved ({} is readable by you only).".format(PRIVATE_KEY_FILE))

    elif args.action == "sign":
        if not args.data or not args.privkey:
            return error("Provide --data, and --privkey")
        [sk, version] = load_sk(args.privkey)
        sig = signature(sk, bytes.fromhex(args.data), version,
                        deterministic=args.deterministic)
        save_signature(sig, SIGNATURE_FILE)
        print("Signature saved in {}.".format(SIGNATURE_FILE))

    elif args.action == "sign_tx":
        if not args.data or not args.privkey or not args.nonce or not args.to or not args.value:
            return error("Provide --data, --privkey, --nonce, --to and --value")
        [sk, version] = load_sk(args.privkey)
        if args.version and args.version != version:
            return error("--version {} does not match the key file version {}"
                         .format(args.version, version))
        tx_hash = transaction_hash(
            int(args.nonce, 16),
            int(args.to, 16),
            bytes.fromhex(args.data),
            int(args.value, 16)
        )
        pk = sk.public_key()
        sig = signature(sk, tx_hash, version, deterministic=args.deterministic)
        if not verify_signature(pk, tx_hash, sig, version):
            raise RuntimeError("signature verification failed")
        print_signature_transaction(sig, pk, tx_hash, version)

    elif args.action == "verify":
        if not args.data or not args.pubkey or not args.signature:
            return error("Provide --data, --pubkey, and --signature")
        [pk, version] = load_pk(args.pubkey)
        sig = load_signature(args.signature)
        if verify_signature(pk, bytes.fromhex(args.data), sig, version):
            print("Signature is valid.")
        else:
            print("Invalid signature.")
            return 1

    elif args.action == "verifyonchain":
        if not args.data or not args.pubkey or not args.signature or not args.rpc or not args.contractaddress:
            return error("Provide --data, --pubkey, --signature, --contractaddress and --rpc")
        [pk, version] = load_pk(args.pubkey)
        sig = load_signature(args.signature)
        if not verify_signature_on_chain(
                pk, bytes.fromhex(args.data), sig, args.contractaddress, args.rpc, version):
            return 1

    elif args.action == "verifyonchainsend":
        if not args.data or not args.pubkey or not args.signature or not args.rpc or not args.contractaddress or not _has_wallet(args):
            return error("Provide --data, --pubkey, --signature, --contractaddress, --rpc, "
                         "and a wallet (${}, --account or --keystore)".format(ETH_PRIVATE_KEY_ENV))
        [pk, version] = load_pk(args.pubkey)
        sig = load_signature(args.signature)
        with _wallet_from_args(args) as wallet:
            result = verify_signature_on_chain_with_transaction(
                pk, bytes.fromhex(args.data), sig, args.contractaddress, args.rpc, wallet, version)
        return 0 if result.returncode == 0 else 1

    elif args.action == "recoveronchain":
        if not args.data or not args.pubkey or not args.signature or not args.rpc or not args.contractaddress:
            return error("Provide --data, --pubkey, --signature, --contractaddress and --rpc")
        [pk, version] = load_pk(args.pubkey)
        sig = load_signature(args.signature)
        pk_rec = recover_on_chain(
            bytes.fromhex(args.data), sig, args.contractaddress, args.rpc, version)
        print("Address recovered: 0x{:040x}".format(pk_rec))

    elif args.action == "recoveronchainsend":
        if not args.data or not args.pubkey or not args.signature or not args.rpc or not args.contractaddress or not _has_wallet(args):
            return error("Provide --data, --pubkey, --signature, --contractaddress, --rpc, "
                         "and a wallet (${}, --account or --keystore)".format(ETH_PRIVATE_KEY_ENV))
        [pk, version] = load_pk(args.pubkey)
        sig = load_signature(args.signature)
        with _wallet_from_args(args) as wallet:
            result = recover_on_chain_with_transaction(
                bytes.fromhex(args.data), sig, args.contractaddress, args.rpc, wallet, version)
        return 0 if result.returncode == 0 else 1

    return 0


if __name__ == "__main__":
    sys.exit(cli())
