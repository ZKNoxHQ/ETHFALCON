"""
Tests for sign_cli.py (audit C-1, H-2, M-4, L-9, L-10).
No network access: every cast invocation is mocked, except one offline
`cast mktx` check of the ephemeral keystore.
"""
import contextlib
import io
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import sign_cli
from falcon import SecretKey
from falcon_epervier import EpervierSecretKey
from falcon_recovery import RecoveryModeSecretKey
from scripts.sign_KAT import sign_KAT

n = 512
KAT = sign_KAT[n][0]
POLYS = [KAT["f"], KAT["g"], KAT["F"], KAT["G"]]

# Well-known public test key (anvil account #0): not a secret.
TEST_ETH_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
CONTRACT = "0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"
EVIL_RPC = "http://127.0.0.1:1; touch pwned; #"

KEYS = {}


def key(version):
    if version not in KEYS:
        SK = {"falcon": SecretKey, "ethfalcon": SecretKey,
              "epervier": EpervierSecretKey, "falconrec": RecoveryModeSecretKey}[version]
        KEYS[version] = SK(n, POLYS)
    return KEYS[version]


def read(path):
    with open(path) as f:
        return f.read()


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = sign_cli.cli(argv)
    return code, out.getvalue(), err.getvalue()


class CliTestCase(unittest.TestCase):

    def setUp(self):
        self.old_cwd = os.getcwd()
        self.dir = tempfile.mkdtemp()
        os.chdir(self.dir)
        env = {k: v for k, v in os.environ.items() if k != sign_cli.ETH_PRIVATE_KEY_ENV}
        self.env = mock.patch.dict(os.environ, env, clear=True)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        os.chdir(self.old_cwd)
        shutil.rmtree(self.dir)

    def write_keys(self, version):
        sk = key(version)
        sign_cli.save_sk(sk, sign_cli.PRIVATE_KEY_FILE, version)
        sign_cli.save_pk(sk.public_key(), sign_cli.PUBLIC_KEY_FILE, version)
        return sk


class TestKeyFiles(CliTestCase):

    def test_secret_key_mode_0600_even_with_permissive_umask(self):
        old = os.umask(0)
        try:
            sign_cli.save_sk(key("falcon"), "sk.pem", "falcon")
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(os.stat("sk.pem").st_mode), 0o600)

    def test_no_overwrite_without_force(self):
        sign_cli.save_sk(key("falcon"), "sk.pem", "falcon")
        before = read("sk.pem")
        with self.assertRaises(FileExistsError):
            sign_cli.save_sk(key("epervier"), "sk.pem", "epervier")
        self.assertEqual(read("sk.pem"), before)
        sign_cli.save_sk(key("epervier"), "sk.pem", "epervier", force=True)
        self.assertIn("version = epervier", read("sk.pem"))
        self.assertEqual(stat.S_IMODE(os.stat("sk.pem").st_mode), 0o600)

    def test_symlink_not_followed(self):
        with open("target", "w") as f:
            f.write("keep")
        os.symlink("target", "sk.pem")
        with self.assertRaises(FileExistsError):
            sign_cli.save_sk(key("falcon"), "sk.pem", "falcon")
        self.assertEqual(read("target"), "keep")

    def test_genkeys_refuses_overwrite(self):
        with mock.patch.object(sign_cli, "generate_keys",
                               side_effect=lambda n, v: (key(v), key(v).public_key())):
            code, _, _ = run_cli(["genkeys", "--version", "falcon"])
            self.assertEqual(code, 0)
            self.assertEqual(stat.S_IMODE(os.stat("private_key.pem").st_mode), 0o600)
            before = read("private_key.pem")
            code, _, err = run_cli(["genkeys", "--version", "epervier"])
            self.assertEqual(code, 1)
            self.assertIn("refusing to overwrite", err)
            self.assertEqual(read("private_key.pem"), before)
            code, _, _ = run_cli(["genkeys", "--version", "epervier", "--force"])
            self.assertEqual(code, 0)
            self.assertIn("version = epervier", read("private_key.pem"))

    def test_load_sk_validates(self):
        self.write_keys("falcon")
        sk, version = sign_cli.load_sk("private_key.pem")
        self.assertEqual((sk.h, version), (key("falcon").h, "falcon"))
        content = read("private_key.pem")
        # Corrupted F: f*G - g*F != q
        F = POLYS[2][:]
        F[0] += 1
        with open("bad_F.pem", "w") as f:
            f.write(content.replace("F = {}".format(POLYS[2]), "F = {}".format(F)))
        with self.assertRaises(ValueError):
            sign_cli.load_sk("bad_F.pem")
        # Stored public key does not match
        with open("bad_pk.pem", "w") as f:
            f.write(content.replace("pk = [", "pk = [1, "))
        with self.assertRaises(ValueError):
            sign_cli.load_sk("bad_pk.pem")
        # Old format, without the pk line, is still accepted
        with open("old.pem", "w") as f:
            f.write("".join(line + "\n" for line in content.splitlines()
                            if not line.startswith("pk =")))
        os.chmod("old.pem", 0o600)
        self.assertEqual(sign_cli.load_sk("old.pem")[0].h, key("falcon").h)

    def test_load_sk_warns_on_readable_file(self):
        self.write_keys("falcon")
        os.chmod("private_key.pem", 0o644)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            sign_cli.load_sk("private_key.pem")
        self.assertIn("chmod 600", err.getvalue())


class TestVersions(CliTestCase):

    def test_unknown_version(self):
        for bad in ("foo", "Falcon", None, ""):
            with self.assertRaises(ValueError):
                sign_cli.version_params(bad)
        code, _, err = run_cli(["genkeys", "--version", "falcn"])
        self.assertEqual(code, 1)
        self.assertIn("Unknown version", err)
        with open("pk.pem", "w") as f:
            f.write("# public key\nn = 512\npk = 1\nversion = typo\n")
        with self.assertRaises(ValueError):
            sign_cli.load_pk("pk.pem")

    def test_sign_and_verify_every_version(self):
        for version in sign_cli.VERSIONS:
            sk = key(version)
            pk = sk.public_key()
            sig = sign_cli.signature(sk, b"\x01\x23", version)
            self.assertTrue(sign_cli.verify_signature(pk, b"\x01\x23", sig, version), version)
            self.assertFalse(sign_cli.verify_signature(pk, b"\x01\x24", sig, version), version)

    def test_version_selects_hash(self):
        sk = key("falcon")
        sig = sign_cli.signature(sk, b"abc", "ethfalcon")
        self.assertTrue(sign_cli.verify_signature(sk.public_key(), b"abc", sig, "ethfalcon"))
        self.assertFalse(sign_cli.verify_signature(sk.public_key(), b"abc", sig, "falcon"))

    def test_cli_hedged_and_deterministic(self):
        self.write_keys("ethfalcon")
        sigs = {}
        for name, extra in [("h1", []), ("h2", []), ("d1", ["--deterministic"]), ("d2", ["--deterministic"])]:
            code, _, _ = run_cli(["sign", "--privkey", "private_key.pem", "--data", "0123"] + extra)
            self.assertEqual(code, 0)
            os.rename("sig", name)
            sigs[name] = read(name)
            code, out, _ = run_cli(["verify", "--pubkey", "public_key.pem", "--data", "0123",
                                    "--signature", name])
            self.assertEqual((code, out.strip()), (0, "Signature is valid."))
        self.assertNotEqual(sigs["h1"], sigs["h2"])
        self.assertEqual(sigs["d1"], sigs["d2"])

    def test_sign_tx_uses_key_version(self):
        for version, field in [("falcon", "PK = "), ("epervier", "HINT = ")]:
            os.chdir(tempfile.mkdtemp(dir=self.dir))
            self.write_keys(version)
            code, out, err = run_cli(["sign_tx", "--privkey", "private_key.pem", "--data", "00",
                                      "--nonce", "01", "--to", "01", "--value", "00"])
            self.assertEqual(code, 0, err)
            self.assertIn("TX_HASH = 0x", out)
            self.assertIn(field, out)
            code, _, err = run_cli(["sign_tx", "--privkey", "private_key.pem", "--data", "00",
                                    "--nonce", "01", "--to", "01", "--value", "00",
                                    "--version", "falconrec"])
            self.assertEqual(code, 1)
            self.assertIn("does not match", err)


class TestCastInvocation(CliTestCase):

    def setUp(self):
        super().setUp()
        self.calls = []

    def fake_run(self, stdout="0x" + "00" * 31 + "01", returncode=0):
        def run(command, **kwargs):
            # Snapshot the wallet files while cast would be running.
            snapshot = {}
            for flag in ("--keystore", "--password-file"):
                if flag in command:
                    path = command[command.index(flag) + 1]
                    snapshot[flag] = (path, os.path.exists(path),
                                      stat.S_IMODE(os.stat(path).st_mode),
                                      read(path))
            self.calls.append((command, kwargs, snapshot))
            return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")
        return mock.patch.object(sign_cli.subprocess, "run", side_effect=run)

    def assert_safe(self, command, kwargs):
        self.assertIsInstance(command, list)
        self.assertNotEqual(kwargs.get("shell"), True)
        self.assertNotIn("--private-key", command)
        raw = TEST_ETH_KEY[2:]
        for arg in command:
            self.assertNotIn(raw, arg.lower())

    def sign_files(self, version):
        sk = self.write_keys(version)
        sign_cli.save_signature(sign_cli.signature(sk, b"\x89\xab", version), "sig")

    def test_verifyonchainsend_env_key_and_shell_metacharacters(self):
        self.sign_files("falcon")
        os.environ[sign_cli.ETH_PRIVATE_KEY_ENV] = TEST_ETH_KEY
        with self.fake_run():
            code, _, _ = run_cli(["verifyonchainsend", "--pubkey", "public_key.pem", "--data", "89ab",
                                  "--signature", "sig", "--contractaddress", CONTRACT,
                                  "--rpc", EVIL_RPC])
        self.assertEqual(code, 0)
        self.assertEqual(len(self.calls), 1)
        command, kwargs, snapshot = self.calls[0]
        self.assert_safe(command, kwargs)
        self.assertEqual(command[:2], ["cast", "send"])
        self.assertIn("--rpc-url=" + EVIL_RPC, command)  # one verbatim argument
        self.assertFalse(os.path.exists("pwned"))
        # The key reached cast through an ephemeral 0600 keystore, encrypted
        ks_path, existed, mode, content = snapshot["--keystore"]
        self.assertTrue(existed)
        self.assertEqual(mode, 0o600)
        self.assertNotIn(TEST_ETH_KEY[2:], content.lower())
        self.assertEqual(snapshot["--password-file"][2], 0o600)
        self.assertFalse(os.path.exists(ks_path))  # removed after the call

    def test_legacy_privatekey_flag_warns_and_stays_out_of_cast_argv(self):
        self.sign_files("ethfalcon")
        with self.fake_run():
            code, _, err = run_cli(["verifyonchainsend", "--pubkey", "public_key.pem", "--data", "89ab",
                                    "--signature", "sig", "--contractaddress", CONTRACT,
                                    "--rpc", "http://localhost:8545", "--privatekey", TEST_ETH_KEY])
        self.assertEqual(code, 0)
        self.assertIn("deprecated", err)
        self.assert_safe(*self.calls[0][:2])

    def test_account_passthrough(self):
        self.sign_files("falcon")
        with self.fake_run():
            code, _, _ = run_cli(["verifyonchainsend", "--pubkey", "public_key.pem", "--data", "89ab",
                                  "--signature", "sig", "--contractaddress", CONTRACT,
                                  "--rpc", "http://localhost:8545", "--account", "alice"])
        self.assertEqual(code, 0)
        command, kwargs, _ = self.calls[0]
        self.assert_safe(command, kwargs)
        self.assertEqual(command[2:4], ["--account", "alice"])
        self.assertNotIn("--keystore", command)

    def test_no_wallet_is_an_error(self):
        self.sign_files("falcon")
        with self.fake_run():
            code, _, err = run_cli(["verifyonchainsend", "--pubkey", "public_key.pem", "--data", "89ab",
                                    "--signature", "sig", "--contractaddress", CONTRACT,
                                    "--rpc", "http://localhost:8545"])
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, [])

    def test_bad_contract_address_rejected(self):
        self.sign_files("falcon")
        with self.fake_run():
            code, _, _ = run_cli(["verifyonchain", "--pubkey", "public_key.pem", "--data", "89ab",
                                  "--signature", "sig", "--contractaddress", "0x1; touch pwned",
                                  "--rpc", "http://localhost:8545"])
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, [])

    def test_recoveronchainsend_passes_s1(self):
        self.sign_files("epervier")
        os.environ[sign_cli.ETH_PRIVATE_KEY_ENV] = TEST_ETH_KEY
        with self.fake_run():
            code, _, _ = run_cli(["recoveronchainsend", "--pubkey", "public_key.pem", "--data", "89ab",
                                  "--signature", "sig", "--contractaddress", CONTRACT,
                                  "--rpc", EVIL_RPC])
        self.assertEqual(code, 0)
        command, kwargs, _ = self.calls[0]
        self.assert_safe(command, kwargs)
        fn = "recover(bytes,bytes,uint256[],uint256[],uint256)"
        args = command[command.index(fn) + 1:-1]
        self.assertEqual(len(args), 5)  # MSG, SALT, S1, S2, HINT
        sig = sign_cli.load_signature("sig")
        self.assertEqual(args, ["0x89ab", *sign_cli.epervier_signature_parts(sig)])

    def test_verifyonchain_epervier_reports_match_and_mismatch(self):
        self.sign_files("epervier")
        address = key("epervier").pk
        argv = ["verifyonchain", "--pubkey", "public_key.pem", "--data", "89ab",
                "--signature", "sig", "--contractaddress", CONTRACT, "--rpc", EVIL_RPC]
        with self.fake_run(stdout="0x{:064x}\n".format(address)):
            code, out, _ = run_cli(argv)
        self.assertEqual(code, 0)
        self.assertIn("Recovered address: 0x{:040x}".format(address), out)
        self.assertIn("MATCH", out)
        self.assertNotIn("MISMATCH", out)
        with self.fake_run(stdout="0x{:064x}\n".format(address ^ 1)):
            code, out, _ = run_cli(argv)
        self.assertEqual(code, 1)
        self.assertIn("MISMATCH", out)
        for command, kwargs, _ in self.calls:
            self.assert_safe(command, kwargs)
            self.assertEqual(command[:2], ["cast", "call"])

    @unittest.skipUnless(shutil.which("cast"), "cast not installed")
    def test_ephemeral_keystore_accepted_by_cast(self):
        """Offline: `cast mktx` signs the same transaction from the keystore and the raw key."""
        tx = ["--nonce", "0", "--gas-limit", "21000", "--gas-price", "1", "--chain", "1",
              "--legacy", "0x0000000000000000000000000000000000000001"]
        with sign_cli.cast_wallet(legacy_private_key=TEST_ETH_KEY) as wallet:
            from_keystore = subprocess.run(["cast", "mktx", *wallet, *tx],
                                           capture_output=True, text=True, timeout=60)
        from_raw = subprocess.run(["cast", "mktx", "--private-key", TEST_ETH_KEY, *tx],
                                  capture_output=True, text=True, timeout=60)
        self.assertEqual(from_keystore.returncode, 0, from_keystore.stderr)
        self.assertEqual(from_keystore.stdout, from_raw.stdout)


if __name__ == "__main__":
    unittest.main()
