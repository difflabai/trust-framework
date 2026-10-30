"""CLI regression checks for public-key output and private credential storage."""

import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

import near_util


class CredentialOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Public RFC 8032 section 7.1 test vector, never a deployed credential.
        self.seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc4"
            "4449c5697b326919703bac031cae7f60"
        )
        public = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a"
            "0ee172f3daa62325af021a68f707511a"
        )
        self.key = "ed25519:" + near_util.b58encode(self.seed + public)
        self.public = "ed25519:" + near_util.b58encode(public)

    def run_cli(self, *args, stdin=None, success=True):
        result = subprocess.run(
            [sys.executable, str(Path(near_util.__file__).resolve()), *map(str, args)],
            input=stdin, capture_output=True, text=True, check=False,
        )
        output = result.stdout + result.stderr
        for value in (self.key, self.key.split(":", 1)[1], near_util.b58encode(self.seed)):
            self.assertNotIn(value, output)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def keyfile(self, **fields):
        path = self.root / "validator.json"
        fields.setdefault("account_id", "example.testnet")
        fields.setdefault("public_key", self.public)
        fields.setdefault("secret_key", self.key)
        path.write_text(json.dumps(fields))
        return path

    def assert_private(self, path):
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_pubkey_prints_only_public_half(self):
        result = self.run_cli("pubkey", stdin=self.key + "\n")
        self.assertEqual(result.stdout, self.public + "\n")

    def test_write_keyfile_keeps_secret_in_private_file(self):
        path = self.root / "key.json"
        result = self.run_cli("write-keyfile", "--account", "example.testnet",
                              "--out", path, stdin=self.key)
        self.assertEqual(result.stdout, self.public + "\n")
        self.assertEqual(json.loads(path.read_text())["private_key"], self.key)
        self.assert_private(path)

    def test_convert_keyfile_prints_only_public_key(self):
        path = self.root / "converted.json"
        result = self.run_cli("convert-keyfile", "--in", self.keyfile(),
                              "--account", "example.testnet", "--out", path)
        self.assertEqual(result.stdout, self.public + "\n")
        self.assertEqual(json.loads(path.read_text())["private_key"], self.key)
        self.assert_private(path)

    def test_keyfile_info_does_not_include_private_fields(self):
        result = self.run_cli("keyfile-info", self.keyfile())
        info = json.loads(result.stdout)
        self.assertEqual(info["public_key"], self.public)
        self.assertEqual(info["account_id"], "example.testnet")
        self.assertNotIn("private_key", info)
        self.assertNotIn("secret_key", info)

    def test_sandbox_env_prints_public_key_and_stores_private_key(self):
        path = self.root / ".env"
        result = self.run_cli(
            "sandbox-env", "--validator-key", self.keyfile(),
            "--account", "example.testnet", "--rpc-url", "http://127.0.0.1:3030",
            "--credentials-dir", self.root / "credentials",
            "--deployments-dir", self.root / "deployments", "--out", path,
        )
        self.assertEqual(result.stdout, self.public + "\n")
        self.assertIn("NEAR_PRIVATE_KEY=" + self.key, path.read_text())
        self.assert_private(path)

    def test_invalid_key_error_does_not_echo_input(self):
        result = self.run_cli("pubkey", stdin=self.key + "!", success=False)
        self.assertEqual(result.stdout, "")

    def test_mismatched_public_key_error_does_not_echo_secret(self):
        other = "ed25519:" + near_util.b58encode(bytes(32))
        result = self.run_cli("keyfile-info", self.keyfile(public_key=other), success=False)
        self.assertEqual(result.stdout, "")

    def test_cli_filter_redacts_secret_and_preserves_public_key(self):
        result = self.run_cli("filter-cli", stdin=self.key + "\n" + self.public + "\n")
        self.assertEqual(result.stdout, "ed25519:<redacted>\n" + self.public + "\n")

    def test_env_append_status_does_not_echo_secret(self):
        path = self.root / ".env"
        args = ("env-append", "--keyfile", self.keyfile(), "--env-file", path,
                "--prefix", "APPROVAL_AGENT", "--comment", "test principal")
        self.assertEqual(self.run_cli(*args).stdout, "appended\n")
        self.assertEqual(self.run_cli(*args).stdout, "unchanged\n")
        self.assertIn("APPROVAL_AGENT_PRIVATE_KEY=" + self.key, path.read_text())
        self.assert_private(path)


if __name__ == "__main__":
    unittest.main()
