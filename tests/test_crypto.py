"""Tests for file and text encryption/decryption (app.crypto.algorithms)."""

import os
import tempfile
import unittest

from app.crypto.algorithms import (
    ALGORITHMS,
    decrypt_file,
    decrypt_text,
    encrypt_file,
    encrypt_text,
    file_checksum,
    verify_file_integrity,
)


class TestTextEncryption(unittest.TestCase):
    """Round-trip text encryption for all supported algorithms."""

    def _roundtrip(self, algo):
        plaintext = "Hello, World! 🔐 Tiếng Việt"
        password = "SuperSecret123!"
        blob = encrypt_text(plaintext, password, algo)
        result = decrypt_text(blob, password, algo)
        self.assertEqual(result, plaintext)

    def test_aes256_roundtrip(self):
        self._roundtrip("AES-256")

    def test_3des_roundtrip(self):
        self._roundtrip("3DES")

    def test_blowfish_roundtrip(self):
        self._roundtrip("Blowfish")

    def test_wrong_password_raises(self):
        blob = encrypt_text("secret", "correct", "AES-256")
        with self.assertRaises(Exception):
            decrypt_text(blob, "wrong", "AES-256")

    def test_algorithms_list(self):
        self.assertIn("AES-256", ALGORITHMS)
        self.assertIn("3DES", ALGORITHMS)
        self.assertIn("Blowfish", ALGORITHMS)

    def test_ciphertext_differs_from_plaintext(self):
        import base64
        blob = encrypt_text("hello", "pw", "AES-256")
        self.assertNotIn(b"hello", blob)

    def test_same_plaintext_different_ciphertext(self):
        """Two encryptions of the same text should produce different blobs (random salt/IV)."""
        b1 = encrypt_text("same", "pw", "AES-256")
        b2 = encrypt_text("same", "pw", "AES-256")
        self.assertNotEqual(b1, b2)


class TestFileEncryption(unittest.TestCase):
    """Round-trip file encryption for all supported algorithms."""

    def _roundtrip(self, algo, content=b"Binary \x00\x01\x02 data"):
        with tempfile.NamedTemporaryFile(delete=False) as src:
            src.write(content)
            src_path = src.name
        enc_path = src_path + ".enc"
        dec_path = src_path + ".dec"
        try:
            encrypt_file(src_path, enc_path, "pass123", algo)
            returned_algo = decrypt_file(enc_path, dec_path, "pass123")
            self.assertEqual(returned_algo, algo)
            with open(dec_path, "rb") as f:
                self.assertEqual(f.read(), content)
        finally:
            for p in [src_path, enc_path, dec_path]:
                if os.path.exists(p):
                    os.remove(p)

    def test_aes256_file_roundtrip(self):
        self._roundtrip("AES-256")

    def test_3des_file_roundtrip(self):
        self._roundtrip("3DES")

    def test_blowfish_file_roundtrip(self):
        self._roundtrip("Blowfish")

    def test_large_file(self):
        self._roundtrip("AES-256", content=os.urandom(1024 * 256))

    def test_empty_file(self):
        self._roundtrip("AES-256", content=b"")

    def test_wrong_password_raises(self):
        with tempfile.NamedTemporaryFile(delete=False) as src:
            src.write(b"data")
            src_path = src.name
        enc_path = src_path + ".enc"
        dec_path = src_path + ".dec"
        try:
            encrypt_file(src_path, enc_path, "correct")
            with self.assertRaises(ValueError):
                decrypt_file(enc_path, dec_path, "wrong")
        finally:
            for p in [src_path, enc_path, dec_path]:
                if os.path.exists(p):
                    os.remove(p)

    def test_invalid_magic_raises(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as f:
            f.write(b"NOT_A_VALID_FILE_XXXX")
            bad_path = f.name
        dec_path = bad_path + ".dec"
        try:
            with self.assertRaises(ValueError):
                decrypt_file(bad_path, dec_path, "pw")
        finally:
            for p in [bad_path, dec_path]:
                if os.path.exists(p):
                    os.remove(p)


class TestFileIntegrity(unittest.TestCase):
    def test_checksum_stable(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            path = f.name
        try:
            h1 = file_checksum(path)
            h2 = file_checksum(path)
            self.assertEqual(h1, h2)
            self.assertEqual(len(h1), 64)  # SHA-256 hex
        finally:
            os.remove(path)

    def test_verify_integrity_pass(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"integrity check")
            path = f.name
        try:
            h = file_checksum(path)
            self.assertTrue(verify_file_integrity(path, h))
        finally:
            os.remove(path)

    def test_verify_integrity_fail(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"original data")
            path = f.name
        try:
            self.assertFalse(verify_file_integrity(path, "a" * 64))
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
