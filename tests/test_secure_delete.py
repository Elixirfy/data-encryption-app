"""Tests for secure file deletion (app.secure_delete.shredder)."""

import os
import tempfile
import unittest

from app.secure_delete.shredder import ALGORITHMS, secure_delete


class TestSecureDelete(unittest.TestCase):
    def _make_temp_file(self, content=b"sensitive data"):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_dod_deletes_file(self):
        path = self._make_temp_file()
        secure_delete(path, "DoD 5220.22-M (7-pass)")
        self.assertFalse(os.path.exists(path))

    def test_gutmann_deletes_file(self):
        path = self._make_temp_file()
        secure_delete(path, "Gutmann (35-pass)")
        self.assertFalse(os.path.exists(path))

    def test_empty_file_dod(self):
        path = self._make_temp_file(content=b"")
        secure_delete(path, "DoD 5220.22-M (7-pass)")
        self.assertFalse(os.path.exists(path))

    def test_empty_file_gutmann(self):
        path = self._make_temp_file(content=b"")
        secure_delete(path, "Gutmann (35-pass)")
        self.assertFalse(os.path.exists(path))

    def test_file_not_found_raises(self):
        with self.assertRaises(FileNotFoundError):
            secure_delete("/tmp/this_file_does_not_exist_xyz123.txt", "DoD 5220.22-M (7-pass)")

    def test_unknown_algorithm_raises(self):
        path = self._make_temp_file()
        try:
            with self.assertRaises(ValueError):
                secure_delete(path, "BogusAlgorithm")
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_algorithms_list(self):
        self.assertIn("DoD 5220.22-M (7-pass)", ALGORITHMS)
        self.assertIn("Gutmann (35-pass)", ALGORITHMS)

    def test_large_file_dod(self):
        path = self._make_temp_file(content=os.urandom(1024 * 128))
        secure_delete(path, "DoD 5220.22-M (7-pass)")
        self.assertFalse(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
