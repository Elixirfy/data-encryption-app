"""Tests for the password manager vault (app.password_manager.vault)."""

import os
import tempfile
import unittest

from app.password_manager.vault import (
    PasswordVault,
    TwoFactorRequiredError,
    VaultError,
    WrongPasswordError,
    generate_password,
)


class TestGeneratePassword(unittest.TestCase):
    def test_default_length(self):
        pw = generate_password()
        self.assertEqual(len(pw), 16)

    def test_custom_length(self):
        pw = generate_password(length=24)
        self.assertEqual(len(pw), 24)

    def test_minimum_length(self):
        pw = generate_password(length=4)
        self.assertEqual(len(pw), 4)

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            generate_password(length=3)

    def test_no_charset_raises(self):
        with self.assertRaises(ValueError):
            generate_password(use_upper=False, use_lower=False, use_digits=False, use_symbols=False)

    def test_only_digits(self):
        pw = generate_password(length=12, use_upper=False, use_lower=False, use_digits=True, use_symbols=False)
        self.assertTrue(all(c.isdigit() for c in pw))
        self.assertEqual(len(pw), 12)

    def test_randomness(self):
        pw1 = generate_password(length=20)
        pw2 = generate_password(length=20)
        self.assertNotEqual(pw1, pw2)


class TestPasswordVault(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._vault_path = os.path.join(self._tmpdir, "test.vault")

    def tearDown(self):
        if os.path.exists(self._vault_path):
            os.remove(self._vault_path)
        os.rmdir(self._tmpdir)

    def _make_vault(self, password="masterpass") -> PasswordVault:
        v = PasswordVault(self._vault_path)
        v.create(password)
        return v

    def test_create_and_open(self):
        self._make_vault()
        v = PasswordVault(self._vault_path)
        v.open("masterpass")
        self.assertTrue(v.is_open())

    def test_wrong_password_raises(self):
        self._make_vault()
        v = PasswordVault(self._vault_path)
        with self.assertRaises(WrongPasswordError):
            v.open("wrongpassword")

    def test_add_and_get_entry(self):
        v = self._make_vault()
        v.add_entry("github.com", "secret123", username="user@example.com", url="https://github.com")
        entry = v.get_entry("github.com")
        self.assertEqual(entry["password"], "secret123")
        self.assertEqual(entry["username"], "user@example.com")

    def test_list_entries(self):
        v = self._make_vault()
        v.add_entry("site1", "pw1")
        v.add_entry("site2", "pw2")
        entries = v.list_entries()
        self.assertIn("site1", entries)
        self.assertIn("site2", entries)

    def test_delete_entry(self):
        v = self._make_vault()
        v.add_entry("mysite", "pw")
        v.delete_entry("mysite")
        with self.assertRaises(KeyError):
            v.get_entry("mysite")

    def test_delete_nonexistent_raises(self):
        v = self._make_vault()
        with self.assertRaises(KeyError):
            v.delete_entry("nonexistent")

    def test_vault_closed_raises(self):
        v = self._make_vault()
        v.close()
        with self.assertRaises(VaultError):
            v.list_entries()

    def test_entry_persists_after_reopen(self):
        v = self._make_vault()
        v.add_entry("persistent", "value", username="testuser")

        v2 = PasswordVault(self._vault_path)
        v2.open("masterpass")
        entry = v2.get_entry("persistent")
        self.assertEqual(entry["password"], "value")
        self.assertEqual(entry["username"], "testuser")

    def test_change_master_password(self):
        v = self._make_vault("oldpass")
        v.change_master_password("newpass")

        v2 = PasswordVault(self._vault_path)
        with self.assertRaises(WrongPasswordError):
            v2.open("oldpass")

        v3 = PasswordVault(self._vault_path)
        v3.open("newpass")
        self.assertTrue(v3.is_open())

    def test_2fa_enabled_requires_code(self):
        import pyotp

        v = PasswordVault(self._vault_path)
        v.create("masterpass", enable_2fa=True)
        totp_secret = v._data["totp_secret"]  # noqa: SLF001

        v2 = PasswordVault(self._vault_path)
        with self.assertRaises(TwoFactorRequiredError):
            v2.open("masterpass")

        totp = pyotp.TOTP(totp_secret)
        valid_code = totp.now()
        v3 = PasswordVault(self._vault_path)
        v3.open("masterpass", totp_code=valid_code)
        self.assertTrue(v3.is_open())

    def test_2fa_wrong_code_raises(self):
        import pyotp

        v = PasswordVault(self._vault_path)
        v.create("masterpass", enable_2fa=True)

        v2 = PasswordVault(self._vault_path)
        with self.assertRaises(WrongPasswordError):
            v2.open("masterpass", totp_code="000000")

    def test_enable_2fa_on_open_vault(self):
        import pyotp

        v = self._make_vault()
        uri = v.enable_2fa()
        self.assertIsNotNone(uri)
        self.assertIn("otpauth://", uri)
        totp_secret = v._data["totp_secret"]  # noqa: SLF001

        # Reopen requires 2FA now
        v2 = PasswordVault(self._vault_path)
        with self.assertRaises(TwoFactorRequiredError):
            v2.open("masterpass")

        code = pyotp.TOTP(totp_secret).now()
        v3 = PasswordVault(self._vault_path)
        v3.open("masterpass", totp_code=code)
        self.assertTrue(v3.is_open())

    def test_disable_2fa(self):
        import pyotp

        v = PasswordVault(self._vault_path)
        v.create("masterpass", enable_2fa=True)
        v.disable_2fa()

        v2 = PasswordVault(self._vault_path)
        v2.open("masterpass")  # No 2FA required
        self.assertTrue(v2.is_open())

    def test_get_nonexistent_entry_raises(self):
        v = self._make_vault()
        with self.assertRaises(KeyError):
            v.get_entry("does_not_exist")

    def test_create_vault_returns_uri_when_2fa(self):
        v = PasswordVault(self._vault_path)
        uri = v.create("masterpass", enable_2fa=True)
        self.assertIsNotNone(uri)
        self.assertIn("otpauth://", uri)

    def test_create_vault_returns_none_without_2fa(self):
        v = PasswordVault(self._vault_path)
        uri = v.create("masterpass", enable_2fa=False)
        self.assertIsNone(uri)


if __name__ == "__main__":
    unittest.main()
