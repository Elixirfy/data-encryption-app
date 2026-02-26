"""
Password vault: store, retrieve and manage passwords.

Storage format
--------------
The vault is a single JSON file encrypted with AES-256-CBC using a master
password (PBKDF2-derived key).  An optional TOTP secret enables 2FA.

Vault JSON (plaintext) structure::

    {
        "version": 1,
        "totp_secret": "<base32-secret or null>",
        "entries": {
            "<name>": {
                "password": "<plaintext password>",
                "username": "<username>",
                "url": "<url>",
                "notes": "<notes>",
                "created_at": "<ISO-8601 timestamp>"
            },
            ...
        }
    }
"""

import base64
import hashlib
import json
import os
import secrets
import string
import struct
from datetime import datetime, timezone

import pyotp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

__all__ = [
    "VaultError",
    "WrongPasswordError",
    "TwoFactorRequiredError",
    "PasswordVault",
    "generate_password",
]

_MAGIC = b"VAULT1"
_SALT_LEN = 16
_ITERATIONS = 200_000


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class VaultError(Exception):
    """Base class for vault errors."""


class WrongPasswordError(VaultError):
    """Raised when the master password is incorrect."""


class TwoFactorRequiredError(VaultError):
    """Raised when 2FA verification is required but no code was provided."""


# ---------------------------------------------------------------------------
# Low-level crypto helpers
# ---------------------------------------------------------------------------

def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS, dklen=32)


def _encrypt_vault(data: bytes, password: str) -> bytes:
    """Encrypt raw bytes; return MAGIC | SALT | IV | CIPHERTEXT."""
    salt = get_random_bytes(_SALT_LEN)
    key = _derive_key(password, salt)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return _MAGIC + salt + iv + ciphertext


def _decrypt_vault(blob: bytes, password: str) -> bytes:
    """Decrypt a blob produced by :func:`_encrypt_vault`."""
    if not blob.startswith(_MAGIC):
        raise WrongPasswordError("Invalid vault file format.")
    offset = len(_MAGIC)
    salt = blob[offset: offset + _SALT_LEN]
    offset += _SALT_LEN
    iv = blob[offset: offset + AES.block_size]
    offset += AES.block_size
    ciphertext = blob[offset:]
    key = _derive_key(password, salt)
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    except (ValueError, KeyError) as exc:
        raise WrongPasswordError("Wrong master password or corrupted vault.") from exc


# ---------------------------------------------------------------------------
# Password generator
# ---------------------------------------------------------------------------

def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """Generate a cryptographically secure random password.

    :param length: Password length (minimum 4).
    :raises ValueError: If *length* < 4 or no character sets selected.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4.")
    charset = ""
    required: list[str] = []
    if use_upper:
        charset += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        charset += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        charset += string.digits
        required.append(secrets.choice(string.digits))
    if use_symbols:
        charset += string.punctuation
        required.append(secrets.choice(string.punctuation))
    if not charset:
        raise ValueError("At least one character set must be selected.")

    remaining = [secrets.choice(charset) for _ in range(length - len(required))]
    pool = required + remaining
    secrets.SystemRandom().shuffle(pool)
    return "".join(pool)


# ---------------------------------------------------------------------------
# Vault class
# ---------------------------------------------------------------------------

class PasswordVault:
    """Encrypted, 2FA-protected password vault."""

    def __init__(self, vault_path: str) -> None:
        self._path = vault_path
        self._master_password: str | None = None
        self._data: dict = {}

    # ------------------------------------------------------------------
    # Vault lifecycle
    # ------------------------------------------------------------------

    def create(self, master_password: str, enable_2fa: bool = False) -> str | None:
        """Create a new vault.

        :param master_password: The master password to protect the vault.
        :param enable_2fa: If True, generate a TOTP secret.
        :returns: The TOTP provisioning URI (for QR code) when 2FA is enabled,
                  otherwise *None*.
        """
        self._master_password = master_password
        totp_secret = None
        provisioning_uri = None
        if enable_2fa:
            totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(totp_secret)
            provisioning_uri = totp.provisioning_uri(
                name="DataEncryptionApp", issuer_name="DataEncryptionApp"
            )
        self._data = {
            "version": 1,
            "totp_secret": totp_secret,
            "entries": {},
        }
        self._save()
        return provisioning_uri

    def open(self, master_password: str, totp_code: str | None = None) -> None:
        """Open an existing vault.

        :param master_password: The master password.
        :param totp_code: The current TOTP code (required if 2FA is enabled).
        :raises WrongPasswordError: On bad password or corrupted vault.
        :raises TwoFactorRequiredError: If 2FA is enabled but no code given.
        """
        with open(self._path, "rb") as f:
            blob = f.read()
        raw = _decrypt_vault(blob, master_password)
        data = json.loads(raw.decode())

        totp_secret = data.get("totp_secret")
        if totp_secret:
            if totp_code is None:
                raise TwoFactorRequiredError(
                    "This vault requires a 2FA code. Please provide a TOTP code."
                )
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(totp_code):
                raise WrongPasswordError("Invalid 2FA code.")

        self._master_password = master_password
        self._data = data

    def is_open(self) -> bool:
        return self._master_password is not None and bool(self._data)

    def close(self) -> None:
        """Lock the vault (clear in-memory data)."""
        self._master_password = None
        self._data = {}

    # ------------------------------------------------------------------
    # 2FA management
    # ------------------------------------------------------------------

    def enable_2fa(self) -> str:
        """Enable 2FA on an already-open vault.

        :returns: The TOTP provisioning URI.
        :raises VaultError: If vault is not open.
        """
        self._check_open()
        totp_secret = pyotp.random_base32()
        self._data["totp_secret"] = totp_secret
        self._save()
        totp = pyotp.TOTP(totp_secret)
        return totp.provisioning_uri(
            name="DataEncryptionApp", issuer_name="DataEncryptionApp"
        )

    def disable_2fa(self) -> None:
        """Disable 2FA on an open vault."""
        self._check_open()
        self._data["totp_secret"] = None
        self._save()

    def has_2fa(self) -> bool:
        """Return True if this vault has 2FA enabled."""
        if not os.path.isfile(self._path):
            return False
        try:
            with open(self._path, "rb") as f:
                blob = f.read()
            # We need to decrypt to check; use current master password if open
            if self._master_password:
                raw = _decrypt_vault(blob, self._master_password)
                d = json.loads(raw.decode())
                return bool(d.get("totp_secret"))
        except Exception:
            pass
        return bool(self._data.get("totp_secret"))

    # ------------------------------------------------------------------
    # Entry CRUD
    # ------------------------------------------------------------------

    def add_entry(
        self,
        name: str,
        password: str,
        username: str = "",
        url: str = "",
        notes: str = "",
    ) -> None:
        """Add or update a password entry."""
        self._check_open()
        self._data["entries"][name] = {
            "password": password,
            "username": username,
            "url": url,
            "notes": notes,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()

    def get_entry(self, name: str) -> dict:
        """Return the entry dict for *name*.

        :raises KeyError: If *name* does not exist.
        """
        self._check_open()
        if name not in self._data["entries"]:
            raise KeyError(f"Entry '{name}' not found.")
        return self._data["entries"][name]

    def delete_entry(self, name: str) -> None:
        """Delete the entry for *name*."""
        self._check_open()
        if name not in self._data["entries"]:
            raise KeyError(f"Entry '{name}' not found.")
        del self._data["entries"][name]
        self._save()

    def list_entries(self) -> list[str]:
        """Return a sorted list of entry names."""
        self._check_open()
        return sorted(self._data["entries"].keys())

    def change_master_password(self, new_password: str) -> None:
        """Re-encrypt the vault with a new master password."""
        self._check_open()
        self._master_password = new_password
        self._save()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_open(self) -> None:
        if not self.is_open():
            raise VaultError("Vault is not open. Call open() or create() first.")

    def _save(self) -> None:
        raw = json.dumps(self._data, ensure_ascii=False).encode()
        blob = _encrypt_vault(raw, self._master_password)
        with open(self._path, "wb") as f:
            f.write(blob)
