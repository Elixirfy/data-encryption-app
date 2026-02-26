"""
Encryption/decryption utilities for files and text.
Supported algorithms: AES-256-CBC, 3DES-CBC, Blowfish-CBC.

Security note
-------------
3DES (Triple DES) is included because the problem specification explicitly
requires it.  It is considered deprecated/weak by NIST (SP 800-131A) due to
its 64-bit block size (meet-in-the-middle, Sweet32 attacks) and should *not*
be chosen for new data.  Prefer AES-256 for all practical use.
Blowfish similarly has a 64-bit block size; AES-256 is the recommended choice.
"""

import os
import hashlib
import struct

from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

ALGORITHMS = ["AES-256", "3DES", "Blowfish"]

# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _derive_key(password: str, salt: bytes, key_len: int) -> bytes:
    """Derive a key from *password* using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=key_len)


def _key_len_for(algorithm: str) -> int:
    return {
        "AES-256": 32,
        "3DES": 24,
        "Blowfish": 32,
    }[algorithm]


def _block_size_for(algorithm: str) -> int:
    return {
        "AES-256": AES.block_size,
        "3DES": DES3.block_size,
        "Blowfish": Blowfish.block_size,
    }[algorithm]


def _make_cipher(algorithm: str, key: bytes, iv: bytes):
    """Return a new CBC cipher object."""
    if algorithm == "AES-256":
        return AES.new(key, AES.MODE_CBC, iv)
    if algorithm == "3DES":
        return DES3.new(key, DES3.MODE_CBC, iv)
    if algorithm == "Blowfish":
        return Blowfish.new(key, Blowfish.MODE_CBC, iv)
    raise ValueError(f"Unknown algorithm: {algorithm}")


# ---------------------------------------------------------------------------
# Text encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_text(plaintext: str, password: str, algorithm: str = "AES-256") -> bytes:
    """Encrypt *plaintext* and return the raw ciphertext blob.

    Format:  SALT(16) | IV(block_size) | CIPHERTEXT
    """
    salt = get_random_bytes(16)
    key = _derive_key(password, salt, _key_len_for(algorithm))
    block_size = _block_size_for(algorithm)
    iv = get_random_bytes(block_size)
    cipher = _make_cipher(algorithm, key, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), block_size))
    return salt + iv + ciphertext


def decrypt_text(blob: bytes, password: str, algorithm: str = "AES-256") -> str:
    """Decrypt a blob produced by :func:`encrypt_text`."""
    block_size = _block_size_for(algorithm)
    salt = blob[:16]
    iv = blob[16: 16 + block_size]
    ciphertext = blob[16 + block_size:]
    key = _derive_key(password, salt, _key_len_for(algorithm))
    cipher = _make_cipher(algorithm, key, iv)
    return unpad(cipher.decrypt(ciphertext), block_size).decode("utf-8")


# ---------------------------------------------------------------------------
# File encryption / decryption
# ---------------------------------------------------------------------------

_MAGIC = b"ENCF"  # 4-byte magic header
_HEADER_VERSION = 1


def encrypt_file(src_path: str, dst_path: str, password: str, algorithm: str = "AES-256") -> None:
    """Encrypt the file at *src_path* and write to *dst_path*.

    File format:
        MAGIC(4) | VERSION(1) | ALGO_LEN(1) | ALGO(variable) |
        SALT(16) | IV(block_size) | ORIG_SIZE(8, little-endian) | CIPHERTEXT
    """
    algo_bytes = algorithm.encode()
    salt = get_random_bytes(16)
    key = _derive_key(password, salt, _key_len_for(algorithm))
    block_size = _block_size_for(algorithm)
    iv = get_random_bytes(block_size)

    with open(src_path, "rb") as f:
        plaintext = f.read()

    orig_size = len(plaintext)
    cipher = _make_cipher(algorithm, key, iv)
    ciphertext = cipher.encrypt(pad(plaintext, block_size))

    with open(dst_path, "wb") as f:
        f.write(_MAGIC)
        f.write(struct.pack("B", _HEADER_VERSION))
        f.write(struct.pack("B", len(algo_bytes)))
        f.write(algo_bytes)
        f.write(salt)
        f.write(iv)
        f.write(struct.pack("<Q", orig_size))
        f.write(ciphertext)


def decrypt_file(src_path: str, dst_path: str, password: str) -> str:
    """Decrypt the file at *src_path* and write to *dst_path*.

    Returns the algorithm name that was used.
    Raises ValueError on wrong password / corrupt file.
    """
    with open(src_path, "rb") as f:
        magic = f.read(4)
        if magic != _MAGIC:
            raise ValueError("Not a valid encrypted file.")
        version = struct.unpack("B", f.read(1))[0]  # reserved for future format versions
        algo_len = struct.unpack("B", f.read(1))[0]
        algorithm = f.read(algo_len).decode()
        salt = f.read(16)
        block_size = _block_size_for(algorithm)
        iv = f.read(block_size)
        orig_size = struct.unpack("<Q", f.read(8))[0]
        ciphertext = f.read()

    key = _derive_key(password, salt, _key_len_for(algorithm))
    try:
        cipher = _make_cipher(algorithm, key, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), block_size)
    except (ValueError, KeyError) as exc:
        raise ValueError("Decryption failed. Wrong password or corrupted file.") from exc

    # Trim padding artefacts using stored original size
    plaintext = plaintext[:orig_size]

    with open(dst_path, "wb") as f:
        f.write(plaintext)

    return algorithm


# ---------------------------------------------------------------------------
# File integrity (SHA-256 checksum)
# ---------------------------------------------------------------------------

def file_checksum(path: str) -> str:
    """Return the SHA-256 hex digest of *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_file_integrity(path: str, expected_checksum: str) -> bool:
    """Return True if *path* matches *expected_checksum* (SHA-256 hex)."""
    return file_checksum(path) == expected_checksum
