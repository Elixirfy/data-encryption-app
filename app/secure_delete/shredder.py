"""
Secure file deletion utilities.

Supported algorithms:
  * DoD 5220.22-M  (7-pass)
  * Gutmann        (35-pass)

Both algorithms overwrite the file data in-place multiple times before the
OS-level unlink, making data recovery significantly harder.
"""

import os
import secrets

__all__ = ["secure_delete", "ALGORITHMS"]

ALGORITHMS = ["DoD 5220.22-M (7-pass)", "Gutmann (35-pass)"]

# ---------------------------------------------------------------------------
# Pass-pattern helpers
# ---------------------------------------------------------------------------

def _overwrite(fd: int, size: int, data: bytes) -> None:
    """Write *data* (repeated as necessary) over *size* bytes, then fsync."""
    os.lseek(fd, 0, os.SEEK_SET)
    written = 0
    while written < size:
        chunk = data * ((min(65536, size - written) // len(data)) + 1)
        n = min(len(chunk), size - written)
        os.write(fd, chunk[:n])
        written += n
    os.fsync(fd)


def _overwrite_random(fd: int, size: int) -> None:
    """Overwrite with cryptographically random bytes."""
    os.lseek(fd, 0, os.SEEK_SET)
    written = 0
    while written < size:
        n = min(65536, size - written)
        os.write(fd, secrets.token_bytes(n))
        written += n
    os.fsync(fd)


# ---------------------------------------------------------------------------
# DoD 5220.22-M  (7 passes)
# ---------------------------------------------------------------------------

def _dod_passes(fd: int, size: int) -> None:
    """Perform the 7-pass DoD 5220.22-M overwrite sequence."""
    _overwrite(fd, size, b"\x00")       # pass 1 – all zeros
    _overwrite(fd, size, b"\xFF")       # pass 2 – all ones
    _overwrite_random(fd, size)         # pass 3 – random
    _overwrite(fd, size, b"\x96")      # pass 4 – 0x96
    _overwrite_random(fd, size)         # pass 5 – random
    _overwrite_random(fd, size)         # pass 6 – random
    _overwrite_random(fd, size)         # pass 7 – random


# ---------------------------------------------------------------------------
# Gutmann (35 passes)
# ---------------------------------------------------------------------------

# The 27 specific Gutmann patterns (passes 5–31).
_GUTMANN_PATTERNS = [
    b"\x55", b"\xAA", b"\x92\x49\x24", b"\x49\x24\x92", b"\x24\x92\x49",
    b"\x00", b"\x11", b"\x22", b"\x33", b"\x44", b"\x55", b"\x66", b"\x77",
    b"\x88", b"\x99", b"\xAA", b"\xBB", b"\xCC", b"\xDD", b"\xEE", b"\xFF",
    b"\x92\x49\x24", b"\x49\x24\x92", b"\x24\x92\x49",
    b"\x6D\xB6\xDB", b"\xB6\xDB\x6D", b"\xDB\x6D\xB6",
]


def _gutmann_passes(fd: int, size: int) -> None:
    """Perform the 35-pass Gutmann overwrite sequence."""
    # Passes 1–4: random
    for _ in range(4):
        _overwrite_random(fd, size)
    # Passes 5–31: specific patterns
    for pattern in _GUTMANN_PATTERNS:
        _overwrite(fd, size, pattern)
    # Passes 32–35: random
    for _ in range(4):
        _overwrite_random(fd, size)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def secure_delete(path: str, algorithm: str = "DoD 5220.22-M (7-pass)") -> None:
    """Securely delete *path* using the chosen *algorithm*.

    The file contents are overwritten according to the selected algorithm
    before the file is removed from the filesystem.

    :param path: Absolute or relative path to the file to delete.
    :param algorithm: One of :data:`ALGORITHMS`.
    :raises FileNotFoundError: If *path* does not exist.
    :raises ValueError: If *algorithm* is unknown.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm '{algorithm}'. Choose from {ALGORITHMS}.")

    size = os.path.getsize(path)
    # Open the file for both reading and writing (binary, no truncation)
    fd = os.open(path, os.O_RDWR)
    try:
        if size > 0:
            if algorithm == "DoD 5220.22-M (7-pass)":
                _dod_passes(fd, size)
            else:  # Gutmann
                _gutmann_passes(fd, size)
    finally:
        os.close(fd)

    os.remove(path)
