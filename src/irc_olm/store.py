"""On-disk state: the pickle key and the state file.

The key encrypts every secret in the state (vodozemac pickles the Olm account
and sessions with it). It lives outside any repository, next to the bot's
other secrets, and is generated once: losing it means a new identity, and
with that a re-verification on every peer.

Both files are mode 600 and are refused when group or others can read them,
the way ssh refuses a private key.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import stat
import tempfile
from pathlib import Path

KEY_BYTES = 32


class InsecureFileError(PermissionError):
    """A secret file readable or writable by group or others."""


class KeyFileError(ValueError):
    """A key file that does not hold a base64 32-byte key."""


def _check_private(path: Path) -> None:
    perm = stat.S_IMODE(os.stat(path).st_mode)
    if perm & 0o077:
        raise InsecureFileError(f"{path} is mode {perm:o}: must not be accessible to group or others")


def generate_key_file(path: str | os.PathLike) -> None:
    """Write a fresh random key, mode 600. Never overwrites."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o600)  # O_CREAT's mode is filtered by the umask
        f.write(base64.b64encode(os.urandom(KEY_BYTES)).decode() + "\n")


def load_key(path: str | os.PathLike) -> bytes:
    path = Path(path)
    _check_private(path)
    try:
        key = base64.b64decode(path.read_text().strip(), validate=True)
    except binascii.Error as e:
        raise KeyFileError(f"{path}: not base64") from e
    if len(key) != KEY_BYTES:
        raise KeyFileError(f"{path}: key is {len(key)} bytes, expected {KEY_BYTES}")
    return key


class StateFile:
    """A JSON document replaced atomically on every save."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)

    def load(self) -> dict | None:
        if not self.path.exists():
            return None
        _check_private(self.path)
        return json.loads(self.path.read_text())

    def save(self, doc: dict) -> None:
        data = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))  # raises before any I/O
        fd, tmp = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w") as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        dfd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
