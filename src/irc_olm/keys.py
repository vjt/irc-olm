"""Keys and signatures as the wire spells them.

A key is standard base64, unpadded, 43 characters, and valid only in the one
spelling vodozemac's to_base64() gives it back: keys are compared as exact
strings, so two spellings of one key must never both pass. A signature is 86
characters.
"""

from __future__ import annotations

import base64

import vodozemac as vz

SIG_LEN = 86


def b64u(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=")


def unb64u(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


def ed25519_key(key: str) -> vz.Ed25519PublicKey:
    """An Ed25519 key from base64. Raises ValueError on a malformed one.
    vodozemac 0.10 PANICS on a key of 33 bytes, and pyo3 raises that as a
    PanicException, a BaseException: it never sees anything but 32."""
    if len(unb64u(key)) != 32:
        raise ValueError("an Ed25519 key is 32 bytes")
    return vz.Ed25519PublicKey.from_base64(key)


def is_key(value: object) -> bool:
    """An Ed25519 key in its one wire spelling."""
    if not isinstance(value, str):
        return False
    try:
        return ed25519_key(value).to_base64() == value
    except (ValueError, vz.KeyException):
        return False


def is_curve(value: object) -> bool:
    """A Curve25519 key in its one wire spelling."""
    if not isinstance(value, str):
        return False
    try:
        return vz.Curve25519PublicKey.from_base64(value).to_base64() == value
    except (ValueError, vz.KeyException):
        return False


def sig_ok(ed25519: str, text: str, sig: object) -> bool:
    """Whether `sig` is `ed25519`'s signature over the UTF-8 of `text`."""
    if not isinstance(sig, str) or len(sig) != SIG_LEN:
        return False
    try:
        ed25519_key(ed25519).verify_signature(text.encode(), vz.Ed25519Signature.from_base64(sig))
    except (vz.KeyException, vz.SignatureException, vz.DecodeException, ValueError):
        return False
    return True
