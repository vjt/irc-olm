"""The operator's pinned keys: the only identities a bot talks E2E with.

One `<nick> <ed25519>` per line, `#` comments and blank lines ignored. The key
is the peer's master Ed25519 key (wire v2: the one that signs its devices) as
vodozemac prints it (`to_base64()`: standard alphabet, unpadded, 43
characters). The nick is where the bot sends to; the key is what it trusts.
Rotation means re-pasting the key.

The bot only ever READS this file. It must not be writable by the bot's own
Claude session: the operator makes it root-owned, or denies it to that session
in its permission rules. load_pins() cannot enforce that; pins_writable()
lets the bot say so loudly.
"""

from __future__ import annotations

import os
import re

import vodozemac as vz

from .framing import fold

_KEY = re.compile(r"[A-Za-z0-9+/]{43}")


class PinsError(ValueError):
    """A malformed pins file."""


def parse_pins(text: str, source: str = "pins") -> dict[str, str]:
    pins: dict[str, str] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise PinsError(f"{source}:{n}: expected '<nick> <ed25519 key>'")
        nick, key = parts
        try:
            # vodozemac refuses stray bits in the last character too, so a
            # key has one spelling and two spellings never pin one key twice.
            ok = _KEY.fullmatch(key) and vz.Ed25519PublicKey.from_base64(key)
        except vz.KeyException:
            ok = False
        if not ok:
            raise PinsError(f"{source}:{n}: {key!r} is not an unpadded base64 Ed25519 key")
        if fold(nick) in {fold(k) for k in pins}:
            raise PinsError(f"{source}:{n}: {nick!r} is pinned twice")
        pins[nick] = key
    return pins


def load_pins(path: str | os.PathLike) -> dict[str, str]:
    with open(path, encoding="utf-8") as f:
        return parse_pins(f.read(), str(path))


def pins_writable(path: str | os.PathLike) -> bool:
    """True when this process could rewrite the pins file: the operator
    should make it root-owned (or deny it to the bot's Claude session)."""
    return os.access(path, os.W_OK) or os.access(os.path.dirname(os.path.abspath(path)), os.W_OK)
