"""Order challenges (CHAL/ACK): the per-order second factor.

An order given outside the encrypted query (in a channel, or in a plaintext
query) is bound to the exact line: the bot sends a CHAL inside the verified
session, and the human's client answers ACK only if it sent exactly that line
there in the last 15 s. The bot accepts iff the ACK comes back from a device
of the same master (wire v2: any of its trusted devices may answer), with an
unused nonce, before it expires. Spec: grappa-irc#2430,
"Authorising orders"; 15 s is vjt's decision 5.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

CHALLENGE_TTL = 15


@dataclass(frozen=True)
class Challenge:
    nonce: str
    nick: str
    master: str
    network: str
    channel: str
    sender_mask: str
    line_sha256: str
    expires_at: int

    def inner(self) -> dict:
        return {"t": "chal", "network": self.network, "channel": self.channel,
                "sender_mask": self.sender_mask, "line_sha256": self.line_sha256,
                "nonce": self.nonce, "expires_at": self.expires_at}


def new_challenge(*, nick: str, master: str, network: str, channel: str,
                  sender_mask: str, line: bytes, now: float) -> Challenge:
    nonce = base64.b64encode(os.urandom(16)).decode().rstrip("=")
    return Challenge(nonce, nick, master, network, channel, sender_mask,
                     hashlib.sha256(line).hexdigest(), int(now) + CHALLENGE_TTL)


class ChallengeBook:
    """Pending challenges by nonce. Every nonce is accepted at most once."""

    def __init__(self):
        self._pending: dict[str, Challenge] = {}

    def add(self, ch: Challenge) -> None:
        self._pending[ch.nonce] = ch

    def check(self, nonce: str, master: str, now: float) -> tuple[Challenge | None, str | None]:
        """(challenge, None) when the ACK is good, (None, reason) otherwise."""
        ch = self._pending.get(nonce)
        if ch is None:
            return None, "unknown-nonce"
        if ch.master != master:
            return None, "wrong-peer"   # the nonce stays usable by its owner
        del self._pending[nonce]
        if now > ch.expires_at:
            return None, "expired"
        return ch, None

    def expire(self, now: float) -> list[Challenge]:
        gone = [c for c in self._pending.values() if now > c.expires_at]
        for c in gone:
            del self._pending[c.nonce]
        return gone
