"""Reassembly of fragmented E2E messages, with anti-flood caps.

Buffered per (sender, msgid). The sender key is whatever the caller trusts to
identify the peer before decryption: in practice the case-folded nick, since
the peer's key is only known once the payload is decoded.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from .framing import MAX_FRAGMENTS, Fragment


@dataclass(frozen=True)
class Assembled:
    verb: str
    msgid: str
    payload: str


@dataclass(frozen=True)
class Rejected:
    msgid: str
    reason: str


@dataclass
class _Pending:
    verb: str
    total: int
    last: float          # the latest fragment: paced, a long message takes minutes
    chunks: dict[int, str] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return sum(len(c) for c in self.chunks.values())


class Reassembler:
    def __init__(self, *, timeout: float = 60.0, max_fragments: int = MAX_FRAGMENTS,
                 max_bytes_per_sender: int = 32 * 1024, max_pending_per_sender: int = 8,
                 max_bytes_total: int = 512 * 1024,
                 clock: Callable[[], float] = time.monotonic):
        self.timeout = timeout
        self.max_fragments = max_fragments
        self.max_bytes = max_bytes_per_sender
        self.max_pending = max_pending_per_sender
        # A message lives `timeout` from its LAST fragment, so one fragment a
        # minute keeps it alive: a sender changing nicks needs this cap too.
        self.max_bytes_total = max_bytes_total
        self.clock = clock
        self._pending: dict[str, dict[str, _Pending]] = {}

    def feed(self, sender: str, frag: Fragment) -> Assembled | Rejected | None:
        """Add one fragment. Returns the whole payload once complete, a
        rejection when the message is dropped, None while it is still open."""
        self._expire()
        if frag.total > self.max_fragments:
            return Rejected(frag.msgid, "too-many-fragments")
        if frag.total == 1:
            return Assembled(frag.verb, frag.msgid, frag.chunk)

        mine = self._pending.setdefault(sender, {})
        p = mine.get(frag.msgid)
        if p is None:
            if len(mine) >= self.max_pending:
                return self._reject(sender, frag.msgid, "too-many-pending")
            p = mine[frag.msgid] = _Pending(frag.verb, frag.total, self.clock())
        elif p.verb != frag.verb or p.total != frag.total:
            return self._reject(sender, frag.msgid, "inconsistent-fragment")
        if frag.index in p.chunks:
            return self._reject(sender, frag.msgid, "duplicate-fragment")

        p.chunks[frag.index] = frag.chunk
        p.last = self.clock()
        if sum(q.size for q in mine.values()) > self.max_bytes:
            return self._reject(sender, frag.msgid, "sender-byte-cap")
        if len(p.chunks) < p.total:
            self._cap_total()
            return None
        self._drop(sender, frag.msgid)
        return Assembled(p.verb, frag.msgid, "".join(p.chunks[i] for i in range(1, p.total + 1)))

    def _reject(self, sender: str, msgid: str, reason: str) -> Rejected:
        self._drop(sender, msgid)
        return Rejected(msgid, reason)

    def _drop(self, sender: str, msgid: str) -> None:
        mine = self._pending.get(sender, {})
        mine.pop(msgid, None)
        if not mine:
            self._pending.pop(sender, None)

    def _cap_total(self) -> None:
        """Until what is buffered, all senders together, fits
        `max_bytes_total`: drop the idlest message of the sender holding the
        most. Not the idlest overall: paced, an honest long message is it."""
        held = {sender: sum(p.size for p in mine.values()) for sender, mine in self._pending.items()}
        total = sum(held.values())
        while total > self.max_bytes_total:
            sender = max(held, key=held.get)
            msgid, p = min(self._pending[sender].items(), key=lambda kv: kv[1].last)
            self._drop(sender, msgid)
            held[sender] -= p.size
            total -= p.size
            if sender not in self._pending:
                del held[sender]

    def _expire(self) -> None:
        cutoff = self.clock() - self.timeout
        for sender in list(self._pending):
            for msgid, p in list(self._pending[sender].items()):
                if p.last < cutoff:
                    self._drop(sender, msgid)
