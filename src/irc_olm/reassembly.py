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
    verb: str


@dataclass
class _Pending:
    verb: str
    total: int
    started: float
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
        self._evicted: list[tuple[str, Rejected]] = []

    def take_evicted(self) -> list[tuple[str, Rejected]]:
        """(sender, rejection) for the messages of OTHER senders the global
        cap dropped since the last call; the feeding sender's own comes back
        from feed()."""
        out, self._evicted = self._evicted, []
        return out

    def feed(self, sender: str, frag: Fragment) -> Assembled | Rejected | None:
        """Add one fragment. Returns the whole payload once complete, a
        rejection when the message is dropped, None while it is still open."""
        self._expire()
        if frag.total > self.max_fragments:
            return Rejected(frag.msgid, "too-many-fragments", frag.verb)
        if frag.total == 1:
            return Assembled(frag.verb, frag.msgid, frag.chunk)

        mine = self._pending.setdefault(sender, {})
        p = mine.get(frag.msgid)
        if p is None:
            if len(mine) >= self.max_pending:
                return self._reject(sender, frag, "too-many-pending")
            now = self.clock()
            p = mine[frag.msgid] = _Pending(frag.verb, frag.total, now, now)
        elif p.verb != frag.verb or p.total != frag.total:
            return self._reject(sender, frag, "inconsistent-fragment")
        if frag.index in p.chunks:
            return self._reject(sender, frag, "duplicate-fragment")

        p.chunks[frag.index] = frag.chunk
        p.last = self.clock()
        if sum(q.size for q in mine.values()) > self.max_bytes:
            return self._reject(sender, frag, "sender-byte-cap")
        if len(p.chunks) < p.total:
            if self._cap_total(sender, frag.msgid):
                return Rejected(frag.msgid, "global-byte-cap", frag.verb)
            return None
        self._drop(sender, frag.msgid)
        return Assembled(p.verb, frag.msgid, "".join(p.chunks[i] for i in range(1, p.total + 1)))

    def _reject(self, sender: str, frag: Fragment, reason: str) -> Rejected:
        self._drop(sender, frag.msgid)
        return Rejected(frag.msgid, reason, frag.verb)

    def _drop(self, sender: str, msgid: str) -> None:
        mine = self._pending.get(sender, {})
        mine.pop(msgid, None)
        if not mine:
            self._pending.pop(sender, None)

    def _cap_total(self, feeding: str, feeding_msgid: str) -> bool:
        """Until what is buffered, all senders together, fits
        `max_bytes_total`: drop, from the sender holding the most (on a tie
        the one whose latest message started last), its message furthest
        from completion. Not the idlest: paced, an honest long message is
        it, and the one closest to done. True when that dropped the message
        being fed; the others wait in take_evicted()."""
        held = {sender: sum(p.size for p in mine.values()) for sender, mine in self._pending.items()}
        total, mine = sum(held.values()), False
        while total > self.max_bytes_total:
            sender = max(held, key=lambda s: (held[s],
                                              max(p.started for p in self._pending[s].values())))
            msgid, p = min(self._pending[sender].items(),
                           key=lambda kv: (len(kv[1].chunks) / kv[1].total, kv[1].last))
            self._drop(sender, msgid)
            if (sender, msgid) == (feeding, feeding_msgid):
                mine = True
            else:
                self._evicted.append((sender, Rejected(msgid, "global-byte-cap", p.verb)))
            held[sender] -= p.size
            total -= p.size
            if sender not in self._pending:
                del held[sender]
        return mine

    def _expire(self) -> None:
        cutoff = self.clock() - self.timeout
        for sender in list(self._pending):
            for msgid, p in list(self._pending[sender].items()):
                if p.last < cutoff:
                    self._drop(sender, msgid)
