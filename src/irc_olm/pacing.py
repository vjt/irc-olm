"""Paced sending of E2E lines: two limits, both from bahamut (Azzurra).

Per target, for the RECEIVER: bahamut drops every CTCP to a client for 15 s
once that client has received more than 4 CTCPs inside its 3 s window (FLUD,
src/s_user.c). The window is in integer seconds and a steady sender's count
keeps growing while its first message is inside it, so "3 per 3 s" still
trips it. 3 lines per 6 s never did in simulation, even with 2 s of arrival
jitter (tests/flud_model.py).

Per connection, for the SENDER: every line costs its sender `2 + bytes/120`
seconds of fake lag, the server parses a client's lines only while that bank
is under 10 s, and more than 2560 unparsed bytes disconnect it with "Excess
Flood" (src/parse.c, src/s_bsd.c; tests/fakelag_model.py). A full E2E line
costs 5 s, so without the bank 3 lines per 6 s gets a long sender killed:
measured on a testnet bahamut at the 12th full line (grappa-irc 2430). A line
is released only when the bank plus its cost stays at or under 10 s, so no
line ever waits unparsed on the server; a long message then takes minutes
(vjt's ruling on grappa-irc 2430, option A).

Urgent messages go out ahead of text: KEYREQ, KEYS and NACK, and the messages
the engine marks for carrying a CHAL or an ACK (Result.urgent), or a CHAL
could expire in the queue. Text keeps its order: a short message never
overtakes a long one sent before it, which its reader would see reversed.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from itertools import count
from typing import Callable

from . import framing

DEFAULT_MAX_LINES = 3
DEFAULT_WINDOW = 6.0
# Queued text, all targets, in seconds of flood bank: 96 full lines. It must
# drain, and a NACK come back, while the engine still remembers what it sent
# (engine.SENT_MEMORY); past it, whatever is generating the text is broken.
DEFAULT_MAX_BACKLOG = 480.0

FAKE_LAG_CEILING = 10.0

log = logging.getLogger(__name__)


class FakeLag:
    """bahamut's flood bank for ONE connection, modelled on our side.

    Every line written to the connection must be charged, whatever it is
    (registration, PONG, chat): the server counts them all. A Pacer charges
    the lines it releases; the application charges every other line it
    writes. Pure apart from a lock: callers pass the time, on the same
    monotonic clock as the PacedSender's. The arithmetic is grappa's
    (Grappa.IRC.FakeLag), so both implementations agree.
    """

    def __init__(self, ceiling: float = FAKE_LAG_CEILING):
        self.ceiling = ceiling
        self._since: float | None = None
        self._lock = threading.Lock()

    @staticmethod
    def cost(line: str) -> int:
        """`2 + bytes/120` in the C's integer arithmetic, bytes being the
        frame as written, CRLF included (a hair above what bahamut counts)."""
        return 2 + (len(line.encode()) + 2) // 120

    def charge(self, line: str, now: float) -> None:
        self.add(self.cost(line), now)

    def add(self, cost: float, now: float) -> None:
        with self._lock:
            self._since = now + cost if self._since is None else max(self._since, now) + cost

    def bank(self, now: float) -> float:
        with self._lock:
            return 0.0 if self._since is None else max(0.0, self._since - now)

    def room_at(self, cost: float, now: float) -> float:
        """The earliest time, not before `now`, at which a line of `cost`
        keeps the bank at or under the ceiling."""
        with self._lock:
            if self._since is None:
                return now
            return max(now, self._since + cost - self.ceiling)


class Pacer:
    """At most `max_lines` lines to one target in any `window` seconds and,
    given a FakeLag, never past the connection's flood bank.

    Pure scheduling, no threads and no clock of its own: the caller asks what
    is due at a given time. Urgent lines go before text; otherwise lines go
    in the order they were submitted. `fakelag=None` paces per target only,
    which is not enough on a real connection.
    """

    def __init__(self, max_lines: int = DEFAULT_MAX_LINES, window: float = DEFAULT_WINDOW,
                 max_backlog: float = DEFAULT_MAX_BACKLOG, *, fakelag: FakeLag | None):
        self.max_lines = max_lines
        self.window = window
        self.max_backlog = max_backlog
        self.fakelag = fakelag
        self._seq = count()
        # target -> (urgent, text), each [(seq, line)]
        self._queues: dict[str, tuple[deque, deque]] = {}
        self._text_cost = 0           # flood bank the queued text will cost
        self._sent: dict[str, deque[float]] = {}

    def submit(self, target: str, lines: list[str], *, urgent: bool) -> bool:
        """Queue `lines` for `target`. Urgent lines are always taken: the
        protocol's own are rate-limited at the source. Text is all or
        nothing, False (nothing queued) when it would take the queued text
        past `max_backlog`: half a fragmented message is worse than none."""
        cost = sum(self._cost(target, line) for line in lines)
        if not urgent and self._text_cost + cost > self.max_backlog:
            return False
        lane = self._queues.setdefault(target, (deque(), deque()))[0 if urgent else 1]
        lane.extend((next(self._seq), line) for line in lines)
        if not urgent:
            self._text_cost += cost
        return True

    def _queued(self, target: str) -> int:
        return sum(len(q) for q in self._queues.get(target, ()))

    def pending(self) -> int:
        return sum(self._queued(t) for t in self._queues)

    def _slot(self, target: str, now: float) -> float:
        sent = self._sent.setdefault(target, deque())
        while sent and sent[0] <= now - self.window:
            sent.popleft()
        if len(sent) < self.max_lines:
            return now
        return sent[-self.max_lines] + self.window

    def _head(self, target: str):
        """(lane, seq, line, queue) of the line `target` would send next."""
        urgent, text = self._queues[target]
        q, lane = (urgent, 0) if urgent else (text, 1)
        seq, line = q[0]
        return lane, seq, line, q

    def _cost(self, target: str, line: str) -> int:
        return FakeLag.cost(f"PRIVMSG {target} :{line}")

    def due(self, now: float) -> list[tuple[str, str]]:
        """Release what may go now, charging it to the bank. Strictly in
        (urgent first, then submission) order: the first line the bank has no
        room for stops everything after it, so nothing starves."""
        for t in [t for t, sent in self._sent.items()
                  if t not in self._queues and (not sent or sent[-1] <= now - self.window)]:
            del self._sent[t]           # a target gone quiet leaves nothing behind
        out = []
        while True:
            ready = sorted((self._head(t)[:2], t) for t in self._queues
                           if self._slot(t, now) <= now)
            if not ready:
                break
            target = ready[0][1]
            lane, _, line, q = self._head(target)
            cost = self._cost(target, line)
            if self.fakelag is not None:
                if self.fakelag.room_at(cost, now) > now:
                    break
                self.fakelag.add(cost, now)
            q.popleft()
            if lane:
                self._text_cost -= cost
            self._sent[target].append(now)
            out.append((target, line))
            if not self._queued(target):
                del self._queues[target]
        return out

    def next_wakeup(self, now: float) -> float | None:
        if not self._queues:
            return None
        times = []
        for t in self._queues:
            slot = self._slot(t, now)
            if self.fakelag is not None:
                slot = max(slot, self.fakelag.room_at(self._cost(t, self._head(t)[2]), now))
            times.append(slot)
        return min(times)


class PacedSender:
    """A daemon thread draining a Pacer into `send(target, line)`. The lines
    it hands to `send` are already charged to the Pacer's FakeLag: `send`
    must write them without charging them again."""

    def __init__(self, send: Callable[[str, str], None], pacer: Pacer,
                 clock: Callable[[], float] = time.monotonic):
        self._send = send
        self._pacer = pacer
        self._clock = clock
        self._cv = threading.Condition()
        self._thread = threading.Thread(target=self._run, name="irc-olm-pacer", daemon=True)
        self._thread.start()

    def submit(self, target: str, lines: list[str], *, urgent: bool) -> bool:
        with self._cv:
            ok = self._pacer.submit(target, lines, urgent=urgent)
            self._cv.notify()
        if not ok:
            log.warning("pacer backlog full: %d lines to %s refused", len(lines), target)
        return ok

    def submit_all(self, outbound: list[tuple[str, str]], urgent: set[str]) -> int:
        """Submit an Engine Result: `submit_all(result.outbound, result.urgent)`.
        Order is kept per target and lane, each target's text all or nothing.
        Returns the number of lines refused (logged)."""
        batches: dict[tuple[str, bool], list[str]] = {}
        for target, body in outbound:
            frag = framing.parse(body)
            batches.setdefault((target, frag is not None and frag.msgid in urgent), []).append(body)
        return sum(len(lines) for (target, lane_urgent), lines in batches.items()
                   if not self.submit(target, lines, urgent=lane_urgent))

    def _run(self) -> None:
        while True:
            with self._cv:
                now = self._clock()
                batch = self._pacer.due(now)
                if not batch:
                    wake = self._pacer.next_wakeup(now)
                    self._cv.wait(None if wake is None else max(0.0, wake - now))
                    continue
            for target, line in batch:
                try:
                    self._send(target, line)
                except Exception:
                    # One failed write (a socket mid-reconnect, say) must not
                    # kill the thread: everything after it would wait forever.
                    log.exception("pacer: send to %s failed, line dropped", target)
