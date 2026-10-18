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
is released only when the bank plus its cost stays at or under 10 s, so a
line the pacer releases does not wait unparsed on the server as long as the
application charges what it writes itself; a long message then takes minutes
(vjt's ruling on grappa-irc 2430, option A).

Urgent messages go out ahead of text: KEYREQ, KEYS and NACK, and the messages
the engine marks for carrying a CHAL or an ACK (Result.urgent), or a CHAL
could expire in the queue. Each target gets a budget of them per minute, so a
peer flooding us cannot hold everyone else back. Text keeps its order: a
short message never overtakes a long one sent before it, which its reader
would see reversed.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from itertools import count
from typing import Callable

from . import framing
from .framing import fold

DEFAULT_MAX_LINES = 3
DEFAULT_WINDOW = 6.0
# Queued text, all targets, in seconds of flood bank: 96 full lines. It must
# drain, and a NACK come back, while the engine still remembers what it sent
# (engine.SENT_MEMORY), even with the application talking meanwhile.
DEFAULT_MAX_BACKLOG = 480.0
# Text messages queued per target. An urgent message (a CHAL, an ACK) goes
# ahead of them, and the receiver's Olm skips one message key per message
# overtaken; vodozemac keeps 40 (tests/test_engine_sessions.py pins this).
DEFAULT_MAX_TEXT_MESSAGES = 32
# Urgent lines queued per target: KEYS, NACKs and CHALs are a few lines each.
DEFAULT_MAX_URGENT = 32
# Urgent lines a target may send ahead of everyone's text per minute. A
# session and an order take a handful; a peer drawing more (KEYREQs and junk
# each draw an urgent answer) waits its turn with the text.
URGENT_BUDGET = 8
URGENT_BUDGET_WINDOW = 60.0

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

    def try_add(self, cost: float, now: float) -> bool:
        """Charge `cost` if the bank stays at or under the ceiling; checked
        and charged in one step, the application charging from its thread."""
        with self._lock:
            bank = 0.0 if self._since is None else max(0.0, self._since - now)
            if bank + cost > self.ceiling:
                return False
            self._since = now + cost if self._since is None else max(self._since, now) + cost
            return True

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
    is due at a given time. Urgent lines go ahead of everyone's text, within
    each target's URGENT_BUDGET; past it a target's urgent lines wait their
    turn with the text, so a peer flooding us with KEYREQs and junk (each
    drawing an urgent answer) takes its share of the bank and no more. Turns
    go to the target served longest ago. Within a target, urgent lines go
    before text, and each lane keeps its order. A target is its nick
    case-folded; each line keeps the spelling it came with. `fakelag=None`
    paces per target only, which is not enough on a real connection.
    """

    def __init__(self, max_lines: int = DEFAULT_MAX_LINES, window: float = DEFAULT_WINDOW,
                 max_backlog: float = DEFAULT_MAX_BACKLOG,
                 max_text_messages: int = DEFAULT_MAX_TEXT_MESSAGES,
                 max_urgent: int = DEFAULT_MAX_URGENT, *, fakelag: FakeLag | None):
        self.max_lines = max_lines
        self.window = window
        self.max_backlog = max_backlog
        self.max_text_messages = max_text_messages
        self.max_urgent = max_urgent
        self.fakelag = fakelag
        self._seq = count()
        # folded target -> (urgent, text), each [(seq, target as given, line)]
        self._queues: dict[str, tuple[deque, deque]] = {}
        self._text_cost = 0                   # flood bank the queued text will cost
        self._text_messages: dict[str, int] = {}
        self._sent: dict[str, deque[float]] = {}
        self._urgent_sent: dict[str, deque[float]] = {}

    def submit(self, target: str, lines: list[str], *, urgent: bool) -> bool:
        """Queue `lines` for `target`, all or nothing: False (nothing queued)
        when they would take the target's urgent queue past `max_urgent`
        lines, or the text past `max_backlog` (all targets) or the target's
        text past `max_text_messages`. Half a fragmented message is worse
        than none."""
        if not lines:
            return True
        key = fold(target)
        queued_urgent, _ = self._queues.get(key, ((), ()))
        cost = sum(self._cost(target, line) for line in lines)
        ends = sum(_ends_a_message(line) for line in lines)
        if urgent:
            if len(queued_urgent) + len(lines) > self.max_urgent:
                return False
        elif (self._text_cost + cost > self.max_backlog
              or self._text_messages.get(key, 0) + ends > self.max_text_messages):
            return False
        lane = self._queues.setdefault(key, (deque(), deque()))[0 if urgent else 1]
        lane.extend((next(self._seq), target, line) for line in lines)
        if not urgent:
            self._text_cost += cost
            self._text_messages[key] = self._text_messages.get(key, 0) + ends
        return True

    def pending(self) -> int:
        return sum(len(u) + len(t) for u, t in self._queues.values())

    def _slot(self, key: str, now: float) -> float:
        sent = self._sent.setdefault(key, deque())
        while sent and sent[0] <= now - self.window:
            sent.popleft()
        if len(sent) < self.max_lines:
            return now
        return sent[-self.max_lines] + self.window

    def _next(self, now: float):
        """(key, lane, target, line) of the line that goes next once the bank
        allows, or None while every target waits on its window; then the
        earliest time a window opens (or None)."""
        heads, opens = [], []
        for key, (urgent, text) in self._queues.items():
            slot = self._slot(key, now)
            if slot > now:
                opens.append(slot)
                continue
            lane, q = (0, urgent) if urgent else (1, text)
            seq, target, line = q[0]
            first = 0 if urgent and self._within_budget(key, now) else 1
            served = self._sent[key][-1] if self._sent[key] else float("-inf")
            heads.append((first, served, seq, key, lane, target, line))
        nxt = min(heads)[3:] if heads else None
        return nxt, min(opens) if opens else None

    def _within_budget(self, key: str, now: float) -> bool:
        sent = self._urgent_sent.get(key, ())
        while sent and sent[0] <= now - URGENT_BUDGET_WINDOW:
            sent.popleft()
        return len(sent) < URGENT_BUDGET

    def _cost(self, target: str, line: str) -> int:
        return FakeLag.cost(f"PRIVMSG {target} :{line}")

    def due(self, now: float) -> list[tuple[str, str]]:
        """Release what may go now, charging it to the bank. Once the bank
        has no room for the line whose turn it is, nothing else goes either:
        a cheaper line slipping past would keep the dear one waiting."""
        for key in [k for k, sent in self._sent.items()
                    if k not in self._queues and (not sent or sent[-1] <= now - self.window)]:
            del self._sent[key]          # a target gone quiet leaves nothing behind
        for key in [k for k, sent in self._urgent_sent.items()
                    if k not in self._queues and sent[-1] <= now - URGENT_BUDGET_WINDOW]:
            del self._urgent_sent[key]
        out = []
        while True:
            nxt, _ = self._next(now)
            if nxt is None:
                break
            key, lane, target, line = nxt
            cost = self._cost(target, line)
            if self.fakelag is not None and not self.fakelag.try_add(cost, now):
                break
            self._queues[key][lane].popleft()
            if lane:
                self._text_cost -= cost
                self._text_messages[key] -= _ends_a_message(line)
            else:
                self._urgent_sent.setdefault(key, deque()).append(now)
            self._sent[key].append(now)
            out.append((target, line))
            if not any(self._queues[key]):
                del self._queues[key]
                self._text_messages.pop(key, None)
        return out

    def next_wakeup(self, now: float) -> float | None:
        """When `due` may release something next, the same choice it makes:
        the bank's room for the line whose turn it is, or a window opening
        on another target. Never `now` with nothing due."""
        nxt, opens = self._next(now)
        times = [] if opens is None else [opens]
        if nxt is not None:
            _, _, target, line = nxt
            times.append(now if self.fakelag is None
                         else self.fakelag.room_at(self._cost(target, line), now))
        return min(times) if times else None


def _ends_a_message(line: str) -> bool:
    """A line that completes a message: its last fragment, or a line that is
    not a fragment at all."""
    frag = framing.parse(line)
    return frag is None or frag.index == frag.total


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
