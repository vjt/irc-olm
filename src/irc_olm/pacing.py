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
costs 5 or 6 s, so without the bank 3 lines per 6 s gets a long sender
killed: measured on a testnet bahamut at the 12th full line (grappa-irc
2430). A line is released only when the bank plus its cost stays at or under
10 s, so a line the pacer releases does not wait unparsed on the server as
long as the application charges what it writes itself; a long message then
takes minutes (vjt's ruling on grappa-irc 2430, option A).

Three lanes (Lane). URGENT is what we originate and cannot wait: a KEYREQ,
and the messages carrying a CHAL or an ACK (Result.urgent), which expire in
15 s. They go first, oldest first, so one message's lines stay together, and
nothing holds them back: no peer can make us originate more than a KEYREQ a
minute. REACTIVE is what a peer draws from us, KEYS and NACK: anyone holding
a pinned nick can draw them, so each target's go ahead of text only within a
budget of bank seconds per minute, taking turns by target; past it they wait
behind the text. TEXT takes turns by target, the target
served longest ago first, and keeps its order within a target: a short
message never overtakes a long one sent before it, which its reader would see
reversed. REACTIVE and TEXT lines never take the bank past a reserve kept for
URGENT ones, so a CHAL behind a stream of text leaves within seconds.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from enum import IntEnum
from itertools import count
from typing import Callable

from . import framing
from .framing import fold

DEFAULT_MAX_LINES = 3
DEFAULT_WINDOW = 6.0
# Queued text, all targets, in seconds of flood bank: 80 full lines. It must
# drain, and a NACK come back, while the engine still remembers what it sent
# (engine.SENT_MEMORY).
DEFAULT_MAX_BACKLOG = 480.0
# Text messages queued per target. An urgent message (a CHAL, an ACK) goes
# ahead of them, and the receiver's Olm skips one message key per message
# overtaken; vodozemac keeps 40 (tests/test_engine_sessions.py pins this).
DEFAULT_MAX_TEXT_MESSAGES = 32
# Lines queued per target in each of the URGENT and REACTIVE lanes: a KEYS,
# a NACK or a CHAL is a few lines.
DEFAULT_MAX_URGENT = 32

FAKE_LAG_CEILING = 10.0
# Seconds of bank REACTIVE and TEXT lines leave free for URGENT ones: they
# never take the bank past FAKE_LAG_CEILING - RESERVE, except a line dearer
# than that, which goes at an empty bank (a full line costs 6 s). Text loses
# no throughput (the bank drains a second a second either way), and a 2-line
# CHAL behind streaming text leaves within 7 s instead of 11.
RESERVE = 5.0
# Bank seconds per minute that one target's REACTIVE lines may take ahead of
# text: a KEYS (two lines, 8 s) and a NACK. Past it they wait behind the
# text, so n holders of pinned nicks flooding us leave it 60 - 10n s a minute.
REACTIVE_BUDGET = 10.0
REACTIVE_BUDGET_WINDOW = 60.0

# Verbs a peer draws from us: anyone holding a pinned nick can.
REACTIVE_VERBS = frozenset({"KEYS", "NACK"})

log = logging.getLogger(__name__)


class Lane(IntEnum):
    """Where a line waits, in the order lanes go: see the module docstring."""
    URGENT = 0
    REACTIVE = 1
    TEXT = 2


def lane_of(body: str, urgent: set[str]) -> Lane:
    """The lane for a CTCP body from an Engine Result: KEYS and NACK are
    REACTIVE whatever the engine says, the msgids in `urgent` (the KEYREQs,
    the messages carrying a CHAL or an ACK) URGENT, everything else TEXT."""
    frag = framing.parse(body)
    if frag is None:
        return Lane.TEXT
    if frag.verb in REACTIVE_VERBS:
        return Lane.REACTIVE
    return Lane.URGENT if frag.msgid in urgent else Lane.TEXT


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
            self._add(cost, now)

    def bank(self, now: float) -> float:
        with self._lock:
            return 0.0 if self._since is None else max(0.0, self._since - now)

    def try_add(self, cost: float, now: float, limit: float | None = None) -> bool:
        """Charge `cost` if the bank stays at or under `limit` (the ceiling
        when None); checked and charged in one step, the application
        charging from its thread."""
        with self._lock:
            if self._room(cost, now, limit) > now:
                return False
            self._add(cost, now)
            return True

    def room_at(self, cost: float, now: float, limit: float | None = None) -> float:
        """The earliest time, not before `now`, at which try_add accepts."""
        with self._lock:
            return self._room(cost, now, limit)

    def _room(self, cost: float, now: float, limit: float | None) -> float:
        # One expression for both try_add and room_at, so that they agree to
        # the last bit. A line dearer than the limit goes at an empty bank.
        if self._since is None:
            return now
        return max(now, self._since + cost - max(self.ceiling if limit is None else limit, cost))

    def _add(self, cost: float, now: float) -> None:
        self._since = now + cost if self._since is None else max(self._since, now) + cost


class Pacer:
    """At most `max_lines` lines to one target in any `window` seconds and,
    given a FakeLag, never past the connection's flood bank; the lanes and
    turns are the module docstring's.

    Pure scheduling, no threads and no clock of its own: the caller asks what
    is due at a given time. A target is its nick case-folded; each line keeps
    the spelling it came with. `fakelag=None` paces per target only, which is
    not enough on a real connection.
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
        # folded target -> its lanes, indexed by Lane: [(seq, target as given, line)]
        self._queues: dict[str, tuple[deque, deque, deque]] = {}
        self._text_cost = 0                   # flood bank the queued text will cost
        self._text_messages: dict[str, int] = {}
        self._sent: dict[str, deque[float]] = {}     # releases inside the window
        self._served: dict[str, float] = {}          # last release, for turns
        self._reactive: dict[str, deque[tuple[float, int]]] = {}  # (release, cost) in the budget window

    def submit(self, target: str, lines: list[str], *, lane: Lane) -> bool:
        """Queue `lines` for `target`, all or nothing: False (nothing queued)
        when they would take the target's URGENT or REACTIVE lane past
        `max_urgent` lines, or the text past `max_backlog` (all targets) or
        the target's text past `max_text_messages`. Half a fragmented message
        is worse than none."""
        if not lines:
            return True
        key = fold(target)
        queued = self._queues.get(key)
        if lane is Lane.TEXT:
            cost = sum(self._cost(target, line) for line in lines)
            ends = sum(_ends_a_message(line) for line in lines)
            if (self._text_cost + cost > self.max_backlog
                    or self._text_messages.get(key, 0) + ends > self.max_text_messages):
                return False
        elif (len(queued[lane]) if queued else 0) + len(lines) > self.max_urgent:
            return False
        q = self._queues.setdefault(key, (deque(), deque(), deque()))[lane]
        q.extend((next(self._seq), target, line) for line in lines)
        if lane is Lane.TEXT:
            self._text_cost += cost
            self._text_messages[key] = self._text_messages.get(key, 0) + ends
        return True

    def pending(self) -> int:
        return sum(len(q) for lanes in self._queues.values() for q in lanes)

    def _slot(self, key: str, now: float) -> float:
        sent = self._sent.setdefault(key, deque())
        while sent and sent[0] + self.window <= now:
            sent.popleft()
        if len(sent) < self.max_lines:
            return now
        return sent[-self.max_lines] + self.window

    def _spent(self, key: str, now: float) -> float:
        """Bank seconds the target's REACTIVE lines took in the last budget
        window."""
        spent = self._reactive.get(key, ())
        while spent and spent[0][0] + REACTIVE_BUDGET_WINDOW <= now:
            spent.popleft()
        return sum(cost for _, cost in spent)

    def _next(self, now: float):
        """(key, lane, target, line) of the line whose turn it is, or None
        while every target waits on its window; then the earliest time a
        window opens (or None)."""
        heads, opens = [], []
        for key, lanes in self._queues.items():
            slot = self._slot(key, now)
            if slot > now:
                opens.append(slot)
                continue
            served = self._served.get(key, float("-inf"))
            for lane in Lane:
                if not lanes[lane]:
                    continue
                seq, target, line = lanes[lane][0]
                if lane is Lane.URGENT:
                    rank = (0, 0.0, seq)           # oldest first: a message stays together
                elif lane is Lane.TEXT:
                    rank = (2, served, seq)
                else:
                    within = self._spent(key, now) + self._cost(target, line) <= REACTIVE_BUDGET
                    rank = (1 if within else 3, served, seq)
                heads.append((rank, key, lane, target, line))
        nxt = min(heads)[1:] if heads else None
        return nxt, min(opens) if opens else None

    def _cost(self, target: str, line: str) -> int:
        return FakeLag.cost(f"PRIVMSG {target} :{line}")

    def _limit(self, lane: Lane) -> float:
        return self.fakelag.ceiling - (0.0 if lane is Lane.URGENT else RESERVE)

    def due(self, now: float) -> list[tuple[str, str]]:
        """Release what may go now, charging it to the bank. Once the bank
        has no room for the line whose turn it is, nothing else goes either:
        a cheaper line slipping past would keep the dear one waiting."""
        self._forget_idle(now)
        out = []
        while True:
            nxt, _ = self._next(now)
            if nxt is None:
                break
            key, lane, target, line = nxt
            cost = self._cost(target, line)
            if self.fakelag is not None and not self.fakelag.try_add(cost, now, self._limit(lane)):
                break
            lanes = self._queues[key]
            lanes[lane].popleft()
            if lane is Lane.TEXT:
                self._text_cost -= cost
                self._text_messages[key] -= _ends_a_message(line)
            elif lane is Lane.REACTIVE:
                self._reactive.setdefault(key, deque()).append((now, cost))
            self._sent[key].append(now)
            self._served[key] = now
            out.append((target, line))
            if not any(lanes):
                del self._queues[key]
                self._text_messages.pop(key, None)
        return out

    def _forget_idle(self, now: float) -> None:
        """A target gone quiet leaves nothing behind: its window once it has
        passed, its turn once every queued target was served after it (it
        would come last anyway)."""
        for key in [k for k, sent in self._sent.items()
                    if k not in self._queues and (not sent or sent[-1] + self.window <= now)]:
            del self._sent[key]
        for key in [k for k in self._reactive if k not in self._queues and not self._spent(k, now)]:
            del self._reactive[key]
        oldest = min((self._served.get(k, float("-inf")) for k in self._queues),
                     default=float("inf"))
        for key in [k for k, t in self._served.items() if k not in self._queues and t <= oldest]:
            del self._served[key]

    def next_wakeup(self, now: float) -> float | None:
        """When `due` may release something next: the bank's room for the
        line whose turn it is, a window opening on another target, or the
        REACTIVE budget recovering (their lines then go ahead of text).
        Never `now` with nothing due."""
        nxt, opens = self._next(now)
        times = [] if opens is None else [opens]
        if nxt is not None:
            _, lane, target, line = nxt
            times.append(now if self.fakelag is None
                         else self.fakelag.room_at(self._cost(target, line), now, self._limit(lane)))
        for key, lanes in self._queues.items():
            if lanes[Lane.REACTIVE]:
                _, target, line = lanes[Lane.REACTIVE][0]
                recovers = self._budget_recovers(key, self._cost(target, line), now)
                if recovers > now:
                    times.append(recovers)
        return min(times) if times else None

    def _budget_recovers(self, key: str, cost: int, now: float) -> float:
        """The instant a REACTIVE line of `cost` to `key` fits the budget
        again: `now` if it does, else when the release it waits on ages out."""
        left = self._spent(key, now)
        for t, spent in self._reactive.get(key, ()):
            if left + cost <= REACTIVE_BUDGET:
                break
            left -= spent
            now = t + REACTIVE_BUDGET_WINDOW
        return now


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

    def submit(self, target: str, lines: list[str], *, lane: Lane) -> bool:
        with self._cv:
            ok = self._pacer.submit(target, lines, lane=lane)
            self._cv.notify()
        if not ok:
            log.warning("pacer: %d %s lines to %s refused, queue full", len(lines),
                        lane.name, target)
        return ok

    def submit_all(self, outbound: list[tuple[str, str]],
                   urgent: set[str]) -> list[tuple[str, str | None]]:
        """Submit an Engine Result: `submit_all(result.outbound, result.urgent)`.
        Each message (a msgid's fragments) is queued or refused whole, in
        order within its target and lane. Returns (target, msgid) for each
        message refused, logged; pass the msgids to Engine.discard and report
        them. A body that is not E2E counts as a message of its own, msgid None."""
        messages: dict[tuple[str, str | int], tuple[str | None, list[str]]] = {}
        for i, (target, body) in enumerate(outbound):
            frag = framing.parse(body)
            msgid = frag.msgid if frag is not None else None
            messages.setdefault((target, msgid if msgid is not None else i), (msgid, []))[1].append(body)
        return [(target, msgid) for (target, _), (msgid, lines) in messages.items()
                if not self.submit(target, lines, lane=lane_of(lines[0], urgent))]

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
