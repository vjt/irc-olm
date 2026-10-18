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

Three lanes (Lane), scheduled by MESSAGE: once a message's first line has
left, its other lines go before anything else of its rank. URGENT is what we
originate and cannot wait: a KEYREQ, and the messages carrying a CHAL or an
ACK (Result.urgent). They go first, within a budget per target, because a
peer can draw them too: the bot challenges every line a pinned human
addresses to it, and a chatty human draws CHALs faster than the bank drains.
A CHAL carries its deadline and is dropped unsent past it. REACTIVE is what
a peer draws from us, KEYS and NACK: ahead of text within a smaller budget
per target and one for the connection. Past its budget an urgent or reactive
message waits behind the text. TEXT has no budget. Turns go to the target
served longest ago, in every lane, so one target's messages do not hold
another's back; within a target each lane keeps its order, and a short
message never overtakes a long one sent before it, which its reader would
see reversed. REACTIVE and TEXT lines never take the bank past a reserve kept
for URGENT ones, so a CHAL behind a stream of text leaves within seconds.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from enum import IntEnum
from itertools import count
from typing import Callable, Mapping, NamedTuple

from . import framing
from .framing import fold

DEFAULT_MAX_LINES = 3
DEFAULT_WINDOW = 6.0
# Queued text, all targets, in seconds of flood bank: 80 full lines. It must
# drain, and a NACK come back, while the engine still remembers what it sent
# (engine.SENT_MEMORY).
DEFAULT_MAX_BACKLOG = 480.0
# Text messages queued per target, plus the Olm messages refused or dropped
# behind them. An urgent message (a CHAL, an ACK) goes ahead of the queue, and
# the receiver's Olm skips one message key for each message it overtakes, and
# for each refused one too (it was encrypted): vodozemac keeps 40
# (tests/test_engine_sessions.py pins this). Ask room() before encrypting.
DEFAULT_MAX_TEXT_MESSAGES = 32
# Lines queued per target in each of the URGENT and REACTIVE lanes.
DEFAULT_MAX_URGENT = 32

FAKE_LAG_CEILING = 10.0
# Seconds of bank REACTIVE and TEXT lines leave free for URGENT ones: they
# never take the bank past FAKE_LAG_CEILING - RESERVE, except a line dearer
# than that, which goes at an empty bank (a full line costs 6 s). Text loses
# no throughput (the bank drains a second a second either way), and a 2-line
# CHAL behind streaming text leaves within 7 s instead of 11.
RESERVE = 5.0
# Bank seconds per target per minute that may go ahead of text, decided when
# a message's first line is due (it must fit): a message that starts inside
# the budget finishes. URGENT: four orders a minute (CHALs of 5 + 4 s), or a
# first contact and three. REACTIVE: four NACKs and a KEYS (the recovery
# after a lost session), or two KEYS (an answer and a retry's).
URGENT_BUDGET = 40.0
REACTIVE_BUDGET = 14.0
# And REACTIVE lines of all targets together, so that any number of holders of
# pinned nicks flooding us leave text a third of the bank (measured up to
# ten): past it, only a target that drew nothing in the last minute goes ahead.
REACTIVE_BUDGET_TOTAL = 30.0
BUDGET_WINDOW = 60.0

# Verbs a peer draws from us: anyone holding a pinned nick can.
REACTIVE_VERBS = frozenset({"KEYS", "NACK"})
# Verbs whose messages are Olm-encrypted: the ones a refusal leaves a gap for.
OLM_VERBS = frozenset({"PKMSG", "MSG"})

log = logging.getLogger(__name__)


class Lane(IntEnum):
    """Where a line waits, in the order lanes go: see the module docstring."""
    URGENT = 0
    REACTIVE = 1
    TEXT = 2


def lane_of(body: str, urgent: Mapping[str, float | None]) -> Lane:
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


class _Line(NamedTuple):
    seq: int
    target: str                # as given: each line keeps its spelling
    line: str
    msgid: str | None          # None: a bare line, a message of its own
    ends: bool                 # the message's last line
    deadline: float | None     # unsent past it, the message is dropped
    olm: bool                  # an Olm-encrypted message (MSG, PKMSG)


class Pacer:
    """At most `max_lines` lines to one target in any `window` seconds and,
    given a FakeLag, never past the connection's flood bank; the lanes,
    budgets and turns are the module docstring's.

    Pure scheduling, no threads and no clock of its own: the caller asks what
    is due at a given time. A target is its nick case-folded. `fakelag=None`
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
        self._queues: dict[str, tuple[deque, deque, deque]] = {}   # folded target -> lanes
        self._text_cost = 0                   # flood bank the queued text will cost
        self._text_messages: dict[str, int] = {}
        self._gap: dict[str, int] = {}        # Olm messages refused behind queued text
        self._sent: dict[str, deque[float]] = {}     # releases inside the window
        self._served: dict[str, float] = {}          # last release, for turns
        self._spent: dict[tuple[str, Lane], deque[tuple[float, int]]] = {}  # budget window
        self._open: dict[tuple[str, Lane], str] = {}  # a message part sent

    def submit(self, target: str, lines: list[str], *, lane: Lane,
               deadline: float | None = None) -> bool:
        """Queue `lines` for `target`, all or nothing: False (nothing queued)
        when they would take the target's URGENT or REACTIVE lane past
        `max_urgent` lines, or the text past `max_backlog` (all targets) or
        the target's text past `max_text_messages`. Half a fragmented message
        is worse than none. An URGENT message not started by `deadline` is
        dropped."""
        if not lines:
            return True
        key = fold(target)
        queued = self._queues.get(key)
        entries = [self._entry(target, line, deadline if lane is Lane.URGENT else None)
                   for line in lines]
        ends = sum(e.ends for e in entries)
        if lane is Lane.TEXT:
            cost = sum(self._cost(e) for e in entries)
            ok = (self._text_cost + cost <= self.max_backlog
                  and self._text_messages.get(key, 0) + self._gap.get(key, 0) + ends
                  <= self.max_text_messages)
        else:
            ok = (len(queued[lane]) if queued else 0) + len(lines) <= self.max_urgent
        if not ok:
            self._left_a_gap(key, sum(e.olm and e.ends for e in entries))
            return False
        q = self._queues.setdefault(key, (deque(), deque(), deque()))[lane]
        q.extend(entries)
        if lane is Lane.TEXT:
            self._text_cost += cost
            self._text_messages[key] = self._text_messages.get(key, 0) + ends
        return True

    def room(self, target: str) -> bool:
        """Whether a text message to `target` may be queued, the messages
        refused behind its queue counted: ask before encrypting one, since a
        refused message was encrypted all the same."""
        key = fold(target)
        return (self._text_cost < self.max_backlog
                and self._text_messages.get(key, 0) + self._gap.get(key, 0)
                < self.max_text_messages)

    def pending(self) -> int:
        return sum(len(q) for lanes in self._queues.values() for q in lanes)

    def _entry(self, target: str, line: str, deadline: float | None) -> _Line:
        frag = framing.parse(line)
        return _Line(next(self._seq), target, line, None if frag is None else frag.msgid,
                     frag is None or frag.index == frag.total, deadline,
                     frag is not None and frag.verb in OLM_VERBS)

    def _left_a_gap(self, key: str, messages: int) -> None:
        # The receiver skips the key of an Olm message it never gets when the
        # next one arrives; it only matters behind queued text, which an
        # urgent message may still overtake.
        queued = self._queues.get(key)
        if messages and queued and queued[Lane.TEXT]:
            self._gap[key] = self._gap.get(key, 0) + messages

    def _slot(self, key: str, now: float) -> float:
        sent = self._sent.setdefault(key, deque())
        while sent and sent[0] + self.window <= now:
            sent.popleft()
        if len(sent) < self.max_lines:
            return now
        return sent[-self.max_lines] + self.window

    def _spent_in(self, key: str, lane: Lane, now: float) -> float:
        """Bank seconds the target's lines of `lane` took in the last budget
        window."""
        spent = self._spent.get((key, lane), ())
        while spent and spent[0][0] + BUDGET_WINDOW <= now:
            spent.popleft()
        return sum(cost for _, cost in spent)

    def _rank(self, key: str, lane: Lane, head: _Line, served: float, now: float):
        if lane is Lane.TEXT:
            return (2, 1, served, head.seq)
        first = 0 if lane is Lane.URGENT else 1
        if head.msgid is not None and self._open.get((key, lane)) == head.msgid:
            return (first, 0, served, head.seq)    # a started message finishes
        budget = URGENT_BUDGET if lane is Lane.URGENT else REACTIVE_BUDGET
        spent = self._spent_in(key, lane, now)
        within = spent + self._cost(head) <= budget
        if within and lane is Lane.REACTIVE and spent:
            # Past the connection's budget only a target that drew nothing in
            # the last minute goes ahead: an honest peer, not a flooder.
            within = self._spent_in("", lane, now) < REACTIVE_BUDGET_TOTAL
        return (first if within else 3, 1, served, head.seq)

    def _next(self, now: float):
        """(key, lane, entry) of the line whose turn it is, or None while
        every target waits on its window; then the earliest time a window
        opens (or None)."""
        heads, opens = [], []
        for key, lanes in self._queues.items():
            slot = self._slot(key, now)
            if slot > now:
                opens.append(slot)
                continue
            served = self._served.get(key, float("-inf"))
            for lane in Lane:
                if lanes[lane]:
                    head = lanes[lane][0]
                    heads.append((self._rank(key, lane, head, served, now), key, lane, head))
        nxt = min(heads, key=lambda h: h[0])[1:] if heads else None
        return nxt, min(opens) if opens else None

    def _cost(self, entry: _Line) -> int:
        return FakeLag.cost(f"PRIVMSG {entry.target} :{entry.line}")

    def _limit(self, lane: Lane) -> float:
        return self.fakelag.ceiling - (0.0 if lane is Lane.URGENT else RESERVE)

    def due(self, now: float) -> list[tuple[str, str]]:
        """Release what may go now, charging it to the bank. Once the bank
        has no room for the line whose turn it is, nothing else goes either:
        a cheaper line slipping past would keep the dear one waiting."""
        self._drop_dead(now)
        self._forget_idle(now)
        out = []
        while True:
            nxt, _ = self._next(now)
            if nxt is None:
                break
            key, lane, head = nxt
            cost = self._cost(head)
            if self.fakelag is not None and not self.fakelag.try_add(cost, now, self._limit(lane)):
                break
            lanes = self._queues[key]
            lanes[lane].popleft()
            if lane is Lane.TEXT:
                self._text_cost -= cost
                self._text_messages[key] -= head.ends
                if not lanes[Lane.TEXT]:
                    self._gap.pop(key, None)       # nothing left to overtake
            else:
                self._spent.setdefault((key, lane), deque()).append((now, cost))
                if lane is Lane.REACTIVE:
                    self._spent.setdefault(("", lane), deque()).append((now, cost))
                if head.ends:
                    self._open.pop((key, lane), None)
                else:
                    self._open[(key, lane)] = head.msgid
            self._sent[key].append(now)
            self._served[key] = now
            out.append((head.target, head.line))
            if not any(lanes):
                del self._queues[key]
                self._text_messages.pop(key, None)
        return out

    def _drop_dead(self, now: float) -> None:
        """Drop the URGENT messages whose deadline passed before their first
        line left (a CHAL nobody can answer any more)."""
        for key in list(self._queues):
            lanes = self._queues[key]
            urgent = lanes[Lane.URGENT]
            started = self._open.get((key, Lane.URGENT))
            dead = [e for e in urgent if e.deadline is not None and e.deadline <= now
                    and (e.msgid is None or e.msgid != started)]
            if not dead:
                continue
            gone = {e.seq if e.msgid is None else e.msgid for e in dead}
            keep = [e for e in urgent if (e.seq if e.msgid is None else e.msgid) not in gone]
            urgent.clear()
            urgent.extend(keep)
            log.warning("pacer: %d urgent messages to %s dropped unsent, past their deadline",
                        len(gone), dead[0].target)
            self._left_a_gap(key, sum(e.olm and e.ends for e in dead))
            if not any(lanes):
                del self._queues[key]
                self._text_messages.pop(key, None)

    def _forget_idle(self, now: float) -> None:
        """A target gone quiet leaves nothing behind: its window once it has
        passed, its budgets once spent, its turn once it is older than every
        queued target's that has one. Coming back without it, it goes first,
        as a target never served does; with it, it went first too."""
        for key in [k for k, sent in self._sent.items()
                    if k not in self._queues and (not sent or sent[-1] + self.window <= now)]:
            del self._sent[key]
        for kl in [kl for kl in self._spent
                   if kl[0] not in self._queues and not self._spent_in(*kl, now)]:
            del self._spent[kl]
        oldest = min((self._served[k] for k in self._queues if k in self._served),
                     default=float("inf"))
        for key in [k for k, t in self._served.items() if k not in self._queues and t <= oldest]:
            del self._served[key]

    def next_wakeup(self, now: float) -> float | None:
        """When `due` may release something next: the bank's room for the
        line whose turn it is, a window opening on another target, a budget
        recovering, or a dead urgent message making way for the next. Never
        `now` with nothing due."""
        nxt, opens = self._next(now)
        times = [] if opens is None else [opens]
        if nxt is not None:
            _, lane, head = nxt
            times.append(now if self.fakelag is None
                         else self.fakelag.room_at(self._cost(head), now, self._limit(lane)))
        for key, lanes in self._queues.items():
            for lane in (Lane.URGENT, Lane.REACTIVE):
                if lanes[lane]:
                    head = lanes[lane][0]
                    if head.msgid is None or self._open.get((key, lane)) != head.msgid:
                        times += self._budget_recovers(key, lane, self._cost(head), now)
            # A started message keeps its lines past the deadline.
            times += [e.deadline for e in lanes[Lane.URGENT]
                      if e.deadline is not None and e.deadline > now]
        return min(times) if times else None

    def _budget_recovers(self, key: str, lane: Lane, cost: int, now: float) -> list[float]:
        """The instants after `now` at which a line of `cost` to `key` may
        come within budget: the target's budget fitting it, the connection's
        dropping under its total (REACTIVE), the target's emptying (which
        lifts the connection's). Waking at one where nothing changes costs
        nothing; missing one makes a line late."""
        budget = URGENT_BUDGET if lane is Lane.URGENT else REACTIVE_BUDGET
        times = [self._ages_out((key, lane), now, lambda left: left + cost <= budget)]
        if lane is Lane.REACTIVE:
            times.append(self._ages_out(("", lane), now, lambda left: left < REACTIVE_BUDGET_TOTAL))
            times.append(self._ages_out((key, lane), now, lambda left: not left))
        return [t for t in times if t > now]

    def _ages_out(self, kl: tuple[str, Lane], now: float, ok: Callable[[float], bool]) -> float:
        """When enough of the releases in a budget window age out for `ok`
        to hold of what is left: `now` if it holds already."""
        left = self._spent_in(*kl, now)
        for t, spent in self._spent.get(kl, ()):
            if ok(left):
                break
            left -= spent
            now = t + BUDGET_WINDOW
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

    def submit(self, target: str, lines: list[str], *, lane: Lane,
               deadline: float | None = None) -> bool:
        with self._cv:
            ok = self._pacer.submit(target, lines, lane=lane, deadline=deadline)
            self._cv.notify()
        if not ok:
            log.warning("pacer: %d %s lines to %s refused, queue full", len(lines),
                        lane.name, target)
        return ok

    def room(self, target: str) -> bool:
        """Pacer.room: ask before encrypting a text message for `target`."""
        with self._cv:
            return self._pacer.room(target)

    def submit_all(self, outbound: list[tuple[str, str]],
                   urgent: Mapping[str, float | None]) -> list[tuple[str, str]]:
        """Submit an Engine Result: `submit_all(result.outbound, result.urgent)`.
        Each message (a msgid's fragments) is queued or refused whole, in
        order within its target and lane; a CHAL gets the deadline its
        seconds in `urgent` name. Every refusal is logged; returns (target,
        msgid) for the refused messages that carried text (MSG, PKMSG): pass
        the msgids to Engine.discard. A refused KEYREQ, KEYS or NACK is no
        message anyone wrote: the protocol recovers from it, or the engine
        reports what it costs (a keys-timeout). A body that is not E2E counts
        as a message of its own."""
        now = self._clock()
        messages: dict[tuple[str, str | int], tuple[str | None, list[str]]] = {}
        for i, (target, body) in enumerate(outbound):
            frag = framing.parse(body)
            msgid = frag.msgid if frag is not None else None
            messages.setdefault((target, msgid if msgid is not None else i), (msgid, []))[1].append(body)
        refused = []
        for (target, _), (msgid, lines) in messages.items():
            ttl = urgent.get(msgid) if msgid is not None else None
            if (not self.submit(target, lines, lane=lane_of(lines[0], urgent),
                                deadline=None if ttl is None else now + ttl)
                    and framing.parse(lines[0]).verb in OLM_VERBS):
                refused.append((target, msgid))
        return refused

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
