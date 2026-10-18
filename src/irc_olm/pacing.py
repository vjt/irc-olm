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
left, its other lines go before anything else of its rank, and one text
message is under way at a time. URGENT is what we originate and cannot wait:
a KEYREQ, and the messages carrying a CHAL or an ACK (Result.urgent).
REACTIVE is what a peer draws from us, KEYS and NACK. Both go ahead of text
within budgets, per target and for the connection, because peers draw both:
the bot challenges every line a pinned human addresses to it. Past its
budget a message waits behind the text, except that a target which drew
nothing from that lane in the last minute may still go ahead, from a small
allowance: an honest peer, or a second human, behind a flooder or a chatty
one. A CHAL carries its deadline, and starts only if it can still be
answered. TEXT has no budget, and a floor instead: text queued and no text
line for TEXT_FLOOR seconds, the text goes next, so a message under way
reaches its receiver (who drops a partial message 60 s after its last
fragment) whatever goes ahead of it. Turns go to the target served longest
ago, in every lane; within a target each lane keeps its order, so a short
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
# What a full line costs (512 bytes): room() keeps one free in the backlog.
FULL_LINE_COST = 6

FAKE_LAG_CEILING = 10.0
# Seconds of bank REACTIVE and TEXT lines leave free for URGENT ones: they
# never take the bank past FAKE_LAG_CEILING - RESERVE, except a line dearer
# than that, which goes at an empty bank (a full line costs 6 s). Text loses
# no throughput (the bank drains a second a second either way), and a 2-line
# CHAL behind streaming text leaves within 7 s instead of 11.
RESERVE = 5.0
# Bank seconds that may go ahead of text in BUDGET_WINDOW, decided when a
# message's first line is due (it must fit): a message that starts finishes.
# URGENT, the connection's, whoever gives the orders: four orders (CHALs of
# 5 + 4 s), or a first contact (KEYREQ, pre-key CHAL) and two; one human may
# take it all. REACTIVE, per target: five NACKs and a KEYS (the recovery
# after a lost session), or two KEYS (an answer and a retry's); and for the
# connection, two KEYS and a few NACKs.
URGENT_BUDGET = 36.0
REACTIVE_BUDGET = 16.0
REACTIVE_BUDGET_TOTAL = 22.0
# A target that drew nothing else from a lane in the window (nothing spent,
# one message queued) may take the connection past its budget by this much,
# one message more for all such targets together: an honest peer behind
# flooders, a second human behind a chatty one. A flooder held back by the
# budget always has more queued.
FRESH_ALLOWANCE = 9.0
BUDGET_WINDOW = 60.0
# Text queued and no text line released for this long: the text goes next,
# ahead of every message not yet started. A message under way then gets a
# line every TEXT_FLOOR, plus the bank's and the window's wait (10 + 6 s),
# well inside the 60 s its receiver keeps it.
TEXT_FLOOR = 30.0
# A CHAL starts only if its last line can leave this long before its
# deadline at the bank as it stands: the ACK's way back (the peer's decrypt,
# its pacer, two hops). The deadline is when the ACK must be here.
ACK_MARGIN = 2.0

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
    deadline: float | None     # past it no answer can come back: dropped unstarted
    olm: bool                  # an Olm-encrypted message (MSG, PKMSG)
    cost: int                  # flood bank, computed at submit: bad input fails there


# (per target, the connection's) for each budgeted lane.
_BUDGETS = {Lane.URGENT: (URGENT_BUDGET, URGENT_BUDGET),
            Lane.REACTIVE: (REACTIVE_BUDGET, REACTIVE_BUDGET_TOTAL)}

# Ranks, the lowest goes first; then turns (the target served longest ago),
# then the order of submission.
(_STARTED_URGENT, _STARVED_STARTED_TEXT, _URGENT, _STARTED_REACTIVE, _STARVED_TEXT,
 _REACTIVE, _TEXT, _PAST_BUDGET) = range(8)


class Pacer:
    """At most `max_lines` lines to one target in any `window` seconds and,
    given a FakeLag, never past the connection's flood bank; the lanes,
    budgets, floor and turns are the module docstring's.

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
        # Budget windows: (target, lane), and ("", lane) for the connection.
        self._spent: dict[tuple[str, Lane], deque[tuple[float, int]]] = {}
        self._open: dict[tuple[str, Lane], str] = {}  # a message part sent
        self._text_at: float | None = None    # the floor's clock: the last text line
        self._dropped: list[tuple[str, str | None]] = []

    def submit(self, target: str, lines: list[str], *, lane: Lane,
               deadline: float | None = None) -> bool:
        """Queue `lines`, whole messages one after another, for `target`, all
        or nothing: False (nothing queued) when they would take the target's
        URGENT or REACTIVE lane past `max_urgent` lines, or the text past
        `max_backlog` (all targets) or the target's text past
        `max_text_messages`. Half a fragmented message is worse than none:
        ValueError when the last line does not end a message. An URGENT
        message is dropped unstarted once it cannot leave ACK_MARGIN before
        `deadline` (take_dropped)."""
        if not lines:
            return True
        key = fold(target)
        queued = self._queues.get(key)
        entries = [self._entry(target, line, deadline if lane is Lane.URGENT else None)
                   for line in lines]
        if not entries[-1].ends:
            raise ValueError(f"submit whole messages: {lines[-1][:40]!r} does not end one")
        ends = sum(e.ends for e in entries)
        if lane is Lane.TEXT:
            cost = sum(e.cost for e in entries)
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
            if not self._text_cost:
                self._text_at = None          # the floor's clock starts at the next due()
            self._text_cost += cost
            self._text_messages[key] = self._text_messages.get(key, 0) + ends
        return True

    def room(self, target: str) -> bool:
        """Whether a one-line text message to `target` may still be queued,
        the messages refused behind its queue counted: ask before encrypting
        one, since a refused message was encrypted all the same. A longer
        message can still be refused, and submit_all says so."""
        key = fold(target)
        return (self._text_cost + FULL_LINE_COST <= self.max_backlog
                and self._text_messages.get(key, 0) + self._gap.get(key, 0)
                < self.max_text_messages)

    def pending(self) -> int:
        return sum(len(q) for lanes in self._queues.values() for q in lanes)

    def take_dropped(self) -> list[tuple[str, str | None]]:
        """(target, msgid) of the URGENT messages dropped unstarted since the
        last call, too late to be answered: hand the msgids to
        Engine.discard. PacedSender drains this; a caller of due() must."""
        out, self._dropped = self._dropped, []
        return out

    def drop(self, target: str, msgid: str) -> None:
        """Drop what is left of message `msgid` to `target`: one of its lines
        failed to go out, so its receiver can never complete it."""
        key = fold(target)
        for lane in Lane:
            if self._open.get((key, lane)) == msgid:
                del self._open[(key, lane)]
        lanes = self._queues.get(key)
        if lanes is None:
            return
        gone = [e for q in lanes for e in q if e.msgid == msgid]
        for lane, q in zip(Lane, lanes):
            keep = [e for e in q if e.msgid != msgid]
            if lane is Lane.TEXT:
                self._text_cost -= sum(e.cost for e in q if e.msgid == msgid)
                self._text_messages[key] -= sum(e.ends for e in q if e.msgid == msgid)
            q.clear()
            q.extend(keep)
        self._left_a_gap(key, int(any(e.olm for e in gone)))
        self._tidy(key)

    def _entry(self, target: str, line: str, deadline: float | None) -> _Line:
        frag = framing.parse(line)
        return _Line(next(self._seq), target, line, None if frag is None else frag.msgid,
                     frag is None or frag.index == frag.total, deadline,
                     frag is not None and frag.verb in OLM_VERBS,
                     FakeLag.cost(f"PRIVMSG {target} :{line}"))

    def _left_a_gap(self, key: str, messages: int) -> None:
        # The receiver skips the key of an Olm message it never gets when the
        # next one arrives; it only matters behind queued text, which an
        # urgent message may still overtake.
        queued = self._queues.get(key)
        if messages and queued and queued[Lane.TEXT]:
            self._gap[key] = self._gap.get(key, 0) + messages

    def _tidy(self, key: str) -> None:
        """After lines left a target's queue: no gap without text to
        overtake, and nothing kept for a target with nothing queued."""
        lanes = self._queues[key]
        if not lanes[Lane.TEXT]:
            self._gap.pop(key, None)
        if not any(lanes):
            del self._queues[key]
            self._text_messages.pop(key, None)

    def _slot(self, key: str, now: float) -> float:
        sent = self._sent.setdefault(key, deque())
        while sent and sent[0] + self.window <= now:
            sent.popleft()
        if len(sent) < self.max_lines:
            return now
        return sent[-self.max_lines] + self.window

    def _spent_in(self, key: str, lane: Lane, now: float) -> float:
        """Bank seconds the target's lines of `lane` (the connection's, for
        key "") took in the last budget window."""
        spent = self._spent.get((key, lane), ())
        while spent and spent[0][0] + BUDGET_WINDOW <= now:
            spent.popleft()
        return sum(cost for _, cost in spent)

    def _within(self, key: str, lane: Lane, cost: int, now: float) -> bool:
        """Whether the head message of a lane, its first line costing `cost`,
        may start ahead of text: within the target's budget and the
        connection's, the latter stretched for a target that drew nothing
        else (FRESH_ALLOWANCE)."""
        per_target, total = _BUDGETS[lane]
        spent = self._spent_in(key, lane, now)
        q = self._queues[key][lane]
        if not spent and (q[0].seq == q[-1].seq or q[0].msgid is not None
                          and q[0].msgid == q[-1].msgid):
            total += FRESH_ALLOWANCE
        return spent + cost <= per_target and self._spent_in("", lane, now) + cost <= total

    def _starved(self, now: float) -> bool:
        # The wakeup's expression, so that the two agree to the last bit.
        return bool(self._text_cost) and self._text_at is not None \
            and now >= self._text_at + TEXT_FLOOR

    def _rank(self, key: str, lane: Lane, head: _Line, starved: bool, now: float):
        started = head.msgid is not None and self._open.get((key, lane)) == head.msgid
        if lane is Lane.TEXT:
            # Starved, a message under way goes before any order: its
            # receiver would drop it. One not started yields to the orders.
            rank = (_STARVED_STARTED_TEXT if started else _STARVED_TEXT) if starved else _TEXT
        elif started:
            rank = _STARTED_URGENT if lane is Lane.URGENT else _STARTED_REACTIVE
        elif self._within(key, lane, head.cost, now):
            rank = _URGENT if lane is Lane.URGENT else _REACTIVE
        else:
            rank = _PAST_BUDGET
        return (rank, self._served.get(key, float("-inf")), head.seq)

    def _next(self, now: float):
        """(key, lane, entry) of the line whose turn it is, or None while
        every target waits on its window; then the earliest time a window
        opens (or None). While a text message is under way, no other starts."""
        heads, opens = [], []
        writing = next((k for k, lane in self._open if lane is Lane.TEXT), None)
        starved = self._starved(now)
        for key, lanes in self._queues.items():
            slot = self._slot(key, now)
            if slot > now:
                opens.append(slot)
                continue
            for lane in Lane:
                if lanes[lane] and not (lane is Lane.TEXT and writing not in (None, key)):
                    head = lanes[lane][0]
                    heads.append((self._rank(key, lane, head, starved, now), key, lane, head))
        nxt = min(heads, key=lambda h: h[0])[1:] if heads else None
        return nxt, min(opens) if opens else None

    def _limit(self, lane: Lane) -> float:
        return self.fakelag.ceiling - (0.0 if lane is Lane.URGENT else RESERVE)

    def due(self, now: float) -> list[tuple[str, str]]:
        """Release what may go now, charging it to the bank. Once the bank
        has no room for the line whose turn it is, nothing else goes either:
        a cheaper line slipping past would keep the dear one waiting."""
        self._forget_idle(now)
        if self._text_at is None and self._text_cost:
            self._text_at = now
        out = []
        while True:
            self._drop_dead(now)
            nxt, _ = self._next(now)
            if nxt is None:
                break
            key, lane, head = nxt
            if self.fakelag is not None and not self.fakelag.try_add(head.cost, now,
                                                                     self._limit(lane)):
                break
            self._queues[key][lane].popleft()
            if lane is Lane.TEXT:
                self._text_cost -= head.cost
                self._text_messages[key] -= head.ends
                self._text_at = now
            else:
                for k in (key, ""):
                    self._spent.setdefault((k, lane), deque()).append((now, head.cost))
            if head.ends:
                self._open.pop((key, lane), None)
            else:
                self._open[(key, lane)] = head.msgid
            self._sent[key].append(now)
            self._served[key] = now
            out.append((head.target, head.line))
            self._tidy(key)
        return out

    @staticmethod
    def _messages(q: deque) -> dict:
        """{message: (cost, deadline, first line)} of a lane, in its order; a
        bare line is a message of its own, keyed by its seq."""
        out: dict = {}
        for e in q:
            k = e.seq if e.msgid is None else e.msgid
            cost, _, first = out.get(k, (0, None, e))
            out[k] = (cost + e.cost, e.deadline, first)
        return out

    def _drop_at(self, cost: int, deadline: float, now: float) -> float:
        """When an URGENT message of `cost` not yet started stops being worth
        starting: its last line would leave less than ACK_MARGIN before
        `deadline`. `now` once the bank already says so. One expression for
        due() and next_wakeup(), so that they agree to the last bit."""
        if self.fakelag is None:
            return deadline - ACK_MARGIN
        over = cost - self.fakelag.ceiling
        if now + self.fakelag.bank(now) + over >= deadline - ACK_MARGIN:
            return now
        return deadline - ACK_MARGIN - max(0.0, over)

    def _unstarted_deadlines(self, key: str, lanes) -> list[tuple[str | int, int, float, _Line]]:
        started = self._open.get((key, Lane.URGENT))
        return [(k, cost, deadline, first)
                for k, (cost, deadline, first) in self._messages(lanes[Lane.URGENT]).items()
                if deadline is not None and k != started]

    def _drop_dead(self, now: float) -> None:
        """Drop the URGENT messages not started that can no longer be
        answered in time (a CHAL whose ACK could not make its deadline)."""
        for key in list(self._queues):
            lanes = self._queues[key]
            gone = {k: first for k, cost, deadline, first in self._unstarted_deadlines(key, lanes)
                    if now >= self._drop_at(cost, deadline, now)}
            if not gone:
                continue
            keep = [e for e in lanes[Lane.URGENT]
                    if (e.seq if e.msgid is None else e.msgid) not in gone]
            lanes[Lane.URGENT].clear()
            lanes[Lane.URGENT].extend(keep)
            log.warning("pacer: %d urgent messages to %s dropped unsent, too late to be answered",
                        len(gone), next(iter(gone.values())).target)
            self._dropped += [(first.target, first.msgid) for first in gone.values()]
            self._left_a_gap(key, sum(first.olm for first in gone.values()))
            self._tidy(key)

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
        recovering, an urgent message going too late to start and making way,
        or the text floor. Never `now` with nothing due."""
        nxt, opens = self._next(now)
        times = [] if opens is None else [opens]
        if nxt is not None:
            _, lane, head = nxt
            times.append(now if self.fakelag is None
                         else self.fakelag.room_at(head.cost, now, self._limit(lane)))
        later = []
        for key, lanes in self._queues.items():
            for lane in (Lane.URGENT, Lane.REACTIVE):
                if lanes[lane]:
                    head = lanes[lane][0]
                    if head.msgid is None or self._open.get((key, lane)) != head.msgid:
                        later += self._budget_recovers(key, lane, head.cost, now)
            later += [self._drop_at(cost, deadline, now)
                      for _, cost, deadline, _ in self._unstarted_deadlines(key, lanes)]
        if self._text_cost and self._text_at is not None:
            later.append(self._text_at + TEXT_FLOOR)
        times += [t for t in later if t > now]
        return min(times) if times else None

    def _budget_recovers(self, key: str, lane: Lane, cost: int, now: float) -> list[float]:
        """The instants at which a line of `cost` to `key` may come within
        budget: the target's budget fitting it, the connection's fitting it
        with and without the allowance, the target's emptying (which may grant
        the allowance; the rest of its condition changes only when lines are
        queued or leave). Waking at one where nothing changes costs nothing;
        missing one makes a line late."""
        per_target, total = _BUDGETS[lane]
        mine, conn = (key, lane), ("", lane)
        return [self._ages_out(mine, now, lambda left: left + cost <= per_target),
                self._ages_out(conn, now, lambda left: left + cost <= total),
                self._ages_out(conn, now, lambda left: left + cost <= total + FRESH_ALLOWANCE),
                self._ages_out(mine, now, lambda left: not left)]

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


class PacedSender:
    """A daemon thread draining a Pacer into `send(target, line)`. The lines
    it hands to `send` are already charged to the Pacer's FakeLag: `send`
    must write them without charging them again.

    `on_lost(target, msgid, reason)` hears, on the pacer's thread, of every
    message lost after it was queued: "late", an URGENT message dropped
    unstarted because no answer could make its deadline (for a CHAL,
    ChallengeExpired follows); "send-failed", a message one of whose lines
    `send` raised on, the rest of it dropped. Hand the msgids to
    Engine.discard. If the thread dies, every call after raises."""

    def __init__(self, send: Callable[[str, str], None], pacer: Pacer,
                 clock: Callable[[], float] = time.monotonic,
                 on_lost: Callable[[str, str | None, str], None] | None = None):
        self._send = send
        self._pacer = pacer
        self._clock = clock
        self._on_lost = on_lost
        self._died: Exception | None = None
        self._cv = threading.Condition()
        self._thread = threading.Thread(target=self._run, name="irc-olm-pacer", daemon=True)
        self._thread.start()

    def _alive(self) -> None:
        if self._died is not None:
            raise RuntimeError("the pacer's thread died: nothing goes out") from self._died

    def submit(self, target: str, lines: list[str], *, lane: Lane,
               deadline: float | None = None) -> bool:
        with self._cv:
            self._alive()
            ok = self._pacer.submit(target, lines, lane=lane, deadline=deadline)
            self._cv.notify()
        if not ok:
            log.warning("pacer: %d %s lines to %s refused, queue full", len(lines),
                        lane.name, target)
        return ok

    def room(self, target: str) -> bool:
        """Pacer.room: ask before encrypting a text message for `target`."""
        with self._cv:
            self._alive()
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
        reports what it costs (a keys-timeout). A body that is not E2E is a
        message of its own, and its refusal is only logged: submit() such
        lines, and its answer says it."""
        now = self._clock()
        messages: dict[tuple[str, str | int], tuple[str | None, list[str]]] = {}
        for i, (target, body) in enumerate(outbound):
            frag = framing.parse(body)
            msgid = frag.msgid if frag is not None else None
            messages.setdefault((target, msgid if msgid is not None else i), (msgid, []))[1].append(body)
        refused = []
        for (target, _), (msgid, lines) in messages.items():
            ttl = urgent.get(msgid) if msgid is not None else None
            frag = framing.parse(lines[0])
            if (not self.submit(target, lines, lane=lane_of(lines[0], urgent),
                                deadline=None if ttl is None else now + ttl)
                    and frag is not None and frag.verb in OLM_VERBS):
                refused.append((target, msgid))
        return refused

    def _run(self) -> None:
        try:
            while True:
                with self._cv:
                    now = self._clock()
                    batch = self._pacer.due(now)
                    lost = [(t, m, "late") for t, m in self._pacer.take_dropped()]
                    if not batch and not lost:
                        wake = self._pacer.next_wakeup(now)
                        self._cv.wait(None if wake is None else max(0.0, wake - now))
                        continue
                lost += self._write(batch)
                if self._on_lost is not None:
                    for target, msgid, reason in lost:
                        self._on_lost(target, msgid, reason)
        except Exception as exc:
            # Never a silent stop: whatever kills the thread, submit() says so.
            log.exception("pacer: thread died, nothing goes out any more")
            with self._cv:
                self._died = exc

    def _write(self, batch: list[tuple[str, str]]) -> list[tuple[str, str | None, str]]:
        lost, failed = [], set()
        for target, line in batch:
            frag = framing.parse(line)
            msgid = None if frag is None else frag.msgid
            if msgid is not None and (fold(target), msgid) in failed:
                continue                    # the rest of a message already lost
            try:
                self._send(target, line)
            except Exception:
                # One failed write (a socket mid-reconnect, say) must not kill
                # the thread; its message can no longer be completed.
                log.exception("pacer: send to %s failed, its message dropped", target)
                lost.append((target, msgid, "send-failed"))
                if msgid is not None:
                    failed.add((fold(target), msgid))
                    with self._cv:
                        self._pacer.drop(target, msgid)
        return lost
