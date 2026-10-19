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

Three lanes (Lane), scheduled by MESSAGE: once an urgent or a text message's
first line has left, no other message of its lane starts before it ends, so
one urgent and one text message are under way at a time (KEYS and NACKs to
different targets may interleave). URGENT is what we originate and cannot
wait: a KEYREQ, and the messages carrying a CHAL or an ACK (Result.urgent).
REACTIVE is what a peer draws from us, KEYS and NACK. Both go ahead of text
within budgets, per target and for the connection, counted on all of a
message's lines, because peers draw both: the bot challenges every line a
pinned human addresses to it. Past its budget a message waits behind the
text, except that a target which drew nothing from that lane in the last
minute may still go, from a small allowance: an honest peer behind a
flooder, a second human behind a chatty one. Such a target's KEYS or NACK
goes ahead of the others' backlog. A first contact's KEYS that has waited
FRESH_PATIENCE also goes ahead of the orders queued since, paid from the
orders' allowance, which it shares with that second human: it is answered
before its asker asks again, a CHAL queued meanwhile still goes first, and
the orders keep their own budget. A CHAL carries its deadline, and starts
only if it can still be answered. TEXT has no budget, and a floor instead:
text queued and no text line for TEXT_FLOOR seconds, a text message under
way goes next after an order under way, so it reaches its receiver (who
drops a partial message 60 s after its last fragment); one not started goes
after the orders and the first contacts' KEYS. A KEYS or NACK under way
has that floor too, from its own last line, and takes turns with text under
way past it. Turns go to the target served longest ago, in every lane;
within a target each lane keeps its order, so a short message never
overtakes a long one sent before it, which its reader would see reversed.
REACTIVE and TEXT lines never take the bank past a reserve kept for URGENT
ones, so a CHAL behind a stream of text leaves within seconds, but the rest
of a KEYS or NACK past its floor, and a first contact's KEYS going ahead of
every order, take it, as the orders do.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from enum import IntEnum
from itertools import count, islice
from math import inf
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
# than that, which goes at an empty bank (a full line costs 6 s), and the rest
# of a KEYS or NACK past its floor and a first contact's KEYS going ahead of
# every order, which take the reserve as the orders do (behind an older order
# a KEYS leaves it to that order). Text loses no throughput (the bank drains a
# second a second either way), and a 2-line CHAL behind streaming text leaves
# within 7 s instead of 11.
RESERVE = 5.0
# Bank seconds that may go ahead of text in BUDGET_WINDOW, decided when a
# message's first line is due, on all its lines: a message that starts
# finishes, and no window holds more than the budget (and the allowance)
# ahead of text. When no text line can go (none queued, or its target's
# window full), a message past its budget takes the idle bank.
# URGENT, the connection's, whoever gives the orders: four orders (CHALs of
# 5 + 4 s), or a first contact (KEYREQ, pre-key CHAL) and two; one human may
# take it all. REACTIVE, per target: five NACKs and a KEYS (the recovery
# after a lost session), or two KEYS (an answer and a retry's); and for the
# connection, two KEYS and a few NACKs.
URGENT_BUDGET = 36.0
REACTIVE_BUDGET = 18.0
REACTIVE_BUDGET_TOTAL = 22.0
# A target that drew nothing else from a lane in the window (nothing spent,
# one message queued) may take the connection past its budget by this much,
# one message more for all such targets together: an honest peer behind
# flooders, a second human behind a chatty one. Its KEYS or NACK goes ahead
# of the rest of the lane. URGENT's allowance is also what a first
# contact's KEYS pays from to go ahead of the orders (FRESH_PATIENCE): it
# pays while the orders, the second human and what the first contacts paid
# fit URGENT_BUDGET + FRESH_ALLOWANCE, and the orders keep their own budget
# whatever was paid. So ahead of text past the floor a minute holds at most
# that much when the orders spend first, and the orders' budget on top of
# what was paid when the first contacts pay first: the price of a human's
# orders never failing because strangers came first. A flooder held back by
# the budget always has more queued.
FRESH_ALLOWANCE = 9.0
BUDGET_WINDOW = 60.0
# A fresh target's KEYS waits behind the orders not yet started, and behind
# text past the floor, for this long. Then it goes ahead of the orders queued
# after that instant (those queued before keep their place, waiting on the
# bank or on their target's window: a CHAL arriving meanwhile, 15 s to be
# answered, still goes first, and the KEYS behind it leaves it the reserve)
# and of text past the floor, takes the reserve ahead of them all, and pays
# for the rest of it, once, from URGENT's allowance: one first contact a
# minute while the orders are at their budget. Its asker asks again at
# KEYREQ_RETRY (30 s) and drops what it queued at OUTQ_TTL (60 s). A NACK has
# no asker waiting (its sender keeps the message SENT_MEMORY) and never goes
# ahead of the orders.
FRESH_PATIENCE = 8.0
# Text queued and no text line released for this long: a text message under
# way goes next after an order under way, one not started after the orders
# and the first contacts' KEYS. A message under way then gets a line every
# TEXT_FLOOR, plus the rest of one order (10 s), the bank emptying for the
# text line (10 s) and the target's window (6 s): 46 s, inside the 60 s its
# receiver keeps it. The rest of a KEYS or NACK whose last line left this
# long ago takes turns with it, taking the reserve: the same 46 s, plus a
# line for every other message under way past its floor at that instant.
TEXT_FLOOR = 20.0
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
    keys: bool                 # a KEYS: a first contact waits on it
    cost: int                  # flood bank, computed at submit: bad input fails there


# (per target, the connection's) for each budgeted lane.
_BUDGETS = {Lane.URGENT: (URGENT_BUDGET, URGENT_BUDGET),
            Lane.REACTIVE: (REACTIVE_BUDGET, REACTIVE_BUDGET_TOTAL)}

# Ranks, the lowest goes first; then turns (the target served longest ago),
# then the order of submission: an order under way, a message under way past
# its floor (text, or a KEYS or NACK), a fresh target's KEYS that has waited
# FRESH_PATIENCE (under way or not, no order queued before that instant still
# waiting within budget), the orders within budget, a fresh target's KEYS
# that has waited but behind such an order, text past the floor, another
# KEYS or NACK under way, a fresh target's, the rest within budget, text, and
# whatever is past its budget. What goes ahead of text past the floor, but
# what is under way, is the orders and what the fresh KEYS paid: the orders
# within their own budget (the allowance for a second human), the KEYS
# within URGENT_BUDGET + FRESH_ALLOWANCE less what the orders had spent.
(_STARTED_URGENT, _STARVED_STARTED, _FRESH_FIRST, _URGENT, _FRESH_NEXT, _STARVED_TEXT,
 _STARTED_REACTIVE, _FRESH_REACTIVE, _REACTIVE, _TEXT, _PAST_BUDGET) = range(11)

# What fresh KEYS paid to go ahead of the orders: a budget window like the
# others (a target is a nick, never with a space in it).
_PAID = " paid"


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
        self._reactive_at: dict[str, float] = {}  # REACTIVE queued since (FRESH_PATIENCE)
        self._cutoff: dict[str, int] = {}     # a seq drawn when that patience ran out
        self._fresh: set[str] = set()         # a KEYS under way started at _FRESH_REACTIVE
        self._paid: set[str] = set()          # a KEYS under way that paid for going ahead
        self._dropped: list[tuple[str, str | None]] = []

    def submit(self, target: str, lines: list[str], *, lane: Lane,
               deadline: float | None = None) -> bool:
        """Queue `lines`, whole messages one after another, for `target`, all
        or nothing: False (nothing queued) when they would take the target's
        URGENT or REACTIVE lane past `max_urgent` lines, or the text past
        `max_backlog` (all targets) or the target's text past
        `max_text_messages`. Half a fragmented message is worse than none:
        ValueError when a message cuts into another or the last line does
        not end one (fragment indexes are not checked). An URGENT
        message is dropped unstarted once it cannot leave ACK_MARGIN before
        `deadline` (take_dropped)."""
        if not lines:
            return True
        key = fold(target)
        queued = self._queues.get(key)
        entries = [self._entry(target, line, deadline if lane is Lane.URGENT else None)
                   for line in lines]
        under_way = None
        for e in entries:
            if under_way is not None and e.msgid != under_way:
                raise ValueError(f"submit whole messages: {e.line[:40]!r} cuts into another")
            under_way = None if e.ends else e.msgid
        if under_way is not None:
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
        if self._open.get((key, Lane.REACTIVE)) == msgid:
            self._paid.discard(key)
            self._fresh.discard(key)
        for lane in Lane:
            if self._open.get((key, lane)) == msgid:
                del self._open[(key, lane)]
        lanes = self._queues.get(key)
        if lanes is None:
            return
        gone = [e for q in lanes for e in q if e.msgid == msgid]
        for lane, q in zip(Lane, lanes):
            mine = [e for e in q if e.msgid == msgid]
            if not mine:
                continue
            if lane is Lane.TEXT:
                self._text_cost -= sum(e.cost for e in mine)
                self._text_messages[key] -= sum(e.ends for e in mine)
            keep = [e for e in q if e.msgid != msgid]
            q.clear()
            q.extend(keep)
        self._left_a_gap(key, int(any(e.olm for e in gone)))
        self._tidy(key)

    def _entry(self, target: str, line: str, deadline: float | None) -> _Line:
        frag = framing.parse(line)
        return _Line(next(self._seq), target, line, None if frag is None else frag.msgid,
                     frag is None or frag.index == frag.total, deadline,
                     frag is not None and frag.verb in OLM_VERBS,
                     frag is not None and frag.verb == "KEYS",
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
        if not lanes[Lane.REACTIVE]:
            self._reactive_at.pop(key, None)
            self._cutoff.pop(key, None)
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

    @staticmethod
    def _head(q: deque) -> tuple[int, int]:
        """(lines, bank cost) of a lane's head message, not yet started."""
        lines = next(n for n, e in enumerate(q, 1) if e.ends)
        return lines, sum(e.cost for e in islice(q, lines))

    def _budget_rank(self, key: str, lane: Lane, now: float) -> int:
        """Where the head message of an URGENT or REACTIVE lane, not yet
        started, goes: ahead of text if all its lines fit the target's
        budget and the connection's, behind it if not. A target that drew
        nothing else from the lane in the window (nothing spent, one message
        queued) may use the connection's allowance (_allowed), and its KEYS
        or NACK goes ahead of the rest of the lane: an honest peer's answer
        does not queue behind the backlog others drew. Its KEYS, once it
        has waited FRESH_PATIENCE, goes ahead of the orders queued since
        too (_ahead), if the allowance has room for it."""
        per_target, total = _BUDGETS[lane]
        q = self._queues[key][lane]
        lines, cost = self._head(q)
        spent = self._spent_in(key, lane, now)
        fresh = not spent and lines == len(q)
        if spent + cost > per_target or (self._spent_in("", lane, now) + cost > total and not (
                fresh and self._allowed(lane, cost, now))):
            return _PAST_BUDGET
        if lane is Lane.URGENT:
            return _URGENT
        if not fresh:
            return _REACTIVE
        ahead = self._ahead(key, cost, now) if q[0].keys else None
        return _FRESH_REACTIVE if ahead is None else ahead

    def _allowed(self, lane: Lane, cost: int, now: float) -> bool:
        """Whether `cost` more fits the connection's budget stretched by
        FRESH_ALLOWANCE: URGENT's counts what the fresh KEYS paid to go
        ahead too, the two sharing it."""
        return (self._spent_in("", lane, now) + cost
                + (self._spent_in(_PAID, lane, now) if lane is Lane.URGENT else 0.0)
                <= _BUDGETS[lane][1] + FRESH_ALLOWANCE)

    def _ahead(self, key: str, cost: int, now: float) -> int | None:
        """Where a fresh target's KEYS (the rest of it, of `cost`) goes
        ahead of text past the floor: None before its patience is out, or
        while URGENT's allowance has no room for it. Behind the orders
        queued before its patience ran out, still waiting within budget;
        ahead of the others."""
        if not (self._waited(key, now) and self._allowed(Lane.URGENT, cost, now)):
            return None
        return _FRESH_NEXT if self._order_before(key, now) else _FRESH_FIRST

    def _waited(self, key: str, now: float) -> bool:
        # The wakeup's expression, so that the two agree to the last bit.
        at = self._reactive_at.get(key)
        return at is not None and now >= at + FRESH_PATIENCE

    def _order_before(self, key: str, now: float) -> bool:
        # A seq is drawn when the patience runs out (due()): the orders
        # queued before have lower ones. Not drawn yet, every order is.
        cutoff = self._cutoff.get(key, inf)
        return any(lanes[Lane.URGENT][0].seq < cutoff
                   and self._open.get((k, Lane.URGENT)) is None
                   and self._budget_rank(k, Lane.URGENT, now) == _URGENT
                   for k, lanes in self._queues.items() if lanes[Lane.URGENT])

    def _last_reactive(self, key: str) -> float:
        """When the target's last KEYS or NACK line left (-inf: over a
        budget window ago): the floor's clock of one under way."""
        spent = self._spent.get((key, Lane.REACTIVE))
        return spent[-1][0] if spent else -inf

    def _starved(self, now: float) -> bool:
        # The wakeup's expression, so that the two agree to the last bit.
        return bool(self._text_cost) and self._text_at is not None \
            and now >= self._text_at + TEXT_FLOOR

    def _rank(self, key: str, lane: Lane, head: _Line, starved: bool, now: float):
        started = head.msgid is not None and self._open.get((key, lane)) == head.msgid
        if lane is Lane.TEXT:
            # Starved, a message under way goes before any order: its
            # receiver would drop it. One not started yields to the orders.
            rank = (_STARVED_STARTED if started else _STARVED_TEXT) if starved else _TEXT
        elif started and lane is Lane.URGENT:
            rank = _STARTED_URGENT
        elif started and now >= self._last_reactive(key) + TEXT_FLOOR:
            # The floor, from its own last line (the wakeup's expression),
            # before what it paid or waited: those only ever raise it.
            rank = _STARVED_STARTED
        elif started and key in self._paid:
            # Paid for, a fresh KEYS's rest stays ahead.
            rank = _FRESH_NEXT if self._order_before(key, now) else _FRESH_FIRST
        elif started and key in self._fresh and (
                ahead := self._ahead(key, self._head(self._queues[key][lane])[1], now)) is not None:
            rank = ahead                     # started with nothing ahead, it waited
        elif started:
            rank = _STARTED_REACTIVE
        else:
            rank = self._budget_rank(key, lane, now)
        return (rank, self._served.get(key, float("-inf")), head.seq)

    def _next(self, now: float):
        """(key, lane, entry, rank) of the line whose turn it is, or None while
        every target waits on its window; then the earliest time a window
        opens (or None). While a message is under way, no other of its lane
        starts."""
        heads, opens = [], []
        # One urgent and one text message under way at a time: a second
        # order interleaving with the first makes both late, and text
        # messages taking turns age together past their receivers' minute.
        under_way = {lane: k for k, lane in self._open if lane is not Lane.REACTIVE}
        starved = self._starved(now)
        for key, lanes in self._queues.items():
            slot = self._slot(key, now)
            if slot > now:
                opens.append(slot)
                continue
            for lane in Lane:
                if lanes[lane] and under_way.get(lane, key) == key:
                    head = lanes[lane][0]
                    heads.append((self._rank(key, lane, head, starved, now), key, lane, head))
        if not heads:
            return None, min(opens) if opens else None
        rank, key, lane, head = min(heads, key=lambda h: h[0])
        return (key, lane, head, rank[0]), min(opens) if opens else None

    def _limit(self, lane: Lane, rank: int) -> float:
        # The rest of a KEYS or NACK under way past its floor, and a first
        # contact's KEYS going ahead of every order, take the reserve as the
        # orders do; one behind an older order leaves it to that order.
        urgent = lane is Lane.URGENT or (lane is Lane.REACTIVE
                                         and rank in (_STARVED_STARTED, _FRESH_FIRST))
        return self.fakelag.ceiling - (0.0 if urgent else RESERVE)

    def due(self, now: float) -> list[tuple[str, str]]:
        """Release what may go now, charging it to the bank. Once the bank
        has no room for the line whose turn it is, nothing else goes either:
        a cheaper line slipping past would keep the dear one waiting."""
        self._forget_idle(now)
        if self._text_at is None and self._text_cost:
            self._text_at = now
        for key, lanes in self._queues.items():
            if lanes[Lane.REACTIVE]:
                self._reactive_at.setdefault(key, now)    # the patience's clock
                if key not in self._cutoff and self._waited(key, now):
                    self._cutoff[key] = next(self._seq)
        out = []
        while True:
            self._drop_dead(now)
            nxt, _ = self._next(now)
            if nxt is None:
                break
            key, lane, head, rank = nxt
            if self.fakelag is not None and not self.fakelag.try_add(head.cost, now,
                                                                     self._limit(lane, rank)):
                break
            if rank == _FRESH_REACTIVE and head.keys:
                self._fresh.add(key)
            if rank in (_FRESH_FIRST, _FRESH_NEXT) and key not in self._paid:
                # Going ahead of the orders and of text past the floor: the
                # rest of it is paid for, once, from URGENT's allowance.
                self._spent.setdefault((_PAID, Lane.URGENT), deque()).append(
                    (now, self._head(self._queues[key][lane])[1]))
                self._paid.add(key)
            if head.ends and lane is Lane.REACTIVE:
                self._paid.discard(key)
                self._fresh.discard(key)
            self._queues[key][lane].popleft()
            if lane is Lane.TEXT:
                self._text_cost -= head.cost
                self._text_messages[key] -= head.ends
                self._text_at = now
            else:
                for k in (key, ""):
                    self._spent.setdefault((k, lane), deque()).append((now, head.cost))
            if not head.ends:
                self._open[(key, lane)] = head.msgid
            else:
                # Messages are queued whole, one after another: the line
                # that ends one is the open message's (a bare line has none).
                self._open.pop((key, lane), None)
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
        a fresh KEYS's patience running out or the allowance's room for it,
        the floor of a KEYS or NACK under way, or the text floor. Never `now`
        with nothing due."""
        nxt, opens = self._next(now)
        times = [] if opens is None else [opens]
        if nxt is not None:
            _, lane, head, rank = nxt
            times.append(now if self.fakelag is None
                         else self.fakelag.room_at(head.cost, now, self._limit(lane, rank)))
        later = []
        for key, lanes in self._queues.items():
            for lane in (Lane.URGENT, Lane.REACTIVE):
                if lanes[lane]:
                    head = lanes[lane][0]
                    cost = self._head(lanes[lane])[1]
                    if head.msgid is None or self._open.get((key, lane)) != head.msgid:
                        later += self._budget_recovers(key, lane, cost, now)
                        if lane is Lane.REACTIVE:
                            later += self._patience_ends(key, cost, now)
                    elif lane is Lane.REACTIVE:
                        later.append(self._last_reactive(key) + TEXT_FLOOR)
                        if key in self._fresh and key not in self._paid:
                            later += self._patience_ends(key, cost, now)
            later += [self._drop_at(cost, deadline, now)
                      for _, cost, deadline, _ in self._unstarted_deadlines(key, lanes)]
        if self._text_cost and self._text_at is not None:
            later.append(self._text_at + TEXT_FLOOR)
        times += [t for t in later if t > now]
        return min(times) if times else None

    def _budget_recovers(self, key: str, lane: Lane, cost: int, now: float) -> list[float]:
        """The instants at which a message of `cost` to `key` may come within
        budget: the target's budget fitting it, the connection's fitting it
        with and without the allowance, the target's emptying (which may grant
        the allowance and the precedence; the rest of its condition changes
        only when lines are queued or leave). Waking at one where nothing
        changes costs nothing; missing one makes a line late."""
        per_target, total = _BUDGETS[lane]
        mine, conn = (key, lane), ("", lane)
        allowed = (conn, (_PAID, lane)) if lane is Lane.URGENT else (conn,)
        return [self._ages_out((mine,), now, lambda left: left + cost <= per_target),
                self._ages_out((conn,), now, lambda left: left + cost <= total),
                self._ages_out(allowed, now, lambda left: left + cost <= total + FRESH_ALLOWANCE),
                self._ages_out((mine,), now, lambda left: not left)]

    def _patience_ends(self, key: str, cost: int, now: float) -> list[float]:
        """The instants at which a fresh target's KEYS (the rest of it) of
        `cost` may go ahead: its patience running out, and URGENT's
        allowance (_allowed) fitting it."""
        at = self._reactive_at.get(key)
        return ([] if at is None else [at + FRESH_PATIENCE]) + [self._ages_out(
            (("", Lane.URGENT), (_PAID, Lane.URGENT)), now,
            lambda left: left + cost <= URGENT_BUDGET + FRESH_ALLOWANCE)]

    def _ages_out(self, kls: tuple[tuple[str, Lane], ...], now: float,
                  ok: Callable[[float], bool]) -> float:
        """When enough of the releases in the budget windows `kls` age out
        for `ok` to hold of what is left of them together: `now` if it holds
        already."""
        left = sum(self._spent_in(*kl, now) for kl in kls)
        for t, spent in sorted(e for kl in kls for e in self._spent.get(kl, ())):
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
                for target, msgid, reason in lost + self._write(batch):
                    self._report(target, msgid, reason)
        except Exception as exc:
            # Never a silent stop: whatever kills the thread, submit() says so.
            log.exception("pacer: thread died, nothing goes out any more")
            with self._cv:
                self._died = exc

    def _report(self, target: str, msgid: str | None, reason: str) -> None:
        if self._on_lost is None:
            return
        try:
            self._on_lost(target, msgid, reason)
        except Exception:
            # The application's callback failing is not the pacer failing:
            # the other losses are still reported, and lines still go.
            log.exception("pacer: on_lost failed for %s %s", target, msgid)

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
