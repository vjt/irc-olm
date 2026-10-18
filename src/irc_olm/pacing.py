"""Paced sending of E2E lines, per target.

bahamut (Azzurra) drops every CTCP to a client for 15 s once that client has
received more than 4 CTCPs inside its 3 s window (FLUD, src/s_user.c). The
window is in integer seconds and a steady sender's count keeps growing while
its first message is inside it, so "3 per 3 s" still trips it. 3 lines per
6 s never did in simulation, even with 2 s of arrival jitter
(tests/test_pacing.py, tests/flud_model.py; numbers on grappa-irc 2430).
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Callable

DEFAULT_MAX_LINES = 3
DEFAULT_WINDOW = 6.0
# Lines waiting per target. At 3 lines per 6 s that is about 17 minutes of
# backlog: past it, whatever is generating the lines is broken or hostile.
DEFAULT_MAX_QUEUE = 512

log = logging.getLogger(__name__)


class Pacer:
    """At most `max_lines` lines to one target in any `window` seconds.

    Pure scheduling, no threads and no clock of its own: the caller asks what
    is due at a given time. Order is kept per target; targets do not wait on
    each other.
    """

    def __init__(self, max_lines: int = DEFAULT_MAX_LINES, window: float = DEFAULT_WINDOW,
                 max_queue: int = DEFAULT_MAX_QUEUE):
        self.max_lines = max_lines
        self.window = window
        self.max_queue = max_queue
        self._queues: dict[str, deque[str]] = {}
        self._sent: dict[str, deque[float]] = {}

    def submit(self, target: str, lines: list[str]) -> bool:
        """Queue `lines` for `target`, all or nothing: False (nothing queued)
        when they would take the target past `max_queue`. Half a fragmented
        message is worse than none."""
        q = self._queues.get(target, ())
        if len(q) + len(lines) > self.max_queue:
            return False
        self._queues.setdefault(target, deque()).extend(lines)
        return True

    def pending(self) -> int:
        return sum(len(q) for q in self._queues.values())

    def _slot(self, target: str, now: float) -> float:
        sent = self._sent.setdefault(target, deque())
        while sent and sent[0] <= now - self.window:
            sent.popleft()
        if len(sent) < self.max_lines:
            return now
        return sent[-self.max_lines] + self.window

    def due(self, now: float) -> list[tuple[str, str]]:
        out = []
        for target, q in list(self._queues.items()):
            while q and self._slot(target, now) <= now:
                out.append((target, q.popleft()))
                self._sent[target].append(now)
            if not q:
                del self._queues[target]
        return out

    def next_wakeup(self, now: float) -> float | None:
        slots = [self._slot(t, now) for t in self._queues]
        return min(slots) if slots else None


class PacedSender:
    """A daemon thread draining a Pacer into `send(target, line)`."""

    def __init__(self, send: Callable[[str, str], None], pacer: Pacer | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self._send = send
        self._pacer = pacer or Pacer()
        self._clock = clock
        self._cv = threading.Condition()
        self._thread = threading.Thread(target=self._run, name="irc-olm-pacer", daemon=True)
        self._thread.start()

    def submit(self, target: str, lines: list[str]) -> bool:
        with self._cv:
            ok = self._pacer.submit(target, lines)
            self._cv.notify()
        if not ok:
            log.warning("pacer queue for %s full: %d lines refused", target, len(lines))
        return ok

    def submit_all(self, outbound: list[tuple[str, str]]) -> int:
        """Submit an Engine Result's (target, body) pairs, order kept per
        target, each target's lines all or nothing. Returns the number of
        lines refused (logged)."""
        by_target: dict[str, list[str]] = {}
        for target, body in outbound:
            by_target.setdefault(target, []).append(body)
        return sum(len(lines) for target, lines in by_target.items()
                   if not self.submit(target, lines))

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
