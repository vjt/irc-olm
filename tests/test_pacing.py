import math
import random

import pytest

from flud_model import FludModel
from irc_olm.pacing import Lane, Pacer


# --- the model itself (positive and negative controls) -------------------

def test_model_trips_on_five_in_one_second():
    m = FludModel()
    assert [m.ctcp("a", 1000) for _ in range(5)] == [False] * 4 + [True]


def test_model_trips_on_a_second_burst_at_the_three_second_boundary():
    m = FludModel()
    for _ in range(3):
        assert not m.ctcp("a", 1000)
    assert not m.ctcp("a", 1003)
    assert m.ctcp("a", 1003)


def test_model_lets_a_steady_sender_through_after_the_first_window():
    m = FludModel()
    assert not any(m.ctcp("a", 1000 + t) for t in range(60))


def test_model_counts_all_senders_together():
    m = FludModel()
    for s in "abcd":
        assert not m.ctcp(s, 1000)
    assert m.ctcp("e", 1000)


# --- the pacer -----------------------------------------------------------

def drain(p, t0, step=0.05, until=600.0):
    """Run the pacer on a fake clock; return [(t, target, line)]."""
    out = []
    for k in range(int(until / step)):
        t = t0 + k * step  # multiplied, not accumulated: no float drift
        for target, line in p.due(t):
            out.append((t, target, line))
        if not p.pending():
            break
    return out


def test_burst_then_one_line_every_window_per_target():
    p = Pacer(max_lines=3, window=6.0, fakelag=None)
    p.submit("vjt", [f"l{i}" for i in range(7)], lane=Lane.TEXT)
    sent = drain(p, 0.0)
    times = [round(t, 2) for t, _, _ in sent]
    assert [line for _, _, line in sent] == [f"l{i}" for i in range(7)]
    assert times[:3] == [0.0, 0.0, 0.0]
    assert times[3:6] == [6.0, 6.0, 6.0]
    assert times[6] == 12.0


def test_targets_are_paced_independently():
    p = Pacer(max_lines=3, window=6.0, fakelag=None)
    p.submit("a", ["a1", "a2", "a3", "a4"], lane=Lane.TEXT)
    p.submit("b", ["b1"], lane=Lane.TEXT)
    first = p.due(0.0)
    assert ("b", "b1") in first and ("a", "a3") in first and ("a", "a4") not in first


def test_next_wakeup_is_the_earliest_slot():
    p = Pacer(max_lines=3, window=6.0, fakelag=None)
    assert p.next_wakeup(0.0) is None
    p.submit("a", ["1", "2", "3", "4"], lane=Lane.TEXT)
    p.due(1.0)
    assert p.next_wakeup(1.0) == pytest.approx(7.0)


@pytest.mark.parametrize("seed", range(20))
def test_default_pacing_never_trips_bahamut_flud(seed):
    rng = random.Random(seed)
    p = Pacer(fakelag=None)  # the per-target defaults are what ships
    t = 0.0
    events = []
    for _ in range(rng.randint(1, 15)):
        t += rng.choice([0, 0, rng.uniform(0, 10)])
        events.append((t, rng.randint(1, 8)))
    sent, now, i, k = [], 0.0, 0, 0
    while now < 1000 and (i < len(events) or p.pending()):
        while i < len(events) and events[i][0] <= now:
            p.submit("vjt", ["x"] * events[i][1], lane=Lane.TEXT)
            i += 1
        sent += [now for _ in p.due(now)]
        k += 1
        now = k * 0.05
    for jitter in (0.0, 0.5, 1.0, 2.0):
        phase = rng.uniform(0, 1)
        arrivals = sorted(math.floor(1000 + s + phase + rng.uniform(0, jitter)) for s in sent)
        m = FludModel()
        assert not any(m.ctcp("bot", a) for a in arrivals), (seed, jitter)


def test_three_per_three_seconds_does_trip_it():
    # Pins the reason the default is not the obvious 3-per-3s window.
    p = Pacer(max_lines=3, window=3.0, fakelag=None)
    p.submit("vjt", ["x"] * 6, lane=Lane.TEXT)
    sent = [t for t, _, _ in drain(p, 0.0)]
    m = FludModel()
    assert any(m.ctcp("bot", math.floor(1000 + s)) for s in sent)


def test_paced_sender_thread_delivers_in_order():
    import threading
    from irc_olm.pacing import PacedSender

    got, done = [], threading.Event()

    def send(target, line):
        got.append((target, line))
        if len(got) == 5:
            done.set()

    s = PacedSender(send, Pacer(max_lines=2, window=0.1, fakelag=None))
    s.submit("vjt", ["1", "2", "3", "4", "5"], lane=Lane.TEXT)
    assert done.wait(5)
    assert got == [("vjt", str(i)) for i in range(1, 6)]


def test_submit_all_keeps_order_per_target():
    import threading
    from irc_olm.pacing import PacedSender

    got, done = [], threading.Event()

    def send(target, line):
        got.append((target, line))
        if len(got) == 4:
            done.set()

    s = PacedSender(send, Pacer(max_lines=3, window=0.1, fakelag=None))
    s.submit_all([("a", "a1"), ("b", "b1"), ("a", "a2"), ("b", "b2")], set())
    assert done.wait(5)
    assert [x for x in got if x[0] == "a"] == [("a", "a1"), ("a", "a2")]
    assert [x for x in got if x[0] == "b"] == [("b", "b1"), ("b", "b2")]


def test_paced_sender_survives_a_send_that_raises():
    import threading
    from irc_olm.pacing import PacedSender

    got, done = [], threading.Event()

    def send(target, line):
        if line == "boom":
            raise OSError("socket gone")
        got.append(line)
        if line == "after":
            done.set()

    s = PacedSender(send, Pacer(max_lines=3, window=0.1, fakelag=None))
    s.submit("vjt", ["boom", "after"], lane=Lane.TEXT)
    assert done.wait(2)
    assert got == ["after"]


def test_text_past_the_connections_backlog_is_refused_whole_and_control_never_is():
    line = "x" * 110                                   # costs 3 s to "vjt", 3 s to "other"
    p = Pacer(max_backlog=9.0, fakelag=None)
    assert p.submit("vjt", [line, line], lane=Lane.TEXT) is True
    assert p.submit("other", [line, line], lane=Lane.TEXT) is False   # 12 s: the whole batch
    assert p.pending() == 2
    assert p.submit("other", [line], lane=Lane.TEXT) is True          # 9 s, across targets
    assert p.submit("vjt", [line] * 5, lane=Lane.URGENT) is True         # control always goes
    drain(p, 1000.0)
    assert p.submit("other", [line] * 3, lane=Lane.TEXT) is True      # sent text frees it


# --- fake lag (bahamut's flood bank) -------------------------------------

from fakelag_model import ServerModel  # noqa: E402
from irc_olm import framing  # noqa: E402
from irc_olm.pacing import (DEFAULT_MAX_TEXT_MESSAGES, DEFAULT_MAX_URGENT,  # noqa: E402
                            DEFAULT_WINDOW, FakeLag)

FULL = "x" * (400 - len("PRIVMSG vjt :"))      # a full E2E line, 400 bytes before CRLF


def run_against_server(p, t0=1000.0, step=0.05, until=900.0, also=()):
    """Drain the pacer into the server model; `also` = [(t, line)] the
    application writes itself at those times, charging its bank then."""
    server, out, extra = ServerModel(), [], sorted(also)
    for k in range(int(until / step)):
        t = t0 + k * step
        while extra and extra[0][0] <= t:
            line = extra.pop(0)[1]
            if p.fakelag is not None:
                p.fakelag.charge(line, t)
            server.arrive(line, int(t))
        for target, body in p.due(t):
            out.append((t, target, body))
            server.arrive(f"PRIVMSG {target} :{body}", int(t))
        server.drain(int(t))
        if not p.pending() and not extra:
            break
    return server, out


def test_fakelag_cost_is_bahamuts_integer_arithmetic_on_the_whole_frame():
    # 2 + bytes/120, bytes = the frame as written, CRLF included (as grappa's FakeLag)
    assert FakeLag.cost("x" * 117) == 2          # 119 bytes with CRLF
    assert FakeLag.cost("x" * 118) == 3          # 120
    assert FakeLag.cost("PRIVMSG vjt :" + FULL) == 5


def test_fakelag_bank_drains_in_real_time_and_never_goes_negative():
    lag = FakeLag()
    assert lag.bank(100.0) == 0.0
    lag.charge("PRIVMSG vjt :" + FULL, 100.0)
    lag.charge("PRIVMSG vjt :" + FULL, 100.0)
    assert lag.bank(100.0) == 10.0
    assert lag.bank(104.0) == 6.0
    assert lag.bank(200.0) == 0.0
    lag.charge("PRIVMSG vjt :x", 200.0)
    assert lag.bank(200.0) == 2.0               # from the floor, no debt carried


def test_three_lines_per_six_seconds_alone_get_a_long_sender_killed():
    # Pins why the per-target window is not enough on its own.
    p = Pacer(fakelag=None)
    p.submit("vjt", [FULL] * 20, lane=Lane.TEXT)
    server, _ = run_against_server(p)
    assert server.killed_at is not None


def test_with_the_bank_no_line_ever_waits_unparsed_on_the_server():
    p = Pacer(max_text_messages=64, fakelag=FakeLag())   # bare lines: one message each
    assert p.submit("vjt", [FULL] * 64, lane=Lane.TEXT)
    server, out = run_against_server(p)
    assert server.killed_at is None
    assert server.max_backlog == 0
    assert len(out) == len(server.parsed) == 64
    assert 300 <= out[-1][0] - out[0][0] <= 330    # one full line every ~5 s


def test_lines_the_application_writes_count_in_the_same_bank():
    def last_e2e_line_at(talk):
        p = Pacer(fakelag=FakeLag())
        p.submit("vjt", [FULL] * 20, lane=Lane.TEXT)
        server, out = run_against_server(p, also=talk)
        assert server.killed_at is None and server.max_backlog == 0
        return out[-1][0]

    chatter = "PRIVMSG #sbiffo :" + "y" * 380
    talking = [(1000.0 + 8 * i, chatter) for i in range(12)]   # the bot talking meanwhile
    assert last_e2e_line_at(talking) > last_e2e_line_at([])    # E2E backed off for it


def _message(n_lines_wanted, target="vjt"):
    size = 300 * n_lines_wanted
    payload = framing.encode_payload({"v": 1, "body": "z" * size})
    bodies = framing.fragment("MSG", payload, own_mask="bot!b@h", target=target)
    assert (len(bodies) > 1) == (n_lines_wanted > 1)
    return bodies


def test_urgent_messages_go_ahead_of_text_and_text_keeps_its_order():
    p = Pacer(fakelag=FakeLag())
    long_msg = _message(12)
    p.submit("vjt", long_msg, lane=Lane.TEXT)
    short = _message(1)                 # text too: it must not overtake the long one
    p.submit("vjt", short, lane=Lane.TEXT)
    chal = _message(2)                  # a CHAL, two lines, queued last: 15 s to live
    p.submit("vjt", chal, lane=Lane.URGENT)
    other = _message(2, target="lucy")
    p.submit("lucy", other, lane=Lane.URGENT)
    _, out = run_against_server(p)
    order = [body for _, _, body in out]
    sent_at = {body: t - 1000.0 for t, _, body in out}
    assert sent_at[chal[-1]] < 15 and sent_at[other[-1]] < 15
    assert order.index(chal[-1]) < order.index(long_msg[-1])
    assert order.index(short[0]) > order.index(long_msg[-1])  # text in the order it came
    assert [b for b in order if b in long_msg] == long_msg     # its own order kept
    assert [b for b in order if b in chal] == chal


def test_submit_all_puts_the_engines_urgent_messages_in_the_fast_lane():
    from irc_olm.pacing import PacedSender
    long_msg, chal = _message(12), _message(2)
    pacer = Pacer(fakelag=FakeLag())
    s = PacedSender(lambda target, line: None, pacer, clock=lambda: 0.0)
    with s._cv:                       # keep the thread off the queue while we look
        refused = s.submit_all([("vjt", b) for b in long_msg + chal],
                               {framing.parse(chal[0]).msgid: None})
        assert refused == []
        assert [line for _, line in pacer.due(1000.0)] == chal[:1]   # 6 s of bank: no room
        assert [line for _, line in pacer.due(1006.0)] == chal[1:]   # for a 5 s long line


def test_an_idle_target_leaves_nothing_behind():
    p = Pacer(fakelag=None)
    for i in range(50):
        p.submit(f"nick{i}", ["x"], lane=Lane.TEXT)
    p.due(1000.0)
    p.due(1000.0 + DEFAULT_WINDOW + 1)
    assert p._sent == {} and p.pending() == 0


def test_the_per_target_window_still_holds_for_single_lines():
    # Small lines (KEYREQs, 2 s each): the bank would let five through at
    # once, the receiver's CTCP flood limit only three.
    keyreq = lambda: framing.fragment("KEYREQ", framing.encode_payload({"v": 1}),  # noqa: E731
                                      own_mask="bot!b@h", target="vjt")[0]
    p = Pacer(fakelag=FakeLag())
    p.submit("vjt", [keyreq() for _ in range(6)], lane=Lane.URGENT)
    _, out = run_against_server(p)
    times = [round(t - 1000.0, 2) for t, _, _ in out]
    assert times[:3] == [0.0, 0.0, 0.0] and min(times[3:]) >= 6.0


def test_a_bank_without_room_sets_the_next_wakeup_instead_of_spinning():
    p = Pacer(fakelag=FakeLag())
    p.submit("vjt", [FULL] * 3, lane=Lane.TEXT)
    assert len(p.due(1000.0)) == 1            # 5 s: text leaves the rest to the reserve
    assert p.due(1000.0) == []
    assert p.next_wakeup(1000.0) == 1005.0    # room for the second line, not "now"


# --- review of the fake-lag branch ---------------------------------------

def test_an_empty_batch_is_accepted_and_breaks_nothing():
    p = Pacer(fakelag=FakeLag())
    assert p.submit("vjt", [], lane=Lane.TEXT) is True
    assert p.submit("vjt", [], lane=Lane.URGENT) is True
    assert p.due(1000.0) == [] and p.next_wakeup(1000.0) is None and p.pending() == 0
    assert not p._queues              # an empty entry would hold every turn back
    p.submit("vjt", ["x"], lane=Lane.TEXT)
    assert [line for _, line in p.due(1000.0)] == ["x"]


def test_one_nick_spelt_two_ways_is_one_target_for_the_window():
    p = Pacer(fakelag=None)
    p.submit("Bob", ["1", "2", "3"], lane=Lane.TEXT)
    p.submit("bob", ["4", "5", "6"], lane=Lane.TEXT)
    assert [t for t, _ in p.due(1000.0)] == ["Bob", "Bob", "Bob"]   # each line keeps its spelling


def test_a_target_flooding_us_with_reactive_lines_cannot_starve_the_others():
    # Whoever holds a pinned nick can draw a KEYS every 30 s and a NACK per
    # junk line: its reactive lines must not hold everyone else's back.
    p = Pacer(fakelag=FakeLag())
    t0, left = 1000.0, {}
    p.submit("c", [FULL] * 3, lane=Lane.TEXT)
    for k in range(int(120 / 0.5)):
        now = t0 + k * 0.5
        if k % 2 == 0:
            p.submit("mal", ["n" * 300], lane=Lane.REACTIVE)     # one NACK a second
        if k == 20:
            p.submit("lucy", ["chal" + "c" * 300] * 2, lane=Lane.URGENT)
        for target, line in p.due(now):
            left.setdefault(target, []).append(now - t0)
    assert len(left.get("c", [])) == 3 and left["c"][-1] < 60
    assert left["lucy"][-1] - 10 <= 7                         # a CHAL submitted at 10 s


@pytest.mark.parametrize("lane", [Lane.URGENT, Lane.REACTIVE])
def test_a_targets_urgent_and_reactive_queues_are_capped(lane):
    p = Pacer(fakelag=FakeLag())
    assert p.submit("mal", ["n"] * DEFAULT_MAX_URGENT, lane=lane) is True
    assert p.submit("mal", ["n"], lane=lane) is False
    assert p.submit("vjt", ["n"], lane=lane) is True
    other = Lane.REACTIVE if lane is Lane.URGENT else Lane.URGENT
    assert p.submit("mal", ["n"], lane=other) is True      # each lane its own cap


def test_text_queued_for_one_target_stays_within_what_olm_can_skip():
    # An urgent message overtakes the target's queued text: the receiver
    # skips one message key per message overtaken, and keeps only so many.
    p = Pacer(fakelag=FakeLag())
    msgs = [_message(1) for _ in range(DEFAULT_MAX_TEXT_MESSAGES)]
    for m in msgs:
        assert p.submit("vjt", m, lane=Lane.TEXT) is True
    assert p.submit("vjt", _message(1), lane=Lane.TEXT) is False
    assert p.submit("lucy", _message(1), lane=Lane.TEXT) is True
    p.due(1000.0)                                             # one message leaves, but the
    assert not p.room("vjt")                                  # refused one was encrypted: a
    p.due(1006.0)                                             # key the receiver skips
    p.due(1012.0)                                             # (lucy had a turn between)
    assert p.room("vjt") and p.submit("vjt", _message(1), lane=Lane.TEXT) is True


def test_fakelag_checks_and_charges_in_one_step():
    lag = FakeLag()
    assert lag.try_add(6, 1000.0) is True
    assert lag.try_add(5, 1000.0) is False and lag.bank(1000.0) == 6.0
    assert lag.try_add(4, 1000.0) is True and lag.bank(1000.0) == 10.0


# --- reviews G and H: lanes, messages, budgets, reserve, deadlines -------

from irc_olm.pacing import (FAKE_LAG_CEILING, REACTIVE_BUDGET,  # noqa: E402
                            REACTIVE_BUDGET_TOTAL, RESERVE, URGENT_BUDGET, PacedSender,
                            lane_of)

# Bare lines by their bank cost as a PRIVMSG to a nick of 2 to 5 letters.
L6, L5, L4, L2 = "W" * 470, "Z" * 430, "Y" * 300, "n" * 60


def msg(target, *costs, verb="MSG"):
    """One fragmented message to `target` whose lines cost `costs`."""
    msgid = framing.new_msgid()
    out = []
    for i, c in enumerate(costs, 1):
        head = f"\x01E2E {verb} {msgid} {i}/{len(costs)} "
        frame = len(f"PRIVMSG {target} :".encode()) + len(head) + 1 + 2   # \x01, CRLF
        out.append(head + "A" * ((120 * (c - 2) + 10 if c > 2 else 100) - frame) + "\x01")
        assert FakeLag.cost(f"PRIVMSG {target} :{out[-1]}") == c
    return out


def poll(p, events, until, t0=0.0, step=0.05, after=None):
    """Drive `p` on a 50 ms poll from t0. `events` = [(t, fn)]: fn(now) runs
    once the clock reaches t. Returns {target: [(t - t0, line)]}; `after`
    (now, batch) is called after every due()."""
    left, pending = {}, sorted(events, key=lambda e: e[0])
    for k in range(int(until / step)):
        t = t0 + k * step
        while pending and pending[0][0] <= t - t0 + 1e-9:
            pending.pop(0)[1](t)
        batch = p.due(t)
        for target, line in batch:
            left.setdefault(target, []).append((round(t - t0, 2), line))
        if after:
            after(t, batch)
    return left


def flooders(p, n, until, start=0):
    """`n` holders of pinned nicks: each draws a NACK (2 s of bank) with a
    junk line every 3 s, and a KEYS (two lines, 5 s and 3 s) with a KEYREQ
    every 15 s, the most the engine answers."""
    ev = []
    for i in range(n):
        f = f"mal{start + i}"
        ev += [(0.05 * i + 3.0 * k, lambda _, f=f: p.submit(f, msg(f, 2, verb="NACK"),
                                                             lane=Lane.REACTIVE))
               for k in range(int(until / 3.0))]
        ev += [(0.5 * i + 15.0 * k, lambda _, f=f: p.submit(f, msg(f, 5, 3, verb="KEYS"),
                                                              lane=Lane.REACTIVE))
               for k in range(int(until / 15.0))]
    return ev


def streams(p, *targets):
    for s in targets:
        assert p.submit(s, [L6] * 20, lane=Lane.TEXT)


def order(p, target, at, costs=(6, 5), ttl=15.0):
    """A CHAL submitted at `at`, as PacedSender.submit_all hands it over."""
    lines = msg(target, *costs)
    return lines, (at, lambda now: p.submit(target, lines, lane=Lane.URGENT, deadline=now + ttl))


def test_room_at_names_an_instant_at_which_try_add_accepts():
    # The two used to round differently: at the instant room_at named, the
    # bank was one ulp over, and next_wakeup returned `now` with nothing due.
    for i in range(2000):
        for limit in (None, FAKE_LAG_CEILING - RESERVE):
            lag = FakeLag()
            t0 = 1000.0 + i * 0.0137
            lag.add(3, t0)
            lag.add(5, t0 + 0.3)
            when = lag.room_at(5, t0 + 0.3, limit)
            assert lag.try_add(5, when, limit), (i, when, limit)


def test_a_line_dearer_than_the_limit_goes_only_at_an_empty_bank():
    lag = FakeLag()
    assert lag.try_add(6, 1000.0, 5.0) and lag.bank(1000.0) == 6.0
    assert not lag.try_add(2, 1000.0, 5.0)
    assert lag.room_at(2, 1000.0, 5.0) == 1003.0
    assert lag.room_at(6, 1000.0, 5.0) == 1006.0


@pytest.mark.parametrize("seed", range(40))
def test_nothing_falls_due_before_the_wakeup_and_the_wakeup_is_never_now(seed):
    # Event-driven, as PacedSender runs it: between one wakeup and the next
    # nothing may become due (a window opening, the bank's room, a budget
    # recovering, a dead urgent message making way), and a wakeup at `now`
    # with nothing due is a spin.
    rng = random.Random(seed)
    p = Pacer(fakelag=FakeLag())
    t0 = 1000.0 + rng.random()
    subs = []
    for _ in range(rng.randint(5, 60)):
        target, lane = rng.choice("abcd"), rng.choice(list(Lane))
        costs = [rng.choice([2, 3, 4, 5, 6]) for _ in range(rng.randint(1, 3))]
        lines = msg(target, *costs) if rng.random() < 0.7 else [L5] * len(costs)
        ttl = rng.choice([None, 2.0, 8.0, 15.0]) if lane is Lane.URGENT else None
        subs.append((t0 + rng.uniform(0, 120), target, lane, lines, ttl))
    subs.sort(key=lambda x: x[0])
    now = t0
    for _ in range(20000):
        while subs and subs[0][0] <= now:
            _, target, lane, lines, ttl = subs.pop(0)
            p.submit(target, lines, lane=lane, deadline=None if ttl is None else now + ttl)
        p.due(now)
        wake = p.next_wakeup(now)
        assert wake is None or wake > now, (seed, now)
        nxt = min([w for w in (wake, subs[0][0] if subs else None) if w is not None], default=None)
        if nxt is None:
            break
        for k in range(1, 8):
            t = now + (nxt - now) * k / 8
            if t < nxt:                  # a wakeup an ulp away rounds onto it
                assert p.due(t) == [], (seed, now, t, nxt)
        now = nxt
    assert p.pending() == 0 and not subs


def test_turns_go_to_the_target_served_longest_ago_beyond_the_window():
    # Two streams of full lines rotate slower than the 6 s window: a third
    # target's line still gets the next turn, it does not wait for both.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    left = poll(p, [(10.0, lambda _: p.submit("c", ["hello"], lane=Lane.TEXT))], until=300)
    assert left["c"][0][0] - 10.0 <= 6.0


@pytest.mark.parametrize("prekey, chal", [((5, 5, 4), (5, 4)), ((6, 6, 3), (6, 3))])
@pytest.mark.parametrize("first_contact", [False, True])
def test_four_orders_a_minute_from_one_human_never_wait(first_contact, prekey, chal):
    # Four orders, or a first contact (KEYREQ, a pre-key CHAL) and two more,
    # two targets streaming text: each CHAL leaves within 7 s (review G,
    # G2b), a pre-key one within 12. The CHALs cost what they do with the
    # conservative mask and with a short one (review I, I2d).
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    ev = [(5.0, lambda now: p.submit("lucy", msg("lucy", 2, verb="KEYREQ"),
                                     lane=Lane.URGENT))] if first_contact else []
    chals = ([order(p, "lucy", 7.0, prekey if first_contact else chal)]
             + [order(p, "lucy", t, chal) for t in (22.0, 37.0, 52.0)[:2 if first_contact else 3]])
    left = poll(p, ev + [e for _, e in chals], until=90)
    sent = {line: t for t, line in left["lucy"]}
    for lines, (at, _) in chals:
        assert sent[lines[-1]] - at <= (12.0 if len(lines) == 3 else 7.0), (at, sent[lines[-1]])


def test_a_human_chatting_in_plaintext_cannot_starve_text_or_other_humans_orders():
    # The bot challenges every line a pinned human addresses to it (review
    # H, H2a): a line every 6 s is a CHAL every 6 s, more than the bank.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    chatty = [order(p, "vjt", 10.0 + 6 * k, (5, 4)) for k in range(30)]
    mario, ev = order(p, "mario", 40.0, (5, 4))
    left = poll(p, [e for _, e in chatty] + [ev], until=200)
    assert left["mario"][-1][0] - 40.0 <= 7.0
    text = [t for s in ("s0", "s1") for t, _ in left.get(s, []) if 10.0 <= t < 190.0]
    assert len(text) * 6 >= (60 - URGENT_BUDGET - 6) * 3      # text keeps the rest of the bank
    sent = {line: t for t, line in left["vjt"]}
    for lines, (at, _) in chatty:
        if lines[0] in sent:
            assert sent[lines[0]] <= at + 15.0                 # never started dead
        else:
            assert lines[-1] not in sent                       # dropped whole
    assert p.pending() == 0 or all(not q[Lane.URGENT] for q in p._queues.values())


def test_an_urgent_message_that_can_no_longer_be_answered_is_dropped_and_makes_way():
    # The application holds the bank past the CHAL's deadline: the CHAL is
    # dropped unsent at once, and the KEYREQ behind it goes when it fits.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    chal, keyreq = msg("vjt", 6, 5), msg("vjt", 2, verb="KEYREQ")
    lag.add(30, 1000.0)                                  # the application's own lines
    assert p.submit("vjt", chal, lane=Lane.URGENT, deadline=1010.0)
    assert p.submit("vjt", keyreq, lane=Lane.URGENT)
    assert p.due(1000.0) == []
    assert p.take_dropped() == [("vjt", framing.parse(chal[0]).msgid)]
    assert p.next_wakeup(1000.0) == 1022.0               # for the KEYREQ
    assert [line for _, line in p.due(1022.0)] == keyreq


def test_an_urgent_message_is_dropped_when_it_turns_too_late_to_start():
    # Review I, I2b: dropped only once its deadline had passed, a CHAL could
    # start with no time left for the ACK. Here its target's window holds it
    # until a second after the last instant it could still be answered: the
    # wakeup names that instant, and the KEYREQ behind it goes when the
    # window opens.
    p = Pacer(fakelag=None)
    assert p.submit("vjt", [L2] * 3, lane=Lane.URGENT)
    assert len(p.due(1001.5)) == 3                       # the window: 1007.5
    chal, keyreq = msg("vjt", 6, 5), msg("vjt", 2, verb="KEYREQ")
    assert p.submit("vjt", chal, lane=Lane.URGENT, deadline=1009.0)
    assert p.submit("vjt", keyreq, lane=Lane.URGENT)
    assert p.next_wakeup(1001.5) == 1009.0 - ACK_MARGIN
    assert p.due(1009.0 - ACK_MARGIN) == [] and p.take_dropped() == [
        ("vjt", framing.parse(chal[0]).msgid)]
    assert p.next_wakeup(1009.0 - ACK_MARGIN) == 1007.5
    assert [line for _, line in p.due(1007.5)] == keyreq


def test_a_started_urgent_message_finishes_past_its_deadline():
    # Started in time; the application then fills the bank: the rest of it
    # still goes, half a message being worse than a late one.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    chal = msg("vjt", 6, 6)
    lag.add(4, 1000.0)
    assert p.submit("vjt", chal, lane=Lane.URGENT, deadline=1009.0)
    assert [line for _, line in p.due(1000.0)] == chal[:1]
    lag.add(20, 1000.5)                                  # the application's own lines
    assert [line for _, line in p.due(1020.0)] == []     # 6 s of bank: no room yet
    assert [line for _, line in p.due(1026.0)] == chal[1:]
    assert p.take_dropped() == []


def test_urgent_lines_past_the_targets_budget_wait_behind_text():
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0")
    chals = [order(p, "vjt", 1.0 + 0.1 * k, (6, 5), ttl=600.0) for k in range(6)]
    left = poll(p, [e for _, e in chals], until=120)
    vjt = [t for t, _ in left["vjt"]]
    costs = [FakeLag.cost(f"PRIVMSG vjt :{line}") for _, line in left["vjt"]]
    ahead = sum(c for t, c in zip(vjt, costs) if t < 60.0)
    assert ahead <= URGENT_BUDGET + 5                    # a message that starts finishes
    assert [t for t, _ in left["s0"] if t < 60.0]        # text went meanwhile


@pytest.mark.parametrize("offset", [0.0, 1.3, 2.6, 3.9, 5.2])
@pytest.mark.parametrize("costs, bound", [((6, 5), 7.0), ((6, 6, 4), 12.0)])
def test_a_chal_behind_streaming_text_leaves_within_what_the_reserve_allows(offset, costs, bound):
    # Text never takes the bank past the reserve (a full line, 6 s, goes at
    # an empty bank): a CHAL on a session finds at most 6 s there and leaves
    # within 7 s; a first CHAL, a pre-key message of three lines, within 12.
    # Both assume no other urgent line queued and no line of the
    # application's own in the last 10 s (each adds its cost).
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    lines, ev = order(p, "lucy", 20.0 + offset, costs)
    left = poll(p, [ev], until=60)
    assert [line for _, line in left["lucy"]] == lines
    assert left["lucy"][-1][0] - (20.0 + offset) <= bound


def test_concurrent_urgent_messages_go_message_by_message():
    # Turns by line would interleave them and make both late. (A second CHAL
    # right behind the first would finish 13 s after its line, too late for
    # the ACK: an ACK, with no deadline, stands in for it.)
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    _, lucy = order(p, "lucy", 20.0, (5, 4))
    ack = msg("mario", 5, 4)
    left = poll(p, [lucy, (20.0, lambda _: p.submit("mario", ack, lane=Lane.URGENT))], until=60)
    assert left["lucy"][-1][0] < left["mario"][0][0]
    assert left["lucy"][-1][0] - 20.0 <= 7.0
    assert [line for _, line in left["mario"]] == ack


@pytest.mark.parametrize("n", [1, 2, 3, 6])
def test_holders_of_pinned_nicks_flooding_us_neither_delay_a_chal_nor_starve_text(n):
    p = Pacer(fakelag=FakeLag())
    ev = flooders(p, n, until=300)
    ev.append((0.0, lambda _: p.submit("c", [L5] * 10, lane=Lane.TEXT)))     # 50 s of bank
    _, chal = order(p, "lucy", 95.0)
    left = poll(p, ev + [chal], until=300)
    assert left["lucy"][-1][0] - 95.0 <= 7.0
    # Ahead of text, each takes at most REACTIVE_BUDGET and the rest of a
    # KEYS a minute, all of them REACTIVE_BUDGET_TOTAL and a KEYS: 50 s of
    # text leave within 50 / share minutes.
    share = max(60 - (REACTIVE_BUDGET + 3) * n, 60 - REACTIVE_BUDGET_TOTAL - 8)
    assert left["c"][-1][0] <= 60 * 50 / share + 20


def test_reactive_lines_ahead_of_text_stay_within_each_targets_budget():
    p = Pacer(fakelag=FakeLag())
    ev = flooders(p, 3, until=300) + [(0.0, lambda _: p.submit("c", [L5] * 30, lane=Lane.TEXT))]
    left = poll(p, ev, until=300)
    c_done = left["c"][-1][0]
    assert c_done > 120                                   # text queued all along
    for target in ("mal0", "mal1", "mal2"):
        costs = [(t, FakeLag.cost(f"PRIVMSG {target} :{line}")) for t, line in left[target]]
        for k in range(0, int(c_done - 60) * 20):
            t0 = k * 0.05
            spent = sum(cost for t, cost in costs if t0 <= t < t0 + 60)
            assert spent <= REACTIVE_BUDGET + 3, (target, t0, spent)   # + the rest of a KEYS


def test_text_keeps_a_third_of_the_bank_however_many_flood_us():
    # Review H, H3c: with budgets per target only, six flooders left text
    # nothing. The connection's budget holds them to REACTIVE_BUDGET_TOTAL,
    # except one message for a target that drew nothing in a minute.
    p = Pacer(fakelag=FakeLag())
    ev = flooders(p, 10, until=700)
    ev += [(0.0, lambda _, i=i: p.submit(f"c{i}", [L5] * 30, lane=Lane.TEXT)) for i in range(3)]
    left = poll(p, ev, until=700)
    text = [t for i in range(3) for t, _ in left[f"c{i}"] if 120 <= t < 420]
    assert len(text) * 5 / 5 >= 20                         # s of bank a minute, of 60


def test_a_keys_after_two_nacks_goes_whole():
    # Review H, H3a: the budget decided per line sent half a KEYS at once and
    # the other half a minute later, past the asker's queue.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0")
    keys = msg("vjt", 5, 3, verb="KEYS")
    ev = [(10.0, lambda _: p.submit("vjt", msg("vjt", 2, verb="NACK"), lane=Lane.REACTIVE)),
          (10.2, lambda _: p.submit("vjt", msg("vjt", 2, verb="NACK"), lane=Lane.REACTIVE)),
          (12.0, lambda _: p.submit("vjt", keys, lane=Lane.REACTIVE))]
    left = poll(p, ev, until=120)
    sent = {line: t for t, line in left["vjt"]}
    assert sent[keys[-1]] - 12.0 <= 12.0


@pytest.mark.parametrize("n", [3, 8])
def test_a_started_reactive_message_finishes_before_turns_rotate(n):
    # Review H, H3b: by line, an honest KEYS's second line waited for every
    # flooder's turn.
    p = Pacer(fakelag=FakeLag())
    ev = flooders(p, n, until=200) + [(0.0, lambda _: p.submit("c", [L5] * 30, lane=Lane.TEXT))]
    keys = msg("vjt", 5, 3, verb="KEYS")
    ev.append((100.0, lambda _: p.submit("vjt", keys, lane=Lane.REACTIVE)))
    left = poll(p, ev, until=200)
    sent = {line: t for t, line in left["vjt"]}
    assert sent[keys[-1]] - 100.0 <= 15.0
    assert sent[keys[-1]] - sent[keys[0]] <= 5.0


def test_reactive_lines_take_turns_by_target():
    # Three targets with reactive messages queued first: a fourth one's goes
    # after one message of each, not after all of theirs. (Two messages: a
    # single one would be fresh, and go first.)
    p = Pacer(fakelag=None)
    for f in ("mal0", "mal1", "mal2"):
        assert p.submit(f, [L2] * 3, lane=Lane.REACTIVE)
    assert p.submit("vjt", [L2] * 2, lane=Lane.REACTIVE)
    order_ = [target for target, _ in p.due(1000.0)]
    assert order_.index("vjt") == 3


def test_reactive_and_text_lines_leave_the_reserve_to_urgent_ones():
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    worst = []
    ev = flooders(p, 2, until=120) + [(0.0, lambda _: p.submit("c", [L6, L5, L2] * 10,
                                                                 lane=Lane.TEXT))]
    poll(p, ev, until=120, after=lambda t, batch: worst.append(lag.bank(t)))
    assert max(worst) <= max(FAKE_LAG_CEILING - RESERVE, 6)


def test_lanes_follow_the_verb_and_the_engines_urgent_set():
    def body(verb, payload=None):
        return framing.fragment(verb, framing.encode_payload(payload or {"v": 1}),
                                own_mask="bot!b@h", target="vjt")[0]
    chal, text, keyreq = body("MSG"), body("MSG"), body("KEYREQ")
    urgent = {framing.parse(chal).msgid: 15.0, framing.parse(keyreq).msgid: None}
    assert lane_of(keyreq, urgent) is Lane.URGENT
    assert lane_of(chal, urgent) is Lane.URGENT
    assert lane_of(body("PKMSG"), {}) is Lane.TEXT
    assert lane_of(text, urgent) is Lane.TEXT
    for verb in ("KEYS", "NACK"):
        line = body(verb)
        assert lane_of(line, {framing.parse(line).msgid: None}) is Lane.REACTIVE   # drawn by a peer
    assert lane_of("not e2e at all", {}) is Lane.TEXT


def test_submit_all_admits_each_message_whole_and_returns_the_refused():
    # A re-key flush can carry several messages: past the per-target cap the
    # later ones are refused, each whole, and reported, not the batch.
    pacer = Pacer(fakelag=FakeLag())
    s = PacedSender(lambda target, line: None, pacer, clock=lambda: 0.0)
    with s._cv:
        for _ in range(DEFAULT_MAX_TEXT_MESSAGES - 2):
            assert pacer.submit("vjt", _message(1), lane=Lane.TEXT)
        flush = [_message(2), _message(1), _message(3), _message(1)]
        refused = s.submit_all([("vjt", b) for m in flush for b in m], {})
        assert refused == [("vjt", framing.parse(m[0]).msgid) for m in flush[2:]]
        queued = [e.line for e in pacer._queues["vjt"][Lane.TEXT]]
        assert queued[-3:] == flush[0] + flush[1]


def test_submit_all_reports_only_refused_messages_that_carried_text():
    # Review H, H4b: a NACK refused past the reactive cap is not a message
    # anyone wrote; the application must not report it as one.
    pacer = Pacer(fakelag=FakeLag())
    s = PacedSender(lambda target, line: None, pacer, clock=lambda: 0.0)
    with s._cv:
        assert pacer.submit("mal", [L2] * DEFAULT_MAX_URGENT, lane=Lane.REACTIVE)
        assert s.submit_all([("mal", b) for b in msg("mal", 2, verb="NACK")], {}) == []


def test_a_chal_passes_its_deadline_from_the_engines_ttl():
    clock = [500.0]
    pacer = Pacer(fakelag=FakeLag())
    s = PacedSender(lambda target, line: None, pacer, clock=lambda: clock[0])
    with s._cv:
        chal = msg("vjt", 6, 5)
        s.submit_all([("vjt", b) for b in chal], {framing.parse(chal[0]).msgid: 15.0})
        assert [e.deadline for e in pacer._queues["vjt"][Lane.URGENT]] == [515.0, 515.0]


def test_room_counts_the_messages_refused_behind_queued_text():
    # Review H, H7a: a refused message was encrypted all the same, so the
    # receiver skips its key when an urgent message overtakes the queue;
    # room() says so before the next one is encrypted.
    p = Pacer(fakelag=FakeLag(), max_backlog=1000.0)
    for _ in range(DEFAULT_MAX_TEXT_MESSAGES - 4):
        assert p.submit("vjt", msg("vjt", 5), lane=Lane.TEXT)
    assert p.room("vjt")
    p.max_backlog = p._text_cost                       # the next ones do not fit
    for _ in range(4):
        assert not p.submit("vjt", msg("vjt", 5), lane=Lane.TEXT)
    assert not p.room("vjt")
    p.max_backlog = 1000.0
    assert not p.room("vjt") and p.room("lucy")
    assert not p.submit("vjt", msg("vjt", 2), lane=Lane.TEXT)    # 28 queued + 4 skipped
    poll(p, [], until=400, t0=1000.0)                   # the queue drains: no gap left
    assert p.pending() == 0 and p.room("vjt") and not p._gap


def test_a_refused_message_with_no_text_queued_leaves_no_gap():
    p = Pacer(fakelag=FakeLag(), max_backlog=8.0)
    assert not p.submit("vjt", msg("vjt", 5, 5), lane=Lane.TEXT)
    assert p.room("vjt") and not p._gap


def test_a_full_text_backlog_leaves_within_sent_memory_with_a_third_of_the_bank():
    # 480 s of text over 12 targets, three flooders holding the reactive
    # budget, the bot talking in channels at a tenth of its bank: text keeps
    # a third of the bank, and a NACK still finds what it refers to.
    from irc_olm.engine import SENT_MEMORY
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    i = 0
    while p.submit(f"u{i % 12}", [L5] * 8, lane=Lane.TEXT):
        i += 1
    assert p._text_cost > p.max_backlog - 40
    talk = [(20.0 * k, lambda t: lag.charge("PRIVMSG #chan :" + "y" * 100, t))
            for k in range(int(SENT_MEMORY / 20))]
    left = poll(p, flooders(p, 3, until=SENT_MEMORY) + talk, until=SENT_MEMORY)
    last = max(lines[-1][0] for target, lines in left.items() if target.startswith("u"))
    assert p._text_cost == 0 and last + 60 <= SENT_MEMORY


def test_sent_max_covers_what_the_bank_lets_out_in_sent_memory():
    # Every line costs at least 2 s of bank: released messages in SENT_MEMORY,
    # plus a full text backlog of one-line messages, fit in SENT_MAX.
    from irc_olm.engine import SENT_MAX, SENT_MEMORY
    from irc_olm.pacing import DEFAULT_MAX_BACKLOG
    assert SENT_MAX >= SENT_MEMORY / 2 + DEFAULT_MAX_BACKLOG / 2


def test_an_idle_target_leaves_no_turn_or_budget_behind():
    p = Pacer(fakelag=None)
    for i in range(50):
        p.submit(f"nick{i}", ["x"], lane=Lane.REACTIVE)
    p.due(1000.0)
    p.due(1000.0 + 61)
    assert p._sent == {} and p._served == {} and not p._spent and p.pending() == 0


def test_turns_stay_bounded_while_a_target_never_served_stays_queued():
    # Review H, H4a: one never-served target in the queue kept every other
    # target's turn for ever.
    p = Pacer(fakelag=FakeLag())
    t = 0.0
    for k in range(1500):
        p.submit(f"n{k}", [L5], lane=Lane.TEXT)
        p.due(t)
        t += 2.0
    assert len([k for k in p._served if k not in p._queues]) <= 10


def test_urgent_goes_before_reactive():
    p = Pacer(fakelag=None)
    for f in ("mal0", "mal1"):
        assert p.submit(f, msg(f, 2, verb="NACK"), lane=Lane.REACTIVE)
    assert p.submit("lucy", msg("lucy", 5, 4), lane=Lane.URGENT)
    assert [target for target, _ in p.due(1000.0)][:2] == ["lucy", "lucy"]


def test_a_keys_after_four_nacks_still_goes_ahead_of_text():
    # What REACTIVE_BUDGET is for: the recovery after a lost session, four
    # messages in flight, each NACKed, then the KEYS of the re-key.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0")
    keys = msg("vjt", 5, 3, verb="KEYS")
    ev = [(10.0 + 0.2 * i, lambda _: p.submit("vjt", msg("vjt", 2, verb="NACK"), lane=Lane.REACTIVE))
          for i in range(4)] + [(12.0, lambda _: p.submit("vjt", keys, lane=Lane.REACTIVE))]
    left = poll(p, ev, until=120)
    sent = {line: t for t, line in left["vjt"]}
    assert sent[keys[-1]] - 12.0 <= 15.0


def test_one_flooder_leaves_text_most_of_the_bank():
    p = Pacer(fakelag=FakeLag())
    ev = flooders(p, 1, until=700)
    ev += [(0.0, lambda _, i=i: p.submit(f"c{i}", [L5] * 30, lane=Lane.TEXT)) for i in range(3)]
    left = poll(p, ev, until=700)
    text = [t for i in range(3) for t, _ in left[f"c{i}"] if 120 <= t < 420]
    assert len(text) * 5 / 5 >= 42                         # s of bank a minute, of 60


def test_an_urgent_message_dropped_past_its_deadline_counts_as_a_gap():
    # It was encrypted: the receiver skips its key like a refused one's.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    for _ in range(DEFAULT_MAX_TEXT_MESSAGES - 1):
        assert p.submit("vjt", msg("vjt", 2), lane=Lane.TEXT)
    assert p.room("vjt")
    lag.add(30, 1000.0)
    assert p.submit("vjt", msg("vjt", 5, 4), lane=Lane.URGENT, deadline=1005.0)
    assert p.due(1006.0) == []
    assert not p.room("vjt")


# --- review I: shares, floors and what reaches the receiver ---------------

from irc_olm.pacing import ACK_MARGIN, FRESH_ALLOWANCE, TEXT_FLOOR, _PAID  # noqa: E402


def completed(left, target, late=0.5):
    """Messages `target`'s receiver completes, each fragment fed `late` s
    after it left into a real Reassembler (a partial message lives 60 s
    after its last fragment)."""
    from irc_olm.reassembly import Assembled, Reassembler
    clock = [0.0]
    r = Reassembler(clock=lambda: clock[0])
    done = 0
    for t, line in left.get(target, []):
        clock[0] = t + late
        frag = framing.parse(line)
        done += frag is not None and isinstance(r.feed("bot", frag), Assembled)
    return done


def humans(p, k, every, until, start=10.0, costs=(5, 4)):
    """`k` pinned humans each addressing the bot a line every `every` s,
    the bot challenging each line: [(lines, (at, fn))]."""
    return [order(p, f"h{i}", start + 0.3 * i + every * j, costs)
            for i in range(k) for j in range(int((until - start) / every))]


def pausing(p, n, until, every=60.5):
    """`n` holders of pinned nicks each drawing one KEYS per `every` s:
    nothing spent inside any minute, so never a flooder by its own budget."""
    return [(0.5 * i + every * k, lambda _, f=f"pz{i}": p.submit(f, msg(f, 5, 3, verb="KEYS"),
                                                                 lane=Lane.REACTIVE))
            for i in range(n) for k in range(int(until / every))]


def text_share(left, targets, start, end):
    """Seconds of bank a minute the text lines to `targets` took in [start, end)."""
    spent = sum(FakeLag.cost(f"PRIVMSG {t} :{line}")
                for t in targets for at, line in left.get(t, []) if start <= at < end)
    return spent * 60 / (end - start)


def test_submit_all_refusing_a_plain_line_still_submits_the_rest():
    # Review I, I4a: the refusal of a body that is not E2E raised, and the
    # rest of the batch, encrypted already, was never queued nor reported.
    pacer = Pacer(fakelag=FakeLag(), max_backlog=10.0)
    s = PacedSender(lambda target, line: None, pacer, clock=lambda: 0.0)
    with s._cv:
        assert pacer.submit("c", [L5, L5], lane=Lane.TEXT)          # the backlog is full
        chal = msg("lucy", 5, 4)
        refused = s.submit_all([("#chan", "hello")] + [("lucy", b) for b in chal],
                               {framing.parse(chal[0]).msgid: 15.0})
        assert refused == []
        assert [e.line for e in pacer._queues["lucy"][Lane.URGENT]] == chal


def test_text_goes_one_message_at_a_time():
    # Review I, I6a: text took turns by line, so every message under way
    # aged at once.
    p = Pacer(fakelag=FakeLag())
    for t in ("u0", "u1"):
        assert p.submit(t, msg(t, 5, 5, 5), lane=Lane.TEXT)
    left = poll(p, [], until=60)
    assert left["u0"][-1][0] < left["u1"][0][0]


@pytest.mark.parametrize("n, lines, nflood", [(12, 7, 0), (6, 13, 3), (12, 7, 3), (8, 10, 6)])
def test_every_text_message_reaches_its_receiver_whole(n, lines, nflood):
    # Review I, I6a: 0 of 6 messages completed with three flooders, the
    # receivers dropping them silently 60 s after a fragment.
    p = Pacer(fakelag=FakeLag())
    for i in range(n):
        assert p.submit(f"u{i}", msg(f"u{i}", *([5] * lines)), lane=Lane.TEXT)
    left = poll(p, flooders(p, nflood, until=1500), until=1500)
    assert [completed(left, f"u{i}") for i in range(n)] == [1] * n


def test_text_gets_a_line_every_text_floor_whatever_goes_ahead_of_it():
    # Four humans chatting with the bot and ten flooders: whatever the
    # budgets let ahead, a message under way still reaches its receiver.
    p = Pacer(fakelag=FakeLag())
    reply = msg("lucy", *([5] * 10))
    ev = [(0.0, lambda _: p.submit("lucy", reply, lane=Lane.TEXT))]
    ev += [e for _, e in humans(p, 4, 6.0, until=600)] + flooders(p, 10, until=600)
    left = poll(p, ev, until=600)
    ts = [t for t, line in left["lucy"] if line in reply]
    assert len(ts) == len(reply) and completed(left, "lucy") == 1
    assert max(b - a for a, b in zip(ts, ts[1:])) <= UNDER_WAY_BOUND


# What the orders leave text of the bank, at most 45 s of each minute, in
# 180 s measured: less the 10 s the bank may hold at either end.
TEXT_LEFT_BY_ORDERS = 60 - URGENT_BUDGET - FRESH_ALLOWANCE - FAKE_LAG_CEILING * 60 / 180


@pytest.mark.parametrize("k, every", [(2, 15.0), (2, 10.0), (3, 15.0), (2, 6.0), (4, 6.0)])
def test_humans_chatting_with_the_bot_leave_text_its_share(k, every):
    # Review I, I2a: URGENT was budgeted per target only, so two humans at
    # four lines a minute each took text to nothing, and a reply under way
    # was lost at its receiver.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    reply = msg("lucy", *([5] * 10))
    ev = [(5.0, lambda _: p.submit("lucy", reply, lane=Lane.TEXT))]
    left = poll(p, ev + [e for _, e in humans(p, k, every, until=200)], until=400)
    share = text_share(left, ("s0", "s1", "lucy"), 10.0, 190.0)
    assert share >= TEXT_LEFT_BY_ORDERS, share
    assert completed(left, "lucy") == 1


@pytest.mark.parametrize("k, every", [(1, 6.0), (2, 6.0), (2, 10.0), (3, 15.0)])
def test_every_chal_sent_can_still_be_answered(k, every):
    # Review I, I2b: the deadline only stopped a CHAL from STARTING late:
    # with two chatty humans 17 of the 20 CHALs sent finished too late for
    # any ACK, 153 s of bank for nothing.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    chats = humans(p, k, every, until=190)
    left = poll(p, [e for _, e in chats], until=220)
    sent = {line: t for target in left for t, line in left[target]}
    started = [(lines, at) for lines, (at, _) in chats if lines[0] in sent]
    assert started
    for lines, at in started:
        assert sent[lines[-1]] <= at + 15.0 - ACK_MARGIN, (at, sent[lines[-1]])


@pytest.mark.parametrize("n, nflood", [(8, 0), (12, 6)])
def test_targets_drawing_once_a_minute_leave_text_its_share(n, nflood):
    # Review I, I3a: a target with nothing spent in the minute went ahead
    # whatever the connection had spent, so one KEYS per nick per 60.5 s
    # took text to nothing at eight nicks. Bounded, the allowance leaves
    # text 30 s of bank a minute (README); unbounded, 22.
    p = Pacer(fakelag=FakeLag())
    ev = pausing(p, n, until=700) + flooders(p, nflood, until=700, start=100)
    ev += [(0.0, lambda _, i=i: p.submit(f"c{i}", [L5] * 30, lane=Lane.TEXT)) for i in range(3)]
    left = poll(p, ev, until=700)
    share = text_share(left, ("c0", "c1", "c2"), 120.0, 420.0)
    assert share >= 28, share


def test_a_keys_after_five_nacks_still_goes_ahead_of_text():
    # Review I, I3c: five messages in flight when a session breaks.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0")
    keys = msg("vjt", 5, 3, verb="KEYS")
    ev = [(10.0 + 0.2 * i, lambda _: p.submit("vjt", msg("vjt", 2, verb="NACK"), lane=Lane.REACTIVE))
          for i in range(5)] + [(12.0, lambda _: p.submit("vjt", keys, lane=Lane.REACTIVE))]
    left = poll(p, ev, until=120)
    sent = {line: t for t, line in left["vjt"]}
    assert sent[keys[-1]] - 12.0 <= 15.0


def test_submit_takes_whole_messages_only():
    # Review I, I3b: half a message submitted lost its open mark, and its
    # deadline then cut its tail after its head had left.
    p = Pacer(fakelag=FakeLag())
    m = msg("vjt", 5, 4)
    with pytest.raises(ValueError):
        p.submit("vjt", m[:1], lane=Lane.URGENT, deadline=1010.0)
    assert p.pending() == 0


@pytest.mark.parametrize("max_lines, window", [(3, 0.1), (1, 0.05)])   # one batch; several
def test_a_failed_write_drops_the_rest_of_its_message_and_says_which(max_lines, window):
    # Review I, I4c: the other fragments still went, for a message its
    # receiver could never complete, and nothing named it.
    import threading
    written, lost, done = [], [], threading.Event()
    m = msg("vjt", 2, 2, 2)

    def send(target, line):
        if line == m[0]:
            raise OSError("socket gone")
        written.append(line)
        if line == "after":
            done.set()

    def on_lost(target, msgid, reason):
        lost.append((target, msgid, reason))

    s = PacedSender(send, Pacer(max_lines=max_lines, window=window, fakelag=None), on_lost=on_lost)
    s.submit("vjt", m, lane=Lane.TEXT)
    s.submit("vjt", ["after"], lane=Lane.TEXT)
    assert done.wait(2)
    assert written == ["after"]
    assert lost == [("vjt", framing.parse(m[0]).msgid, "send-failed")]


def test_an_urgent_message_dropped_too_late_is_reported_to_the_application():
    # Review I, I4e: the drop was a log line only.
    import threading
    lost, done = [], threading.Event()
    lag = FakeLag()
    clock = [1000.0]
    lag.add(30, 1000.0)

    def on_lost(target, msgid, reason):
        lost.append((target, msgid, reason))
        done.set()

    s = PacedSender(lambda target, line: None, Pacer(fakelag=lag), clock=lambda: clock[0],
                    on_lost=on_lost)
    chal = msg("vjt", 5, 4)
    s.submit_all([("vjt", b) for b in chal], {framing.parse(chal[0]).msgid: 15.0})
    assert done.wait(2)
    assert lost == [("vjt", framing.parse(chal[0]).msgid, "late")]


def test_bad_input_fails_in_the_caller_and_a_dead_thread_is_never_silent():
    # Review I, I4d: a cost computed on the thread killed it, and submit()
    # kept saying True for ever after.
    calls = [0]

    def clock():
        calls[0] += 1
        if calls[0] > 2:
            raise RuntimeError("clock broke")
        return 1000.0

    s = PacedSender(lambda target, line: None, Pacer(fakelag=FakeLag()), clock=clock)
    with pytest.raises(UnicodeEncodeError):
        s.submit("vjt", ["\ud800"], lane=Lane.REACTIVE)
    assert s._thread.is_alive()
    assert s.submit("vjt", ["x"], lane=Lane.TEXT)     # wakes it: the clock then breaks
    s._thread.join(2)
    assert not s._thread.is_alive()
    with pytest.raises(RuntimeError):
        s.submit("vjt", ["hello"], lane=Lane.TEXT)


def test_the_floor_fires_at_the_instant_the_wakeup_names():
    # At this t0, (t0 + 20) - t0 rounds below 20: counting elapsed time
    # instead missed the instant the wakeup named, and the text went at the
    # KEYS's instant, 3 s late. (Two KEYS: a single one would be fresh, and
    # go ahead of the starved text.)
    t0 = 1017.6509643838564
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    lag.add(40, t0)                              # the application's own lines
    for _ in range(2):
        assert p.submit("vjt", msg("vjt", 5, 3, verb="KEYS"), lane=Lane.REACTIVE)
    assert p.submit("c", [L2], lane=Lane.TEXT)   # 2 s: room at a bank of 3
    released, now = {}, t0
    assert p.due(now) == []
    while p.pending():
        now = p.next_wakeup(now)
        released.update({line: now for _, line in p.due(now)})
    assert released[L2] == t0 + 37.0


def test_text_arriving_under_a_full_load_still_starts_within_the_floor():
    # The floor's clock starts when text arrives in an empty queue.
    p = Pacer(fakelag=FakeLag())
    reply = msg("lucy", 5, 5, 5)
    ev = [e for _, e in humans(p, 4, 6.0, until=400)] + flooders(p, 10, until=400)
    ev.append((120.0, lambda _: p.submit("lucy", reply, lane=Lane.TEXT)))
    left = poll(p, ev, until=400)
    ts = [t for t, line in left.get("lucy", []) if line in reply]
    assert len(ts) == 3 and ts[0] - 120.0 <= TEXT_FLOOR + FAKE_LAG_CEILING + DEFAULT_WINDOW


def test_text_arriving_after_a_quiet_spell_does_not_count_as_starved():
    # Text sent long ago must not start the floor's clock for the next: the
    # new text waits behind a KEYS as any text does. (Two KEYS: a single one
    # would be fresh, and go first even past the floor.)
    p = Pacer(fakelag=FakeLag())
    assert p.submit("c", [L2], lane=Lane.TEXT)
    assert p.due(1000.0) == [("c", L2)]
    for _ in range(2):
        assert p.submit("vjt", msg("vjt", 5, 3, verb="KEYS"), lane=Lane.REACTIVE)
    assert p.submit("c", [L2], lane=Lane.TEXT)
    assert p.due(2000.0)[0][0] == "vjt"


def test_a_chal_dearer_than_the_bank_is_dropped_once_its_tail_would_be_late():
    # Its last line waits for the bank: a 14 s CHAL at an empty bank leaves
    # its tail 4 s after its head, so it must start 4 s earlier than a short
    # one. The window holds it until 1010, the bank is empty from 1006, and
    # its tail must leave by 1013.
    p = Pacer(window=10.0, fakelag=FakeLag())
    for t in (1000.0, 1001.0, 1002.0):
        assert p.submit("vjt", [L2], lane=Lane.URGENT)
        assert len(p.due(t)) == 1                  # the window opens at 1010
    chal = msg("vjt", 5, 5, 4)
    assert p.submit("vjt", chal, lane=Lane.URGENT, deadline=1013.0 + ACK_MARGIN)
    assert p.due(1006.0) == [] and p.next_wakeup(1006.0) == 1009.0
    assert p.due(1009.0) == [] and p.take_dropped() == [("vjt", framing.parse(chal[0]).msgid)]


def test_room_keeps_a_full_line_free_in_the_backlog():
    # Review I, I6c: room() said yes to a one-line message the backlog
    # then refused.
    p = Pacer(fakelag=FakeLag(), max_backlog=10.0)
    assert p.submit("c", [L5, L2], lane=Lane.TEXT)       # 7 s of 10
    assert not p.room("vjt")
    assert not p.submit("vjt", msg("vjt", 6), lane=Lane.TEXT)


def test_dropping_the_rest_of_a_message_frees_its_text_and_its_turn():
    # What PacedSender does when a line fails to write: the text the rest
    # held is freed, another text message may start, and the receiver will
    # skip the lost message's key when the next one reaches it.
    p = Pacer(max_lines=1, fakelag=None)
    m, n, other = msg("vjt", 5, 5, 5), msg("vjt", 5), msg("lucy", 5, 5)
    for target, lines in (("vjt", m), ("vjt", n), ("lucy", other)):
        assert p.submit(target, lines, lane=Lane.TEXT)
    assert p.due(1000.0) == [("vjt", m[0])]              # m under way, lucy waits
    p.drop("vjt", framing.parse(m[0]).msgid)
    assert p._text_cost == 15 and p._gap == {"vjt": 1}
    assert p.due(1000.0) == [("lucy", other[0])]


# --- review J ---------------------------------------------------------------


@pytest.mark.parametrize("lane, costs, verb, bank", [(Lane.REACTIVE, (5, 3), "KEYS", 0),
                                                     (Lane.URGENT, (5, 4), "MSG", 3)])
def test_a_failed_write_of_an_order_or_a_keys_drops_the_rest_and_the_thread_lives(lane, costs, verb,
                                                                                  bank):
    # Review J, J1a: dropping the rest of a message for a target with no
    # text queued raised KeyError, and the thread died with it.
    import threading
    lag, written, lost, done = FakeLag(), [], [], threading.Event()
    clock = [1000.0]
    lag.add(bank, 1000.0)
    m = msg("vjt", *costs, verb=verb)

    def send(target, line):
        if line == m[0]:
            raise OSError("socket gone")
        written.append(line)

    def on_lost(target, msgid, reason):
        lost.append((target, msgid, reason))
        done.set()

    s = PacedSender(send, Pacer(fakelag=lag), clock=lambda: clock[0], on_lost=on_lost)
    s.submit("vjt", m, lane=lane)
    assert done.wait(2)
    clock[0] = 1100.0                                  # the bank has long had room
    assert s.submit("vjt", ["after"], lane=Lane.TEXT)
    s._thread.join(0.3)
    assert s._thread.is_alive() and m[1] not in written
    assert lost == [("vjt", framing.parse(m[0]).msgid, "send-failed")]


def test_an_on_lost_that_raises_is_logged_and_the_rest_still_reported():
    # Review J, J6a: the application's callback failing killed the thread
    # and ate the losses after it.
    import threading
    lag, calls, done = FakeLag(), [], threading.Event()
    lag.add(30, 1000.0)

    def on_lost(target, msgid, reason):
        calls.append(target)
        if len(calls) == 2:
            done.set()
        raise RuntimeError("callback broke")

    s = PacedSender(lambda target, line: None, Pacer(fakelag=lag), clock=lambda: 1000.0,
                    on_lost=on_lost)
    for nick in ("vjt", "lucy"):
        chal = msg(nick, 5, 4)
        s.submit_all([(nick, b) for b in chal], {framing.parse(chal[0]).msgid: 15.0})
    assert done.wait(2)
    assert sorted(calls) == ["lucy", "vjt"] and s._thread.is_alive()


def test_submit_refuses_lines_that_are_not_whole_messages_one_after_another():
    # Review J, J1b: only the last line was checked.
    p = Pacer(fakelag=FakeLag())
    a, b = msg("vjt", 5, 4), msg("vjt", 5)
    with pytest.raises(ValueError):
        p.submit("vjt", [a[0]] + b, lane=Lane.URGENT)
    assert p.pending() == 0
    assert p.submit("vjt", a + b, lane=Lane.URGENT)


def test_one_order_under_way_at_a_time():
    # Review J, J5a: an order whose target's window held its next line let
    # another start; the two took turns and both finished past the time an
    # ACK could still come back.
    p = Pacer(fakelag=FakeLag())
    for _ in range(2):
        assert p.submit("h0", msg("h0", 2, verb="NACK"), lane=Lane.REACTIVE)
    a, b = msg("h0", 6, 6, 4), msg("h3", 5, 5, 4)
    ev = [(1.0, lambda now: p.submit("h0", a, lane=Lane.URGENT, deadline=now + 15.0)),
          (1.5, lambda now: p.submit("h3", b, lane=Lane.URGENT, deadline=now + 15.0))]
    left = poll(p, ev, until=60)
    sent = {line: t for target in left for t, line in left[target]}
    assert sent[a[-1]] <= 1.0 + 15.0 - ACK_MARGIN
    if b[0] in sent:
        assert sent[b[0]] >= sent[a[-1]] and sent[b[-1]] <= 1.5 + 15.0 - ACK_MARGIN


# Between two lines of a text message under way, at worst: the floor (20 s),
# the rest of one order under way (two lines, 10 s of bank), the bank
# emptying for the text line (10 s), and the target's window (6 s). The
# README's figure, as a literal: a longer floor must fail the tests.
UNDER_WAY_BOUND = 46


def test_a_message_under_way_keeps_inside_the_receivers_minute_behind_orders():
    # Review J, J3a: two orders under way at the floor went first, then the
    # bank had to empty for the text line: 58 s between two fragments. The
    # NACKs fill h1's window, so its CHAL's second line waits; an ACK to h2
    # comes just before the floor.
    p = Pacer(fakelag=FakeLag())
    reply = msg("lucy", *([6] * 14))
    nacks = [msg("h1", 2, verb="NACK") for _ in range(2)]
    a, b = msg("h1", 6, 6, 4), msg("h2", 5, 5, 4)
    ev = [(0.0, lambda _: p.submit("lucy", reply, lane=Lane.TEXT)),
          (12.5, lambda _: p.submit("p1", msg("p1", 5, 3, verb="KEYS"), lane=Lane.REACTIVE)),
          (12.5, lambda _: p.submit("p2", msg("p2", 5, 3, verb="KEYS"), lane=Lane.REACTIVE)),
          (12.5, lambda _: p.submit("p3", msg("p3", 2, verb="NACK"), lane=Lane.REACTIVE)),
          (35.5, lambda _: [p.submit("h1", n, lane=Lane.REACTIVE) for n in nacks]),
          (36.1, lambda _: p.submit("h2", b, lane=Lane.URGENT))]

    def after(now, batch):
        if any(line == nacks[-1][0] for _, line in batch):
            p.submit("h1", a, lane=Lane.URGENT, deadline=now + 15.0)
    left = poll(p, ev, until=400, after=after)
    ts = [t for t, _ in left["lucy"]]
    assert len(ts) == len(reply) and completed(left, "lucy") == 1
    assert max(y - x for x, y in zip(ts, ts[1:])) <= UNDER_WAY_BOUND


from itertools import count  # noqa: E402

from irc_olm.engine import KEYREQ_RETRY  # noqa: E402


def window_peak(left, targets, window=60.0):
    """The most bank the lines to `targets` took in any `window` seconds,
    on poll()'s rounded times counted in hundredths: a line `window` s old
    is out of it, as in the pacer's budgets."""
    rel = sorted((round(t * 100), FakeLag.cost(f"PRIVMSG {tg} :{line}"))
                 for tg in targets for t, line in left.get(tg, []))
    return max((sum(c for u, c in rel[:i + 1] if u + window * 100 > t)
                for i, (t, _) in enumerate(rel)), default=0)


def chatty(p, k, every, seed, until):
    """`k` pinned humans at random phases, each addressing the bot about
    every `every` s with orders of random shapes: [(lines, (at, fn))]."""
    rng = random.Random(seed)
    chats = []
    for i in range(k):
        start, gap = rng.uniform(5, 25), every * rng.uniform(0.8, 1.2)
        chats += [order(p, f"h{i}", start + gap * j, rng.choice([(5, 4), (6, 5), (6, 3)]))
                  for j in range(int((until - start) / gap))]
    return chats


@pytest.mark.parametrize("k, every, seed", [(1, 2.0, 0), (6, 20.0, 0), (6, 9.0, 5), (6, 7.0, 1)])
def test_orders_never_take_more_than_their_budget_in_any_minute(k, every, seed):
    # Review J, J4b: the budget was checked on a message's first line only,
    # so an order of 6 + 5 s started at 30 s spent ended at 41, and the
    # orders took up to 50 s of a minute.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    left = poll(p, [e for _, e in chatty(p, k, every, seed, until=260)], until=260)
    peak = window_peak(left, [f"h{i}" for i in range(k)])
    # The README's figures, as literals: a larger allowance must fail.
    assert peak <= (45 if k > 1 else 36), peak
    share = text_share(left, ("s0", "s1"), 60.0, 240.0)
    assert share >= TEXT_LEFT_BY_ORDERS, share


@pytest.mark.parametrize("at", [100.0 + 0.75 * i for i in range(0, 40, 3)])
def test_an_honest_keys_leaves_before_its_asker_asks_again_behind_chatting_humans(at):
    # Review J, J4a: orders within budget and starved text both went ahead
    # of a KEYS, which needs an empty bank for its 5 s line: with four
    # humans addressing the bot every 6 s the KEYS waited up to 50 s, and
    # the asker re-asks at KEYREQ_RETRY.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    keys = msg("vjt", 5, 3, verb="KEYS")
    ev = [e for _, e in humans(p, 4, 6.0, until=at + 60)]
    ev += [(at, lambda _: p.submit("vjt", keys, lane=Lane.REACTIVE))]
    left = poll(p, ev, until=at + 60)
    sent = {line: t for t, line in left.get("vjt", [])}
    assert sent.get(keys[-1], math.inf) - at <= KEYREQ_RETRY - 5, sent


def test_a_keys_for_a_peer_that_drew_nothing_goes_ahead_of_older_ones():
    # Review J, J4a: a target that drew nothing in the minute only had its
    # cap raised; its KEYS queued behind every older KEYS of targets never
    # served, first come first served. (Eight nicks each drawing one KEYS a
    # minute are another matter: each is fresh too, and together they draw
    # twice what the budget lets ahead of text: the README's known limit.)
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    lag.add(10, 0.0)                             # the application's own lines
    mals = ("mal0", "mal1", "mal2")
    for f in mals:
        for _ in range(2):
            assert p.submit(f, msg(f, 5, 3, verb="KEYS"), lane=Lane.REACTIVE)
    keys = msg("vjt", 5, 3, verb="KEYS")
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    left = poll(p, [], until=120)
    assert [line for _, line in left["vjt"]] == keys
    assert left["vjt"][-1][0] <= min(left[f][0][0] for f in mals)


def released_by_wakeups(p, now, events=()):
    """Drive `p` from `now` at exactly the instants next_wakeup names, and at
    those of `events` [(t, fn(now))], until nothing is pending and no event
    is left: {line: (when it left, its place in the order)}."""
    released, n, ev = {}, count(), sorted(events, key=lambda e: e[0])
    while p.pending() or ev:
        wake = p.next_wakeup(now) if p.pending() else None
        if ev and (wake is None or ev[0][0] <= wake):
            now = ev[0][0]
            while ev and ev[0][0] <= now:
                ev.pop(0)[1](now)
        else:
            now = wake
        released.update({line: (now, next(n)) for _, line in p.due(now)})
    return released


@pytest.mark.parametrize("hold_at, at", [(11.0, 19.5), (21.0, 29.5)])
def test_an_order_started_just_before_the_floor_leaves_text_inside_the_bound(hold_at, at):
    # The case behind UNDER_WAY_BOUND: a fresh KEYS, NACKs and an order hold
    # the text back, then a three-line order starts just before the floor;
    # the text line waits for its rest and for the bank to empty. 39 s with
    # the 20 s floor; with a 30 s one, 49 (the order at 29.5). An order
    # landing after the floor goes after the text, too late to be answered.
    p = Pacer(fakelag=FakeLag())
    reply = msg("lucy", 6, 6, 6)
    ev = [(0.0, lambda _: p.submit("lucy", reply, lane=Lane.TEXT)),
          (0.5, lambda _: p.submit("p3", msg("p3", 5, 3, verb="KEYS"), lane=Lane.REACTIVE))]
    ev += [(0.5, lambda _, f=f: p.submit(f, msg(f, 2, verb="NACK"), lane=Lane.REACTIVE))
           for f in ("p1", "p2") for _ in range(5)]
    big, last = order(p, "h9", at, (6, 6, 4))
    ev += [order(p, "h1", hold_at, (5, 4))[1], last]
    left = poll(p, ev, until=200)
    ts = [t for t, _ in left["lucy"]]
    assert len(ts) == 3 and completed(left, "lucy") == 1
    if at < TEXT_FLOOR:
        assert [line for _, line in left["h9"]] == big
    assert max(y - x for x, y in zip(ts, ts[1:])) <= UNDER_WAY_BOUND


def test_text_not_started_waits_for_the_orders_even_past_the_floor():
    # Past the floor only a message under way goes ahead of the orders: a
    # new one would hold a CHAL back for a line nobody is waiting on yet.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    lag.add(30, 0.0)                             # the application's own lines
    assert p.submit("c", [L2], lane=Lane.TEXT)
    assert p.due(0.0) == []                      # the floor's clock starts
    chal = msg("h0", 5, 4)
    assert p.submit("h0", chal, lane=Lane.URGENT, deadline=100.0)
    released = released_by_wakeups(p, 0.0)
    assert released[chal[-1]] < released[L2]


def test_text_under_way_past_the_floor_goes_before_a_fresh_keys():
    # UNDER_WAY_BOUND counts one order ahead of a starved message under way,
    # not a KEYS: a fresh peer's KEYS waits for the text line.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    reply = msg("lucy", 5, 5)
    assert p.submit("lucy", reply, lane=Lane.TEXT)
    assert p.due(0.0) == [("lucy", reply[0])]
    lag.add(30, 0.5)                             # the application's own lines
    keys = msg("vjt", 5, 3, verb="KEYS")
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    released = released_by_wakeups(p, 0.5)
    assert released[reply[-1]] < released[keys[0]]


def test_fresh_peers_and_a_chatty_human_together_still_leave_text_its_floor():
    # Review K, K2a: a fresh peer's KEYS or NACK went ahead of starved text
    # as the orders did, and the two together could take more than the
    # bank: one human addressing the bot every 6 s and fifteen pinned nicks
    # each drawing a NACK every 75 s left text nothing for 13 minutes.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    reply = msg("lucy", *([5] * 10))
    ev = [(5.0, lambda _: p.submit("lucy", reply, lane=Lane.TEXT))]
    ev += [e for _, e in humans(p, 1, 6.0, until=420)]
    ev += [(2.0 + 5.0 * i + 75.0 * k, lambda _, f=f"pz{i}": p.submit(f, msg(f, 2, verb="NACK"),
                                                                       lane=Lane.REACTIVE))
           for i in range(15) for k in range(6)]
    left = poll(p, ev, until=420)
    ts = [t for t, line in left.get("lucy", []) if line in reply]
    assert len(ts) == len(reply) and completed(left, "lucy") == 1
    share = text_share(left, ("s0", "s1", "lucy"), 60.0, 420.0)
    assert share >= 8, share


@pytest.mark.parametrize("t0", [30.0, 31.5, 33.0, 34.5])
@pytest.mark.parametrize("offset", [-2.0, -1.0, 0.0, 1.0, 2.0])
@pytest.mark.parametrize("costs", [(5, 5, 4), (6, 6, 4), (6, 5)])
def test_a_chal_is_not_held_behind_a_fresh_peers_keys(t0, offset, costs):
    # Review K, K2c: a fresh peer's KEYS queued when a CHAL arrived went
    # first and waited for an empty bank: behind a stream of text up to two
    # thirds of the first challenges were dropped, too late to be answered.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    keys = msg("pz0", 5, 3, verb="KEYS")
    lines, chal = order(p, "lucy", t0 + offset, costs)
    left = poll(p, [(t0, lambda _: p.submit("pz0", keys, lane=Lane.REACTIVE)), chal], until=90)
    assert [line for _, line in left.get("lucy", [])] == lines
    assert [line for _, line in left["pz0"]] == keys


def test_an_order_under_way_finishes_before_text_past_the_floor():
    # Past the floor a text message under way goes next after an order
    # under way, not before it: cut in two, the order would be late. The
    # application keeps the bank up: the CHAL starts at 18 s, the floor is
    # at 20, the CHAL's second line can leave at 22, the text's at 28.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    reply = msg("lucy", 5, 5)
    assert p.submit("lucy", reply, lane=Lane.TEXT)
    assert p.due(0.0) == [("lucy", reply[0])]
    lag.add(18, 0.0)                             # the application's own lines
    chal = msg("h0", 5, 4)
    assert p.submit("h0", chal, lane=Lane.URGENT, deadline=32.0)
    released = released_by_wakeups(p, 0.0)
    assert released[chal[0]][0] < TEXT_FLOOR <= released[chal[-1]][0]
    assert released[chal[-1]][1] < released[reply[-1]][1]


def test_a_fresh_keys_waits_its_patience_then_goes_ahead_of_the_orders_queued_after():
    # Review K, K2c: a fresh peer's KEYS waits 8 s (FRESH_PATIENCE, from
    # the due() that first sees it) behind the orders not yet started, so a
    # CHAL arriving meanwhile still goes first; then it goes ahead of the
    # orders queued after that instant, at their bank limit. A KEYREQ every
    # 2 s keeps the bank up: the KEYS's 5 s line never fits under the
    # reserve, and leaves at 8 s. The README's figure, as a literal: another
    # patience must fail.
    p = Pacer(fakelag=FakeLag())
    keyreqs = [msg(f"h{i}", 3, verb="KEYREQ") for i in range(12)]
    keys = msg("vjt", 5, 3, verb="KEYS")
    times = [0.0] + [0.5 + 2.0 * i for i in range(1, 12)]
    ev = [(times[0], lambda _: p.submit("h0", keyreqs[0], lane=Lane.URGENT)),
          (0.0, lambda _: p.submit("vjt", keys, lane=Lane.REACTIVE))]
    ev += [(times[i], lambda _, i=i: p.submit(f"h{i}", keyreqs[i], lane=Lane.URGENT))
           for i in range(1, 12)]
    released = released_by_wakeups(p, 0.0, ev)
    at, place = released[keys[0]]
    assert 8.0 <= at <= 8.0 + 3.0, at
    for i, k in enumerate(keyreqs):
        assert (released[k[0]][1] < place) == (times[i] < 8.0), (i, released[k[0]], at)


def test_a_fresh_keys_that_waited_takes_the_reserve_and_no_keys_under_way_holds_it_back():
    # Review K: a KEYS under way to a target that is not fresh (another one
    # queued) ranks below the orders and text past the floor, and keeps the
    # reserve, so it must not hold the lane: KEYS and NACKs to different
    # targets interleave. The application keeps the bank at about 5 s for
    # 20 s: mal0's 3 s tail cannot go, and an honest peer's KEYS, fresh,
    # goes once its patience is out, taking the reserve.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    mal = [msg("mal0", 5, 3, verb="KEYS") for _ in range(2)]
    for m in mal:
        assert p.submit("mal0", m, lane=Lane.REACTIVE)
    assert p.due(0.0) == [("mal0", mal[0][0])]
    keys = msg("vjt", 5, 3, verb="KEYS")
    ev = [(0.5, lambda _: p.submit("vjt", keys, lane=Lane.REACTIVE))]
    ev += [(0.5 + i, lambda now: lag.add(1, now)) for i in range(20)]   # the application's
    released = released_by_wakeups(p, 0.0, ev)
    assert released[keys[0]][0] <= 0.5 + 8.0 + 1.0
    assert released[keys[0]][1] < released[mal[0][-1]][1]
    assert released[keys[-1]][0] - 0.5 <= KEYREQ_RETRY - 5


def paid(p):
    return sum(c for _, c in p._spent.get((_PAID, Lane.URGENT), ()))


def test_a_fresh_answer_pays_for_what_of_it_goes_ahead_once_and_nothing_else():
    # Review K, K2a: what goes ahead of the orders or of text past the
    # floor is paid for, a fresh peer's KEYS included: all the rest of it
    # when it first goes ahead, once. Review L, L4a: one that goes with
    # nothing to go ahead of pays nothing.
    p = Pacer(fakelag=FakeLag())
    keys = msg("vjt", 5, 3, verb="KEYS")
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(0.0) == [("vjt", keys[0])]      # nothing ahead of it
    released_by_wakeups(p, 0.0)
    assert paid(p) == 0 and not p._paid and not p._fresh and not p._reactive_at
    # Its rest, held past its patience, goes ahead at the orders' limit and
    # pays for itself: at 8 s, a bank of 7 (room under 10, not under 5).
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(0.0) == [("vjt", keys[0])]
    lag.add(10, 0.0)                             # the application's own lines
    released = released_by_wakeups(p, 0.0)
    assert released[keys[-1]][0] == 8.0 and paid(p) == 3
    # Held before its first line, it pays for all of it, once.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    lag.add(12, 0.0)                             # the application's own lines
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(0.0) == []                      # the patience's clock starts
    released = released_by_wakeups(p, 0.0)
    assert released[keys[0]][0] == 8.0 and paid(p) == 8
    assert released[keys[-1]][0] == 10.0         # paid for: at the orders' limit
    assert not p._paid and not p._fresh and not p._reactive_at and not p._cutoff


def test_a_failed_write_of_a_fresh_answer_leaves_nothing_paid_behind():
    p = Pacer(fakelag=FakeLag())
    keys = msg("vjt", 5, 3, verb="KEYS")
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(0.0) == [("vjt", keys[0])]
    p.drop("vjt", framing.parse(keys[0]).msgid)
    assert p.pending() == 0 and not p._open and not p._paid and not p._fresh
    assert not p._reactive_at and not p._cutoff


def test_a_fresh_keys_goes_ahead_of_text_past_the_floor_only_within_the_orders_budget():
    # Review K, K2a: a fresh peer's KEYS that has waited goes ahead of text
    # past the floor only if the orders' budget (36 s, 45 with the
    # allowance) has room for all of it. Five orders took 45 s by 35 s, so
    # it waits for the first to age out, at 60 s, and the wakeup names that
    # instant; the text's 6 s lines need an empty bank, at 62 s.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    assert p.submit("lucy", [L6] * 3, lane=Lane.TEXT)
    for i in range(5):
        assert p.submit(f"h{i}", msg(f"h{i}", 5, 4), lane=Lane.URGENT, deadline=1000.0)
    keys = msg("vjt", 5, 3, verb="KEYS")
    ev = [(30.0, lambda _: p.submit("vjt", keys, lane=Lane.REACTIVE)),
          (35.5, lambda now: lag.add(17, now))]  # the application's own lines
    released = released_by_wakeups(p, 0.0, ev)
    assert released[keys[0]][0] == 60.0


def test_past_both_floors_a_keys_under_way_goes_before_text_and_a_fresh_one_waiting():
    # Review K: a fresh peer's KEYS within its patience does not go ahead of
    # text past the floor, and a KEYS under way goes before it: none is cut
    # in two for a new one. Review L, L2a: once its last line left
    # TEXT_FLOOR ago, the rest of a KEYS under way to a target that is not
    # fresh gets the floor too, or its receiver drops it. Both floors fall
    # at 20 s here: the KEYS's 3 s line goes first, at a bank of 5 (it
    # takes the reserve), then the text's 2 s line, once the bank is down
    # to 3, at 25 s.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    mal = [msg("mal0", 5, 3, verb="KEYS") for _ in range(2)]   # two: not fresh
    for m in mal:
        assert p.submit("mal0", m, lane=Lane.REACTIVE)
    assert p.submit("lucy", [L2], lane=Lane.TEXT)
    assert p.due(0.0) == [("mal0", mal[0][0])]
    lag.add(20, 0.0)                             # the application's own lines
    keys = msg("vjt", 5, 3, verb="KEYS")
    ev = [(21.5, lambda _: p.submit("vjt", keys, lane=Lane.REACTIVE))]
    released = released_by_wakeups(p, 0.0, ev)
    assert released[mal[0][-1]][0] == TEXT_FLOOR and released[L2][0] == TEXT_FLOOR + 5.0
    assert released[L2][1] < released[keys[0]][1]


def test_past_the_floor_text_goes_before_a_keys_under_way_short_of_its_own():
    # Review L, L2a: the floor of a KEYS under way runs from its own last
    # line. Text's runs from -5 s, mal0's KEYS starts at 5 s (two queued:
    # not fresh), and the application keeps the bank between 2.5 and 3.5 s:
    # the text's 2 s line goes at its floor, 15 s, the KEYS's 3 s line at
    # its own, 25 s, taking the reserve.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    lag.add(10, -5.0)                            # the application's own lines
    assert p.submit("lucy", [L2], lane=Lane.TEXT)
    mal = [msg("mal0", 5, 3, verb="KEYS") for _ in range(2)]
    for m in mal:
        assert p.submit("mal0", m, lane=Lane.REACTIVE)
    assert p.due(-5.0) == []                     # the floor's clock starts
    ev = [(7.5 + i, lambda now: lag.add(1, now)) for i in range(30)]   # the application's
    released = released_by_wakeups(p, -5.0, ev)
    assert released[mal[0][0]][0] == 5.0
    assert released[L2][0] == 15.0 and released[mal[0][-1]][0] == 25.0


def test_a_fresh_keys_started_with_nothing_ahead_waits_behind_text_past_the_floor():
    # Review L, L4a: a fresh peer's KEYS that started with nothing to go
    # ahead of paid nothing, so its rest does not go ahead of text past the
    # floor until it has waited and pays for it. Its first line (2 s) leaves
    # at 17 s at a bank of 3, the floor is at 20, the text's 6 s line needs
    # an empty bank (22 s), the KEYS's patience runs out at 25.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    assert p.submit("lucy", [L6], lane=Lane.TEXT)
    lag.add(20, 0.0)                             # the application's own lines
    assert p.due(0.0) == []
    keys = msg("ann", 2, 3, verb="KEYS")
    ev = [(17.0, lambda _: p.submit("ann", keys, lane=Lane.REACTIVE))]
    released = released_by_wakeups(p, 0.0, ev)
    assert released[keys[0]][0] == 17.0 and released[L6][0] == 22.0
    assert released[keys[-1]][0] == 17.0 + 8.0 and paid(p) == 3


def test_the_patience_ends_at_the_instant_the_wakeup_names():
    # At this t0, (t0 + 8) - t0 rounds below 8: counting elapsed time
    # instead missed the instant the wakeup named, and the KEYS went 4.5 s
    # late, when the text past the floor ahead of it could leave. (The
    # text's 6 s line needs an empty bank; the KEYS's, at the orders'
    # limit, one of 5.)
    t0 = 1018.1631072945817
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    assert p.submit("lucy", [L6], lane=Lane.TEXT)
    lag.add(24.5, t0 - 12.0)                     # the application's own lines
    assert p.due(t0 - 12.0) == []                # the floor's clock starts
    keys = msg("vjt", 5, 3, verb="KEYS")
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(t0) == []
    released = released_by_wakeups(p, t0)
    assert released[keys[0]][0] == t0 + 8.0


@pytest.mark.parametrize("first_contact", [False, True])
@pytest.mark.parametrize("d", [0.5 * i for i in range(0, 120, 7)])
def test_four_orders_a_minute_and_a_first_contact_elsewhere_drop_no_order(first_contact, d):
    # Review L, L4a: a fresh peer's KEYS was charged to the orders' budget
    # even when it went ahead of nothing, so four orders a minute (or a
    # first contact and two) plus one first contact anywhere in the minute
    # put an order past the budget, behind the text, and dropped it.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    ev = [(5.0, lambda now: p.submit("lucy", msg("lucy", 2, verb="KEYREQ"),
                                     lane=Lane.URGENT))] if first_contact else []
    chals = ([order(p, "lucy", 7.0, (5, 5, 4) if first_contact else (5, 4))]
             + [order(p, "lucy", t, (5, 4)) for t in (22.0, 37.0, 52.0)[:2 if first_contact else 3]])
    ev += [(d, lambda _: p.submit("pz0", msg("pz0", 5, 3, verb="KEYS"), lane=Lane.REACTIVE))]
    left = poll(p, ev + [e for _, e in chals], until=90)
    sent = {line: t for t, line in left["lucy"]}
    for lines, (at, _) in chals:
        assert lines[-1] in sent, (at, d)


@pytest.mark.parametrize("n", [4, 16])
def test_fresh_peers_drawing_nacks_leave_a_chatting_humans_orders_their_budget(n):
    # Review L, L4a: every fresh peer's NACK was charged to the orders'
    # budget, so pinned nicks each drawing one NACK every 75 s cut one
    # human's four orders a minute down to one, three of every four
    # challenges dropped.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    chats = humans(p, 1, 15.0, until=300)
    ev = [e for _, e in chats]
    ev += [(2.0 + 75.0 / n * i + 75.0 * k, lambda _, f=f"pz{i}": p.submit(
               f, msg(f, 2, verb="NACK"), lane=Lane.REACTIVE))
           for i in range(n) for k in range(4)]
    ev += [(20.0 * i, lambda _: [p.submit(s, [L6] * 4, lane=Lane.TEXT) for s in ("s0", "s1")])
           for i in range(1, 15)]
    left = poll(p, ev, until=300)
    sent = {line for t, line in left.get("h0", [])}
    assert all(lines[-1] in sent for lines, (at, _) in chats if at < 280), n


@pytest.mark.parametrize("a", [3.0, 5.0, 7.0, 7.9])
@pytest.mark.parametrize("costs", [(5, 4), (6, 5)])
def test_a_chal_queued_while_a_fresh_keys_waits_keeps_its_place_on_the_bank(a, costs):
    # Review L, L4b: a CHAL queued during a fresh peer's patience went first
    # only if it could leave before the patience ran out: one waiting on the
    # bank was overtaken at that instant by the KEYS's 8 s and dropped. The
    # application's lines keep the bank up so that the CHAL cannot start
    # before the KEYS's patience runs out (8 s).
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    keys = msg("pz0", 5, 3, verb="KEYS")
    chal = msg("lucy", *costs)
    ev = [(0.0, lambda _: p.submit("pz0", keys, lane=Lane.REACTIVE)),
          (0.0, lambda now: lag.add(19 - costs[0], now)),   # the CHAL's room at 9 s
          (a, lambda now: p.submit("lucy", chal, lane=Lane.URGENT, deadline=now + 15.0))]
    released = released_by_wakeups(p, 0.0, ev)
    assert all(line in released for line in chal), (a, costs)
    assert released[chal[0]][0] > 8.0
    assert released[chal[-1]][1] < released[keys[0]][1]


@pytest.mark.parametrize("seed, at", [(0, 112.5), (1, 100.0), (2, 107.5), (4, 100.0)])
def test_a_keys_under_way_reaches_its_receiver_behind_chatting_humans(seed, at):
    # Review L, L2a: the rest of a KEYS under way to a target that is not
    # fresh ranked below the orders and text past the floor, with no floor
    # of its own: behind seven humans chatting and a long message under
    # way, its second line left up to 75 s after its first, and its
    # receiver, who keeps a partial message 60 s, never completed it. The
    # recovery after a lost session: a NACK, then the KEYS 5 s later.
    p = Pacer(fakelag=FakeLag())
    ev = [(0.0, lambda _: p.submit("lucy", msg("lucy", *([6] * 40)), lane=Lane.TEXT)),
          (0.0, lambda _: p.submit("s0", [L6] * 40, lane=Lane.TEXT))]
    ev += [e for _, e in chatty(p, 7, 20.0, seed, until=280)]
    keys = msg("vjt", 5, 3, verb="KEYS")
    ev += [(at - 5.0, lambda _: p.submit("vjt", msg("vjt", 2, verb="NACK"), lane=Lane.REACTIVE)),
           (at, lambda _: p.submit("vjt", keys, lane=Lane.REACTIVE))]
    released = released_by_wakeups(p, 0.0, ev)
    left = {"vjt": [(released[line][0], line) for line in keys]}
    assert completed(left, "vjt") == 1, left
    assert left["vjt"][1][0] - left["vjt"][0][0] <= UNDER_WAY_BOUND


def test_a_keys_under_way_past_its_floor_goes_before_the_orders_at_the_instant_named():
    # Review L, L2a: once its last line left TEXT_FLOOR ago, the rest of a
    # KEYS or NACK under way goes next after an order under way, as text
    # under way does, and takes the reserve as the orders do: at t0 + 20 s,
    # the instant the wakeup names (at this t0 the elapsed time rounds below
    # 20). mal0 is not fresh (two KEYS queued); the application keeps the
    # bank between 5.5 and 6.5 s, so a CHAL queued at 18 s, which needs 5,
    # cannot go, and the KEYS's 3 s line, which needs 7 with the reserve,
    # goes first.
    t0 = 1018.1631072945817
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    mal = [msg("mal0", 5, 3, verb="KEYS") for _ in range(2)]
    for m in mal:
        assert p.submit("mal0", m, lane=Lane.REACTIVE)
    assert p.due(t0) == [("mal0", mal[0][0])]
    lag.add(1, t0)                               # the application's own lines
    chal = msg("h0", 5, 4)
    ev = [(t0 + 0.5 + i, lambda now: lag.add(1, now)) for i in range(25)]
    ev += [(t0 + 18.0, lambda now: p.submit("h0", chal, lane=Lane.URGENT, deadline=now + 30.0))]
    released = released_by_wakeups(p, t0, ev)
    assert released[mal[0][-1]][0] == t0 + TEXT_FLOOR
    assert released[mal[0][-1]][1] < released[chal[0]][1]


def test_what_a_fresh_keys_paid_to_go_ahead_never_comes_out_of_the_orders_own_budget():
    # Review L, L4a: a fresh peer's KEYS that goes ahead pays from the
    # allowance it shares with the orders of a human who drew nothing,
    # never from the orders' own 36 s. Held by the application's lines, the
    # KEYS goes ahead at 8 s and pays its 8 s; one human's four orders in
    # the next minute, 36 s, are all sent.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    streams(p, "s0", "s1")
    lag.add(12, 0.0)                             # the application's own lines
    keys = msg("vjt", 5, 3, verb="KEYS")
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    chals = [order(p, "h0", 10.0 + 15.0 * i, (5, 4)) for i in range(4)]
    left = poll(p, [e for _, e in chals], until=120)
    assert left["vjt"][0][0] == 8.0              # it went ahead, so it paid
    sent = {line for _, line in left["h0"]}
    assert all(lines[-1] in sent for lines, _ in chals)


def test_a_fresh_nack_never_goes_ahead_of_an_order_whatever_it_waited():
    # Review L, L4a: only a first contact's KEYS goes ahead of the orders
    # and of text past the floor: its asker asks again at KEYREQ_RETRY and
    # drops what it queued at OUTQ_TTL. A NACK has no such clock (its
    # sender keeps the message SENT_MEMORY), so pinned nicks each drawing
    # one cost no human an order. The application keeps the bank up; the
    # NACK's patience is out at 8 s, the CHAL comes at 9 and leaves first,
    # at 15 and 19 s.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    lag.add(20, 0.0)                             # the application's own lines
    nack = msg("pz0", 2, verb="NACK")
    assert p.submit("pz0", nack, lane=Lane.REACTIVE)
    assert p.due(0.0) == []
    chal = msg("h0", 5, 4)
    ev = [(9.0, lambda now: p.submit("h0", chal, lane=Lane.URGENT, deadline=now + 15.0))]
    released = released_by_wakeups(p, 0.0, ev)
    assert released[chal[0]][0] == 15.0 and released[chal[-1]][0] == 19.0
    assert released[chal[-1]][1] < released[nack[0]][1]
    assert paid(p) == 0


def test_a_fresh_keys_waiting_on_the_bank_goes_ahead_of_an_order_queued_after_its_patience_ran_out():
    # Review L, L4b: the orders queued before a fresh KEYS's patience ran out
    # keep their place, those queued after go behind it, the KEYS still
    # waiting on the bank or not. The application's lines keep the bank up:
    # lucy's CHAL, queued at 5 s, leaves at 11 and 15; ann's KEYREQ, queued
    # at 9, after the KEYS's patience, goes after it (20 and 23 s), at 26.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    keys = msg("vjt", 5, 3, verb="KEYS")
    before, after = msg("lucy", 5, 4), msg("ann", 3, verb="KEYREQ")
    lag.add(16, 0.0)                             # the application's own lines
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(0.0) == []
    ev = [(5.0, lambda now: p.submit("lucy", before, lane=Lane.URGENT, deadline=now + 15.0)),
          (9.0, lambda now: p.submit("ann", after, lane=Lane.URGENT))]
    released = released_by_wakeups(p, 0.0, ev)
    assert [released[line][0] for line in before + keys + after] == [11.0, 15.0, 20.0, 23.0, 26.0]


def test_the_rest_of_a_paid_keys_goes_ahead_of_an_order_queued_after_its_patience_ran_out():
    # Review L, L4b: what a fresh KEYS paid to go ahead covers the rest of
    # it, ahead of the orders queued after its patience ran out. Its patience
    # runs out under h3's pre-key CHAL (5, 10 and 14 s); its first line goes
    # at 19, h2's KEYREQ comes at 20, the KEYS's 3 s rest goes first, at 22.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    keys = msg("vjt", 5, 3, verb="KEYS")
    chal, keyreq = msg("h3", 6, 6, 4), msg("h2", 3, verb="KEYREQ")
    lag.add(8, 0.0)                              # the application's own lines
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(0.0) == []
    ev = [(5.0, lambda now: p.submit("h3", chal, lane=Lane.URGENT, deadline=now + 15.0)),
          (20.0, lambda now: p.submit("h2", keyreq, lane=Lane.URGENT))]
    released = released_by_wakeups(p, 0.0, ev)
    assert [released[line][0] for line in chal + keys + keyreq] == [5.0, 10.0, 14.0, 19.0, 22.0, 25.0]
    assert paid(p) == 8


def test_an_order_past_its_budget_holds_no_fresh_keys_back_and_the_rest_waits_once_it_is_within():
    # Review L, L4b: an order queued before a fresh KEYS's patience ran out
    # but past its budget does not keep it waiting: h0 took its 36 s from
    # -48 s, so its fifth order, queued at 1 s, waits behind the text. The
    # KEYS goes ahead of ann's KEYREQ, queued at 9; at 12 h0's first order
    # ages out, the fifth is within budget again, and the rest of the KEYS
    # goes behind it, at 22.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    orders = [msg("h0", 5, 4) for _ in range(4)]
    released = released_by_wakeups(p, -48.0, [
        (-48.0, lambda now: [p.submit("h0", o, lane=Lane.URGENT) for o in orders])])
    assert released[orders[-1][-1]][0] == -22.0
    keys, fifth, keyreq = msg("vjt", 5, 3, verb="KEYS"), msg("h0", 5, 4), msg("ann", 3, verb="KEYREQ")
    lag.add(15, 0.0)                             # the application's own lines
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(0.0) == []
    ev = [(1.0, lambda now: p.submit("h0", fifth, lane=Lane.URGENT)),
          (9.0, lambda now: p.submit("ann", keyreq, lane=Lane.URGENT))]
    released = released_by_wakeups(p, 0.0, ev)
    assert [released[line][0] for line in keys[:1] + fifth + keys[1:] + keyreq] == [10.0, 15.0, 19.0, 22.0, 25.0]


def test_the_rest_of_a_fresh_keys_goes_behind_an_older_order_held_by_its_window_and_pays():
    # Review L, L4a and L4b: a fresh KEYS that started with nothing ahead
    # paid nothing; past its patience its rest goes ahead of text past the
    # floor and pays, but behind an order queued before. lucy's order,
    # queued at 6 s, waits for lucy's window (three lines at 5, 5 and 7):
    # the rest goes at 10, at the orders' limit (a bank of 7), the order at
    # 15 and 19.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    keys = msg("vjt", 5, 3, verb="KEYS")
    acks, older = [msg("lucy", 2) for _ in range(3)], msg("lucy", 5, 4)
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(0.0) == [("vjt", keys[0])]
    lag.add(6, 0.0)                              # the application's own lines
    ev = [(5.0, lambda now: [p.submit("lucy", a, lane=Lane.URGENT) for a in acks]),
          (6.0, lambda now: p.submit("lucy", older, lane=Lane.URGENT))]
    released = released_by_wakeups(p, 0.0, ev)
    assert [released[a[0]][0] for a in acks] == [5.0, 5.0, 7.0]
    assert [released[line][0] for line in keys[1:] + older] == [10.0, 15.0, 19.0]
    assert paid(p) == 3


def test_a_fresh_keys_goes_ahead_the_instant_an_order_leaves_the_allowance_it_shares():
    # Review L, L4a: a fresh KEYS goes ahead only if the orders, what the
    # other first contacts paid and itself fit URGENT_BUDGET +
    # FRESH_ALLOWANCE. h0's four orders (36 s, from 0) and vjt's KEYS (8,
    # paid at 31) leave ann's no room until h0's first order ages out, at
    # 60 s: it goes then, at the orders' limit (a bank of 2), as the wakeup
    # names. The application keeps the bank up from 40 s.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    orders = [msg("h0", 5, 4) for _ in range(4)]
    first, second = msg("vjt", 5, 3, verb="KEYS"), msg("ann", 5, 3, verb="KEYS")
    for o in orders:
        assert p.submit("h0", o, lane=Lane.URGENT)
    assert p.submit("vjt", first, lane=Lane.REACTIVE)
    assert p.due(0.0) == [("h0", line) for line in orders[0]]
    ev = [(40.0, lambda now: p.submit("ann", second, lane=Lane.REACTIVE)),
          (40.0, lambda now: lag.add(18, now))]     # the application's own lines
    released = released_by_wakeups(p, 0.0, ev)
    assert released[first[0]][0] == 31.0 and released[second[0]][0] == 60.0


def test_the_floor_of_a_keys_under_way_runs_from_its_own_last_line():
    # Review L, L2a: mal0 drew a KEYS at 10 s (lines at 10 and 13) and
    # another at 15 (first line at 18): the second's floor runs from 18, not
    # from the first's lines, so its rest waits behind h2's CHAL (20 and
    # 24 s) for the reserve's limit, at 32.
    p = Pacer(fakelag=FakeLag())
    first, second, chal = msg("mal0", 5, 3, verb="KEYS"), msg("mal0", 5, 3, verb="KEYS"), msg("h2", 6, 5)
    ev = [(10.0, lambda now: p.submit("mal0", first, lane=Lane.REACTIVE)),
          (15.0, lambda now: p.submit("mal0", second, lane=Lane.REACTIVE)),
          (20.0, lambda now: p.submit("h2", chal, lane=Lane.URGENT, deadline=now + 15.0))]
    released = released_by_wakeups(p, 0.0, ev)
    assert [released[line][0] for line in first + second[:1] + chal + second[1:]] == [
        10.0, 13.0, 18.0, 20.0, 24.0, 32.0]


def test_a_keys_under_way_finishes_before_another_first_contacts_starts():
    # Two first contacts in a row: the second's KEYS, fresh, does not cut
    # the first's in two. The first's 3 s rest goes at 3 s, at the
    # reserve's limit; the second's 5 s line needs an empty bank, at 8.
    p = Pacer(fakelag=FakeLag())
    first, second = msg("ann", 5, 3, verb="KEYS"), msg("vjt", 5, 3, verb="KEYS")
    assert p.submit("ann", first, lane=Lane.REACTIVE)
    assert p.due(0.0) == [("ann", first[0])]
    assert p.submit("vjt", second, lane=Lane.REACTIVE)
    assert p.due(2.0) == []
    released = released_by_wakeups(p, 2.0)
    assert released[first[-1]][0] == 3.0 and released[second[0]][0] == 8.0


def test_text_under_way_past_the_floor_still_leaves_the_reserve_to_the_orders():
    # Past the floor a text message under way goes next after an order under
    # way, at the reserve's limit all the same: its 5 s line waits for an
    # empty bank. The application keeps the bank at 5.5 s until 24.5 s.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    reply = msg("lucy", 5, 5)
    assert p.submit("lucy", reply, lane=Lane.TEXT)
    assert p.due(0.0) == [("lucy", reply[0])]
    ev = [(0.5 + i, lambda now: lag.add(1, now)) for i in range(25)]   # the application's
    released = released_by_wakeups(p, 0.0, ev)
    assert released[reply[-1]][0] == 30.0


def test_a_fresh_nack_of_two_lines_never_goes_ahead_of_an_order():
    # Review L, L4a: only a first contact's KEYS goes ahead of the orders;
    # a NACK started with nothing ahead does not, its patience out or not.
    # Its first line leaves at 0; the application keeps the bank up; h0's
    # CHAL, at 8.5 s, goes before the NACK's rest.
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    nack, chal = msg("pz0", 3, 3, verb="NACK"), msg("h0", 5, 4)
    assert p.submit("pz0", nack, lane=Lane.REACTIVE)
    assert p.due(0.0) == [("pz0", nack[0])]
    lag.add(10, 0.0)                             # the application's own lines
    ev = [(8.5, lambda now: p.submit("h0", chal, lane=Lane.URGENT, deadline=now + 15.0))]
    released = released_by_wakeups(p, 0.0, ev)
    assert released[chal[0]][1] < released[nack[-1]][1]
    assert paid(p) == 0


def test_a_failed_write_of_a_paid_fresh_answer_leaves_nothing_paid_behind():
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    keys = msg("vjt", 5, 3, verb="KEYS")
    lag.add(12, 0.0)                             # the application's own lines
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(0.0) == []
    assert p.due(8.0) == [("vjt", keys[0])] and p._paid
    p.drop("vjt", framing.parse(keys[0]).msgid)
    assert p.pending() == 0 and not p._open and not p._paid and not p._fresh
    assert not p._reactive_at and not p._cutoff


def test_a_second_human_and_a_first_contact_share_one_allowance():
    # Review L, L4a: vjt's KEYS paid 8 s at 8 s to go ahead; h0's four
    # orders then take the orders' own 36 s. h1, addressing the bot at 47 s,
    # finds the allowance taken by that KEYS, and waits behind the text
    # until it ages out, at 68, as the wakeup names (the text's 5 s lines
    # leave at 56, 61 and 66).
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    keys, h1 = msg("vjt", 5, 3, verb="KEYS"), msg("h1", 5, 4)
    orders = [msg("h0", 5, 4) for _ in range(4)]
    lag.add(12, 0.0)                             # the application's own lines
    assert p.submit("vjt", keys, lane=Lane.REACTIVE)
    assert p.due(0.0) == []
    ev = [(10.0, lambda now: [p.submit("h0", o, lane=Lane.URGENT) for o in orders]),
          (47.0, lambda now: p.submit("h1", h1, lane=Lane.URGENT)),
          (47.0, lambda now: p.submit("s0", [L5] * 6, lane=Lane.TEXT))]
    released = released_by_wakeups(p, 0.0, ev)
    assert released[keys[0]][0] == 8.0 and released[orders[-1][-1]][0] == 46.0
    assert released[h1[0]][0] == 68.0
