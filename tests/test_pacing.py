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
                               {framing.parse(chal[0]).msgid})
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
    p.due(1000.0)                                             # one message leaves
    assert p.submit("vjt", _message(1), lane=Lane.TEXT) is True


def test_fakelag_checks_and_charges_in_one_step():
    lag = FakeLag()
    assert lag.try_add(6, 1000.0) is True
    assert lag.try_add(5, 1000.0) is False and lag.bank(1000.0) == 6.0
    assert lag.try_add(4, 1000.0) is True and lag.bank(1000.0) == 10.0


# --- review of the fix commit (turns, lanes, reserve) ---------------------

from irc_olm.pacing import (FAKE_LAG_CEILING, REACTIVE_BUDGET, RESERVE,  # noqa: E402
                            PacedSender, lane_of)

# Lines by their bank cost as a PRIVMSG to a nick of 2 to 5 letters.
L6, L5, L4, L2 = "W" * 470, "Z" * 430, "Y" * 300, "n" * 60


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


def flooders(p, n, until):
    """`n` holders of pinned nicks: each draws a NACK (one line, 2 s of bank)
    with a junk line every 3 s, and a KEYS (two lines, 4 s each) with a
    KEYREQ every 15 s, the most the engine answers."""
    ev = []
    for i in range(n):
        f = f"mal{i}"
        ev += [(0.05 * i + 3.0 * k, lambda _, f=f: p.submit(f, [L2], lane=Lane.REACTIVE))
               for k in range(int(until / 3.0))]
        ev += [(0.5 * i + 15.0 * k, lambda _, f=f: p.submit(f, [L4, L4], lane=Lane.REACTIVE))
               for k in range(int(until / 15.0))]
    return ev


def streams(p, *targets):
    for s in targets:
        assert p.submit(s, [L6] * 20, lane=Lane.TEXT)


def unique(line, tag):
    return line[:-len(tag)] + tag


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
    # nothing may become due (a window opening, the bank's room, the reactive
    # budget recovering), and a wakeup at `now` with nothing due is a spin.
    rng = random.Random(seed)
    p = Pacer(fakelag=FakeLag())
    t0 = 1000.0 + rng.random()
    subs = sorted((t0 + rng.uniform(0, 120), rng.choice("abcd"), rng.choice(list(Lane)),
                   rng.randint(1, 3), rng.choice([L2, L4, L5, L6]))
                  for _ in range(rng.randint(5, 60)))
    now = t0
    for _ in range(20000):
        while subs and subs[0][0] <= now:
            _, target, lane, n, line = subs.pop(0)
            p.submit(target, [line] * n, lane=lane)
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


def test_what_we_originate_never_waits_on_a_budget():
    # Five 2-line CHALs to one target in a minute (10 lines: the per-target
    # budget of the fix commit was 8), two targets streaming text: each
    # leaves within 7 s, the most a text-filled bank costs it.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    chals = [(5.0 + 13 * i, [unique(L6, f"{i}a"), unique(L5, f"{i}b")]) for i in range(5)]
    left = poll(p, [(t, lambda _, c=c: p.submit("lucy", c, lane=Lane.URGENT)) for t, c in chals],
                until=90)
    sent = {line: t for t, line in left["lucy"]}
    for t, c in chals:
        assert sent[c[-1]] - t <= 7.0, (t, sent[c[-1]])


@pytest.mark.parametrize("offset", [0.0, 1.3, 2.6, 3.9, 5.2])
@pytest.mark.parametrize("chal, bound", [([L6, L5], 7.0), ([L6, L6, L4], 12.0)])
def test_a_chal_behind_streaming_text_leaves_within_what_the_reserve_allows(offset, chal, bound):
    # Text never takes the bank past the reserve (a full line, 6 s, goes at
    # an empty bank): a CHAL on a session finds at most 6 s there and leaves
    # within 7 s; a first CHAL, a pre-key message of three lines, within 12.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    t = 20.0 + offset
    left = poll(p, [(t, lambda _: p.submit("lucy", chal, lane=Lane.URGENT))], until=60)
    assert len(left["lucy"]) == len(chal)
    assert left["lucy"][-1][0] - t <= bound


def test_concurrent_chals_go_message_by_message():
    # Turns by line would interleave them and make both late.
    p = Pacer(fakelag=FakeLag())
    streams(p, "s0", "s1")
    both = lambda _: (p.submit("lucy", [L6, L5], lane=Lane.URGENT),  # noqa: E731
                      p.submit("mario", [L6, L5], lane=Lane.URGENT))
    left = poll(p, [(20.0, both)], until=60)
    assert left["lucy"][-1][0] < left["mario"][0][0]
    assert left["lucy"][-1][0] - 20.0 <= 7.0


@pytest.mark.parametrize("n", [1, 2, 3])
def test_holders_of_pinned_nicks_flooding_us_neither_delay_a_chal_nor_starve_text(n):
    p = Pacer(fakelag=FakeLag())
    ev = flooders(p, n, until=300)
    ev.append((0.0, lambda _: p.submit("c", [L5] * 10, lane=Lane.TEXT)))     # 50 s of bank
    ev.append((95.0, lambda _: p.submit("lucy", [L6, L5], lane=Lane.URGENT)))
    left = poll(p, ev, until=300)
    assert left["lucy"][-1][0] - 95.0 <= 7.0
    # Reactive lines take at most REACTIVE_BUDGET (and a line) of each
    # minute ahead of text: text keeps half the bank, so 50 s leave in 100 s.
    assert left["c"][-1][0] <= 120.0


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
            assert spent <= REACTIVE_BUDGET, (target, t0, spent)


def test_an_honest_peers_keys_take_their_turn_while_flooders_spend_their_budgets():
    # Each target has its own budget, and reactive lines take turns by
    # target: three flooders with full queues do not hold an honest KEYS.
    p = Pacer(fakelag=FakeLag())
    ev = flooders(p, 3, until=200) + [(0.0, lambda _: p.submit("c", [L5] * 30, lane=Lane.TEXT))]
    ev.append((100.0, lambda _: p.submit("vjt", [L4, L4], lane=Lane.REACTIVE)))
    left = poll(p, ev, until=200)
    assert left["vjt"][-1][0] - 100.0 <= 15.0


def test_reactive_lines_take_turns_by_target():
    # Three targets with reactive lines queued first: a fourth one's line
    # goes after one line of each, not after all of theirs.
    p = Pacer(fakelag=None)
    for f in ("mal0", "mal1", "mal2"):
        assert p.submit(f, [L2] * 3, lane=Lane.REACTIVE)
    assert p.submit("vjt", [L2], lane=Lane.REACTIVE)
    order = [target for target, _ in p.due(1000.0)]
    assert order.index("vjt") == 3


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
    urgent = {framing.parse(chal).msgid, framing.parse(keyreq).msgid}
    assert lane_of(keyreq, urgent) is Lane.URGENT
    assert lane_of(chal, urgent) is Lane.URGENT
    assert lane_of(body("PKMSG"), set()) is Lane.TEXT
    assert lane_of(text, urgent) is Lane.TEXT
    for verb in ("KEYS", "NACK"):
        line = body(verb)
        assert lane_of(line, {framing.parse(line).msgid}) is Lane.REACTIVE   # drawn by a peer
    assert lane_of("not e2e at all", set()) is Lane.TEXT


def test_submit_all_admits_each_message_whole_and_returns_the_refused():
    # A re-key flush can carry several messages: past the per-target cap the
    # later ones are refused, each whole, and reported, not the batch.
    pacer = Pacer(fakelag=FakeLag())
    s = PacedSender(lambda target, line: None, pacer, clock=lambda: 0.0)
    with s._cv:
        for _ in range(DEFAULT_MAX_TEXT_MESSAGES - 2):
            assert pacer.submit("vjt", _message(1), lane=Lane.TEXT)
        flush = [_message(2), _message(1), _message(3), _message(1)]
        refused = s.submit_all([("vjt", b) for m in flush for b in m], set())
        assert refused == [("vjt", framing.parse(m[0]).msgid) for m in flush[2:]]
        queued = [line for _, _, line in pacer._queues["vjt"][Lane.TEXT]]
        assert queued[-3:] == flush[0] + flush[1]


def test_a_full_text_backlog_leaves_within_sent_memory_with_a_third_of_the_bank():
    # 480 s of text over 12 targets, three flooders holding the reactive
    # budget, the bot talking in channels at a sixth of its bank: text keeps
    # a third of the bank, and a NACK still finds what it refers to.
    from irc_olm.engine import SENT_MEMORY
    lag = FakeLag()
    p = Pacer(fakelag=lag)
    i = 0
    while p.submit(f"u{i % 12}", [L5] * 8, lane=Lane.TEXT):
        i += 1
    assert p._text_cost > p.max_backlog - 40
    talk = [(12.0 * k, lambda t: lag.charge("PRIVMSG #chan :" + "y" * 100, t))
            for k in range(int(SENT_MEMORY / 12))]
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
    assert p._sent == {} and p._served == {} and not p._reactive and p.pending() == 0
