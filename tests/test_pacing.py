import math
import random

import pytest

from flud_model import FludModel
from irc_olm.pacing import Pacer


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
    p.submit("vjt", [f"l{i}" for i in range(7)], urgent=False)
    sent = drain(p, 0.0)
    times = [round(t, 2) for t, _, _ in sent]
    assert [line for _, _, line in sent] == [f"l{i}" for i in range(7)]
    assert times[:3] == [0.0, 0.0, 0.0]
    assert times[3:6] == [6.0, 6.0, 6.0]
    assert times[6] == 12.0


def test_targets_are_paced_independently():
    p = Pacer(max_lines=3, window=6.0, fakelag=None)
    p.submit("a", ["a1", "a2", "a3", "a4"], urgent=False)
    p.submit("b", ["b1"], urgent=False)
    first = p.due(0.0)
    assert ("b", "b1") in first and ("a", "a3") in first and ("a", "a4") not in first


def test_next_wakeup_is_the_earliest_slot():
    p = Pacer(max_lines=3, window=6.0, fakelag=None)
    assert p.next_wakeup(0.0) is None
    p.submit("a", ["1", "2", "3", "4"], urgent=False)
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
            p.submit("vjt", ["x"] * events[i][1], urgent=False)
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
    p.submit("vjt", ["x"] * 6, urgent=False)
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
    s.submit("vjt", ["1", "2", "3", "4", "5"], urgent=False)
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
    s.submit("vjt", ["boom", "after"], urgent=False)
    assert done.wait(2)
    assert got == ["after"]


def test_text_past_the_connections_backlog_is_refused_whole_and_control_never_is():
    line = "x" * 110                                   # costs 3 s to "vjt", 3 s to "other"
    p = Pacer(max_backlog=9.0, fakelag=None)
    assert p.submit("vjt", [line, line], urgent=False) is True
    assert p.submit("other", [line, line], urgent=False) is False   # 12 s: the whole batch
    assert p.pending() == 2
    assert p.submit("other", [line], urgent=False) is True          # 9 s, across targets
    assert p.submit("vjt", [line] * 5, urgent=True) is True         # control always goes
    drain(p, 1000.0)
    assert p.submit("other", [line] * 3, urgent=False) is True      # sent text frees it


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
    p.submit("vjt", [FULL] * 20, urgent=False)
    server, _ = run_against_server(p)
    assert server.killed_at is not None


def test_with_the_bank_no_line_ever_waits_unparsed_on_the_server():
    p = Pacer(max_text_messages=64, fakelag=FakeLag())   # bare lines: one message each
    assert p.submit("vjt", [FULL] * 64, urgent=False)
    server, out = run_against_server(p)
    assert server.killed_at is None
    assert server.max_backlog == 0
    assert len(out) == len(server.parsed) == 64
    assert 300 <= out[-1][0] - out[0][0] <= 330    # one full line every ~5 s


def test_lines_the_application_writes_count_in_the_same_bank():
    def last_e2e_line_at(talk):
        p = Pacer(fakelag=FakeLag())
        p.submit("vjt", [FULL] * 20, urgent=False)
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
    p.submit("vjt", long_msg, urgent=False)
    short = _message(1)                 # text too: it must not overtake the long one
    p.submit("vjt", short, urgent=False)
    chal = _message(2)                  # a CHAL, two lines, queued last: 15 s to live
    p.submit("vjt", chal, urgent=True)
    other = _message(2, target="lucy")
    p.submit("lucy", other, urgent=True)
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
        assert refused == 0
        assert [line for _, line in pacer.due(1000.0)] == chal[:1]   # 6 s of bank: no room
        assert [line for _, line in pacer.due(1006.0)] == chal[1:]   # for a 5 s long line


def test_an_idle_target_leaves_nothing_behind():
    p = Pacer(fakelag=None)
    for i in range(50):
        p.submit(f"nick{i}", ["x"], urgent=False)
    p.due(1000.0)
    p.due(1000.0 + DEFAULT_WINDOW + 1)
    assert p._sent == {} and p.pending() == 0


def test_the_per_target_window_still_holds_for_single_lines():
    # Small lines (KEYREQs, 2 s each): the bank would let five through at
    # once, the receiver's CTCP flood limit only three.
    keyreq = lambda: framing.fragment("KEYREQ", framing.encode_payload({"v": 1}),  # noqa: E731
                                      own_mask="bot!b@h", target="vjt")[0]
    p = Pacer(fakelag=FakeLag())
    p.submit("vjt", [keyreq() for _ in range(6)], urgent=True)
    _, out = run_against_server(p)
    times = [round(t - 1000.0, 2) for t, _, _ in out]
    assert times[:3] == [0.0, 0.0, 0.0] and min(times[3:]) >= 6.0


def test_a_bank_without_room_sets_the_next_wakeup_instead_of_spinning():
    p = Pacer(fakelag=FakeLag())
    p.submit("vjt", [FULL] * 3, urgent=False)
    assert len(p.due(1000.0)) == 2            # 5 s + 5 s: the bank is full
    assert p.due(1000.0) == []
    assert p.next_wakeup(1000.0) == 1005.0    # room for the third line, not "now"


# --- review of the fake-lag branch ---------------------------------------

def test_with_lines_queued_the_next_wakeup_is_never_now_when_nothing_is_due():
    # A wakeup at `now` with nothing due is a busy loop in PacedSender.
    rng = random.Random(7)
    for _ in range(300):
        lag = FakeLag()
        p = Pacer(fakelag=lag)
        now = 1000.0
        lag.add(rng.choice([0, 3, 6, 9]), now)
        for i in range(rng.randint(1, 6)):
            target = rng.choice(["a", "b", "c"])
            p.submit(target, ["x" * rng.choice([10, 200, 380])] * rng.randint(1, 3),
                     urgent=rng.random() < 0.3)
        for _ in range(40):
            p.due(now)
            if not p.pending():
                break
            wake = p.next_wakeup(now)
            assert wake is not None and wake > now
            now = wake


def test_an_empty_batch_is_accepted_and_breaks_nothing():
    p = Pacer(fakelag=FakeLag())
    assert p.submit("vjt", [], urgent=False) is True
    assert p.submit("vjt", [], urgent=True) is True
    assert p.due(1000.0) == [] and p.next_wakeup(1000.0) is None and p.pending() == 0
    p.submit("vjt", ["x"], urgent=False)
    assert [line for _, line in p.due(1000.0)] == ["x"]


def test_one_nick_spelt_two_ways_is_one_target_for_the_window():
    p = Pacer(fakelag=None)
    p.submit("Bob", ["1", "2", "3"], urgent=False)
    p.submit("bob", ["4", "5", "6"], urgent=False)
    assert [t for t, _ in p.due(1000.0)] == ["Bob", "Bob", "Bob"]   # each line keeps its spelling


def test_a_target_flooding_us_with_urgent_lines_cannot_starve_the_others():
    # Whoever holds a pinned nick can draw a KEYS every 30 s and a NACK per
    # junk line: its urgent lines must not hold everyone else's back.
    p = Pacer(fakelag=FakeLag())
    t0, left = 1000.0, {}
    p.submit("c", [FULL] * 3, urgent=False)
    for k in range(int(120 / 0.5)):
        now = t0 + k * 0.5
        if k % 2 == 0:
            p.submit("mal", ["n" * 300], urgent=True)       # one urgent line a second
        if k == 20:
            p.submit("lucy", ["chal" + "c" * 300] * 2, urgent=True)
        for target, line in p.due(now):
            left.setdefault(target, []).append(now - t0)
    assert len(left.get("c", [])) == 3 and left["c"][-1] < 60
    assert left["lucy"][-1] - 10 < 15                         # a CHAL submitted at 10 s


def test_a_targets_urgent_queue_is_capped():
    p = Pacer(fakelag=FakeLag())
    assert p.submit("mal", ["n"] * DEFAULT_MAX_URGENT, urgent=True) is True
    assert p.submit("mal", ["n"], urgent=True) is False
    assert p.submit("vjt", ["n"], urgent=True) is True


def test_text_queued_for_one_target_stays_within_what_olm_can_skip():
    # An urgent message overtakes the target's queued text: the receiver
    # skips one message key per message overtaken, and keeps only so many.
    p = Pacer(fakelag=FakeLag())
    msgs = [_message(1) for _ in range(DEFAULT_MAX_TEXT_MESSAGES)]
    for m in msgs:
        assert p.submit("vjt", m, urgent=False) is True
    assert p.submit("vjt", _message(1), urgent=False) is False
    assert p.submit("lucy", _message(1), urgent=False) is True
    p.due(1000.0)                                             # one message leaves
    assert p.submit("vjt", _message(1), urgent=False) is True


def test_text_accepted_leaves_within_sent_memory_on_a_talking_connection():
    # The bot keeps talking in channels meanwhile (charged to the same bank).
    from irc_olm.engine import SENT_MEMORY
    p = Pacer(fakelag=FakeLag())
    while p.submit("vjt", _message(1), urgent=False) and p._text_cost < p.max_backlog - 5:
        p.submit("lucy", _message(1), urgent=False)            # two targets: past 32 each
    chatter = [(1000.0 + 4 * i, "PRIVMSG #sbiffo :" + "y" * 100) for i in range(1000)]
    _, out = run_against_server(p, until=SENT_MEMORY * 2, also=chatter)
    assert out[-1][0] - out[0][0] + 60 <= SENT_MEMORY


def test_fakelag_checks_and_charges_in_one_step():
    lag = FakeLag()
    assert lag.try_add(6, 1000.0) is True
    assert lag.try_add(5, 1000.0) is False and lag.bank(1000.0) == 6.0
    assert lag.try_add(4, 1000.0) is True and lag.bank(1000.0) == 10.0
