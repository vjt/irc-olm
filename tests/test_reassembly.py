from dataclasses import replace

from irc_olm import framing
from irc_olm.framing import Fragment
from irc_olm.reassembly import Assembled, Reassembler, Rejected

MASK = "bot!b@host"
SRC, DST = "AbCdEfGh-_0", "_Uw_z3-OAsk"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def frags(size, verb="MSG"):
    payload = framing.encode_payload({"v": 2, "body": "x" * size})
    return payload, [framing.parse(b) for b in
                     framing.fragment(verb, payload, src=SRC, dst=DST, own_mask=MASK, target="vjt")]


def make(**kw):
    clock = Clock()
    return Reassembler(clock=clock, **kw), clock


def test_single_fragment_completes_at_once():
    r, _ = make()
    payload, (f,) = frags(10)
    assert r.feed("vjt", f) == Assembled("MSG", f.msgid, SRC, DST, payload)


def test_out_of_order_fragments_reassemble():
    r, _ = make()
    payload, fs = frags(2000)
    assert len(fs) > 3
    order = fs[::-1]
    for f in order[:-1]:
        assert r.feed("vjt", f) is None
    assert r.feed("vjt", order[-1]) == Assembled("MSG", fs[0].msgid, SRC, DST, payload)


def test_same_msgid_from_two_senders_does_not_mix():
    r, _ = make()
    payload, fs = frags(1000)
    for f in fs[:-1]:
        r.feed("alice", f)
    assert r.feed("bob", fs[-1]) is None
    assert r.feed("alice", fs[-1]) == Assembled("MSG", fs[0].msgid, SRC, DST, payload)


def test_incomplete_message_is_discarded_after_60s():
    r, clock = make()
    _, fs = frags(1000)
    r.feed("vjt", fs[0])
    clock.t += 60.5
    for f in fs[1:]:
        assert r.feed("vjt", f) is None  # the first chunk is gone for good


def test_message_completing_inside_60s_survives():
    r, clock = make()
    payload, fs = frags(1000)
    r.feed("vjt", fs[0])
    clock.t += 59
    for f in fs[1:-1]:
        r.feed("vjt", f)
    assert r.feed("vjt", fs[-1]).payload == payload


def test_a_fragment_from_or_to_another_device_rejects_the_message():
    for field, other in (("src", "zzzzzzzzzzz"), ("dst", "*")):
        r, _ = make()
        _, fs = frags(1000)
        r.feed("vjt", fs[0])
        assert r.feed("vjt", replace(fs[1], **{field: other})) == Rejected(
            fs[0].msgid, "inconsistent-fragment", "MSG")
        for g in fs[1:]:
            assert not isinstance(r.feed("vjt", g), Assembled)


def test_verb_or_total_mismatch_rejects_the_message():
    r, _ = make()
    _, fs = frags(1000)
    r.feed("vjt", fs[0])
    f = fs[1]
    assert isinstance(r.feed("vjt", replace(f, verb="PKMSG")), Rejected)
    # the whole message is gone, not just the bad fragment
    for g in fs[1:]:
        assert not isinstance(r.feed("vjt", g), Assembled)


def test_duplicate_fragment_rejects_the_message():
    r, _ = make()
    _, fs = frags(1000)
    r.feed("vjt", fs[0])
    assert isinstance(r.feed("vjt", fs[0]), Rejected)


def test_per_sender_byte_cap():
    r, _ = make(max_bytes_per_sender=1000)
    _, fs = frags(3000)
    results = [r.feed("vjt", f) for f in fs]
    assert any(isinstance(x, Rejected) for x in results)
    assert not any(isinstance(x, Assembled) for x in results)
    # another sender is unaffected
    payload, small = frags(10)
    assert r.feed("other", small[0]) == Assembled("MSG", small[0].msgid, SRC, DST, payload)


def test_per_sender_pending_message_cap():
    r, _ = make(max_pending_per_sender=2)
    starts = [frags(1000)[1][0] for _ in range(3)]
    assert r.feed("vjt", starts[0]) is None
    assert r.feed("vjt", starts[1]) is None
    assert isinstance(r.feed("vjt", starts[2]), Rejected)


def test_bytes_are_released_when_a_message_completes():
    r, _ = make(max_bytes_per_sender=1500)
    for _ in range(5):
        payload, fs = frags(600)
        results = [r.feed("vjt", f) for f in fs]
        assert results[-1] == Assembled("MSG", fs[0].msgid, SRC, DST, payload)


def test_a_slow_message_survives_while_its_fragments_keep_coming():
    # Paced under the server's flood bank, a long message takes minutes.
    r, clock = make()
    payload, fs = frags(3000)
    assert len(fs) > 4
    for f in fs[:-1]:
        assert r.feed("vjt", f) is None
        clock.t += 50
    assert r.feed("vjt", fs[-1]).payload == payload


def test_an_incomplete_message_is_discarded_60s_after_its_last_fragment():
    r, clock = make()
    _, fs = frags(1000)
    r.feed("vjt", fs[0])
    clock.t += 50
    r.feed("vjt", fs[1])
    clock.t += 60.5
    for f in fs[2:]:
        assert r.feed("vjt", f) is None


def test_buffered_bytes_are_capped_across_senders_newest_first_on_a_tie():
    # Pending messages live 60 s from their LAST fragment: one fragment a
    # minute keeps one alive, so a nick-changing sender needs a global cap.
    # On a tie the sender that started last goes, here the one feeding: the
    # one that started first is, paced, the honest long message.
    r, clock = make(max_bytes_total=1500)
    msgs = []
    for i in range(4):
        _, fs = frags(600)                        # 2 fragments: ~460 bytes buffered each
        assert len(fs) == 2 and 3 * len(fs[0].chunk) <= 1500 < 4 * len(fs[0].chunk)
        res = r.feed(f"nick{i}", fs[0])
        msgs.append(fs)
        clock.t += 1
    assert res == Rejected(msgs[3][0].msgid, "global-byte-cap", "MSG")
    assert r.take_evicted() == []
    for i in range(3):
        assert isinstance(r.feed(f"nick{i}", msgs[i][1]), Assembled)


def test_the_global_cap_takes_from_the_sender_holding_the_most_first():
    # Paced, an honest long message is the idlest one: idleness alone would
    # pick it first, while other senders keep theirs freshly touched.
    r, clock = make(max_bytes_total=6000)
    _, vjt = frags(3000)                         # 9 fragments, ~4.1 KB whole
    _, mal0 = frags(6000)
    _, mal1 = frags(6000)
    for f in vjt[:2]:
        assert r.feed("vjt", f) is None
    clock.t += 1
    for f in mal0[:9]:
        r.feed("mal0", f)
    for f in mal1[:3]:
        r.feed("mal1", f)                         # past 6000: mal0's goes, not vjt's
    assert isinstance([r.feed("vjt", f) for f in vjt[2:]][-1], Assembled)
    assert r.feed("mal0", mal0[9]) is None        # it starts over


def test_the_global_cap_takes_the_victims_message_furthest_from_completion():
    # Not its idlest: paced, that is the one closest to done.
    r, clock = make(max_bytes_total=3000)
    _, near = frags(2000)    # 4 full chunks of 5: closest to done
    _, far = frags(3000)
    for f in near[:-1]:
        assert r.feed("mal", f) is None
    clock.t += 5
    for f in far[:2]:
        assert r.feed("mal", f) is None
    held = sum(len(f.chunk) for f in near[:-1] + far[:2])
    assert held <= 3000 < held + len(near[0].chunk) and len(far) > 4
    _, vjt = frags(600)
    assert r.feed("vjt", vjt[0]) is None
    assert r.take_evicted() == [("mal", Rejected(far[0].msgid, "global-byte-cap", "MSG"))]
    assert r.take_evicted() == []
    assert isinstance(r.feed("mal", near[-1]), Assembled)
