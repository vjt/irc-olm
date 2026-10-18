import pytest

from irc_olm import framing
from irc_olm.framing import Fragment
from irc_olm.reassembly import Assembled, Reassembler, Rejected

MASK = "bot!b@host"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def frags(size, verb="MSG"):
    payload = framing.encode_payload({"v": 1, "body": "x" * size})
    return payload, [framing.parse(b) for b in
                     framing.fragment(verb, payload, own_mask=MASK, target="vjt")]


def make(**kw):
    clock = Clock()
    return Reassembler(clock=clock, **kw), clock


def test_single_fragment_completes_at_once():
    r, _ = make()
    payload, (f,) = frags(10)
    assert r.feed("vjt", f) == Assembled("MSG", f.msgid, payload)


def test_out_of_order_fragments_reassemble():
    r, _ = make()
    payload, fs = frags(2000)
    assert len(fs) > 3
    order = fs[::-1]
    for f in order[:-1]:
        assert r.feed("vjt", f) is None
    assert r.feed("vjt", order[-1]) == Assembled("MSG", fs[0].msgid, payload)


def test_same_msgid_from_two_senders_does_not_mix():
    r, _ = make()
    payload, fs = frags(1000)
    for f in fs[:-1]:
        r.feed("alice", f)
    assert r.feed("bob", fs[-1]) is None
    assert r.feed("alice", fs[-1]) == Assembled("MSG", fs[0].msgid, payload)


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


def test_verb_or_total_mismatch_rejects_the_message():
    r, _ = make()
    _, fs = frags(1000)
    r.feed("vjt", fs[0])
    f = fs[1]
    assert isinstance(r.feed("vjt", Fragment("PKMSG", f.msgid, f.index, f.total, f.chunk)), Rejected)
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
    assert r.feed("other", small[0]) == Assembled("MSG", small[0].msgid, payload)


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
        assert results[-1] == Assembled("MSG", fs[0].msgid, payload)
