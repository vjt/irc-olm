import hashlib
import re

import pytest

from irc_olm import framing
from irc_olm.engine import (OUTQ_MAX, OUTQ_TTL, AckOk, AckRejected, ChallengeExpired,
                            NotPinnedError, Received, Result, SendFailed, SendQueued)
from irc_olm.challenge import CHALLENGE_TTL
from irc_olm.engine import olm_body_bound
from irc_olm.keys import b64
from irc_olm.pacing import ACK_MARGIN, FAKE_LAG_CEILING, FakeLag, Lane, Pacer, line_cost


def establish(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "hi"}))
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "hello"}))
    net.take("bot"), net.take("vjt")
    return bot, vjt


LINE = "vjt-claude: riavvia il bot".encode()


def chal(net, bot):
    ch, res = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                            sender_mask="vjt!vjt@host", line=LINE)
    net.pump("bot", res)
    return ch


def test_challenge_reaches_the_peer_with_the_spec_fields(net):
    bot, vjt = establish(net)
    ch = chal(net, bot)
    (got,) = net.take("vjt", Received)
    c = got.inner
    assert c["t"] == "chal"
    assert c["network"] == "TestNet" and c["channel"] == "#sbiffo"
    assert c["sender_mask"] == "vjt!vjt@host"
    assert c["line_sha256"] == hashlib.sha256(LINE).hexdigest()
    assert re.fullmatch(r"[A-Za-z0-9+/]{22}", c["nonce"]) and c["nonce"] == ch.nonce
    assert c["expires_at"] == int(net.clock.t) + CHALLENGE_TTL


def test_matching_ack_from_the_verified_peer_is_accepted_once(net):
    bot, vjt = establish(net)
    ch = chal(net, bot)
    net.take("vjt")
    net.pump("vjt", vjt.send("bot", {"t": "ack", "nonce": ch.nonce}))
    (ok,) = net.take("bot", AckOk)
    assert ok.challenge == ch
    net.pump("vjt", vjt.send("bot", {"t": "ack", "nonce": ch.nonce}))
    assert [e.reason for e in net.take("bot", AckRejected)] == ["unknown-nonce"]


def test_ack_after_expiry_is_rejected_and_tick_reports_the_expiry(net):
    bot, vjt = establish(net)
    ch = chal(net, bot)
    net.clock.t += CHALLENGE_TTL + 1
    (exp,) = [e for e in bot.tick().events if isinstance(e, ChallengeExpired)]
    assert exp.challenge == ch
    net.pump("vjt", vjt.send("bot", {"t": "ack", "nonce": ch.nonce}))
    assert not net.take("bot", AckOk)


def test_ack_from_another_key_is_rejected_and_does_not_burn_the_nonce(net):
    bot, vjt = establish(net)
    eve = net.add("eve")
    net.pair("bot", "eve")
    net.pump("eve", eve.send("bot", {"t": "text", "body": "hi"}))
    ch = chal(net, bot)
    net.pump("eve", eve.send("bot", {"t": "ack", "nonce": ch.nonce}))
    assert [e.reason for e in net.take("bot", AckRejected)] == ["wrong-peer"]
    net.pump("vjt", vjt.send("bot", {"t": "ack", "nonce": ch.nonce}))
    assert len(net.take("bot", AckOk)) == 1


def test_no_challenge_to_an_unpinned_nick(net):
    bot, vjt = establish(net)
    with pytest.raises(NotPinnedError):
        bot.challenge("nobody", network="TestNet", channel="#x", sender_mask="m", line=b"x")


def test_ack_after_expiry_without_a_tick_is_rejected_as_expired(net):
    bot, vjt = establish(net)
    ch = chal(net, bot)
    net.take("vjt")
    net.clock.t += CHALLENGE_TTL + 1
    net.pump("vjt", vjt.send("bot", {"t": "ack", "nonce": ch.nonce}))
    assert [e.reason for e in net.take("bot", AckRejected)] == ["expired"]


# --- a challenge that cannot go is its order's expiry, never a lost message ------
#
# A CHAL is no message the application wrote: when it cannot go, its order ends
# in the challenge book (ChallengeExpired, unless an ACK still comes back), and
# a SendFailed counting it as well reports a lost reply that nobody sent.

def paired(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    return bot, vjt


def lost(events):
    return [(e.reason, e.lost) for e in events if isinstance(e, SendFailed)]


def test_a_challenge_that_waited_in_vain_for_keys_is_not_a_lost_message(net):
    bot, vjt = paired(net)
    net.drop = lambda *_: True                      # nobody answers the KEYREQ
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "a reply"}))
    chal(net, bot)
    net.clock.t += OUTQ_TTL + 1
    res = bot.tick()
    assert lost(res.events) == [("keys-timeout", 1)]   # the reply, not the CHAL
    assert [e for e in res.events if isinstance(e, ChallengeExpired)]


def test_a_challenge_goes_as_a_msg_once_the_peer_has_written_to_us(net):
    # O1: what makes a session fit for a CHAL is the peer having written to
    # it, which is also what makes our next message on it a MSG.
    bot, vjt = paired(net)
    net.drop = lambda src, dst, body: src == "vjt" and framing.parse(body).verb == "MSG"
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "hello"}))   # vjt's listreq is lost
    net.drop = None
    _, res = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                           sender_mask="vjt!vjt@host", line=LINE)
    assert res.outbound == []
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "hi"}))
    ch = chal(net, bot)
    assert net.captured("MSG", "bot")[-1]["bodies"]
    assert [e.inner["nonce"] for e in net.take("vjt", Received) if e.inner["t"] == "chal"] == \
        [ch.nonce]


@pytest.mark.parametrize("wait", [0, OUTQ_TTL + 1], ids=["queued", "queue-timed-out"])
def test_keys_from_another_pinned_key_open_no_session_for_it(net, wait):
    # A KEYS answers the KEYREQ sent to a nick, and must describe the master
    # pinned there: another pinned master answering it opens nothing, whether
    # what was queued there is still waiting or already timed out.
    bot, vjt = net.add("bot"), net.add("vjt")
    eve = net.add("eve")
    net.pair("bot", "vjt")
    net.pair("bot", "eve")
    net.drop = lambda *_: True
    r = bot.send("vjt", {"t": "text", "body": "for vjt"})
    keyreq = next(b for _, b in r.outbound if framing.parse(b).verb == "KEYREQ")
    net.clock.t += wait
    bot.tick()
    for _, body in eve.receive("bot", keyreq).outbound:     # eve answers from "vjt"
        bot.receive("vjt", body)
    r = bot.send("eve", {"t": "text", "body": "for eve"})
    assert [e for e in r.events if isinstance(e, SendQueued)]   # no session for eve


def test_a_challenge_that_cannot_be_built_is_not_a_lost_message(net):
    bot, vjt = establish(net)
    for channel in ("#\ud800", "#" + "x" * 40000):  # unencodable, then too long
        _, res = bot.challenge("vjt", network="TestNet", channel=channel,
                               sender_mask="vjt!vjt@host", line=LINE)
        assert lost(res.events) == [] and res.outbound == []
    net.clock.t += CHALLENGE_TTL + 1
    assert len([e for e in bot.tick().events if isinstance(e, ChallengeExpired)]) == 2


def test_an_ack_the_application_wrote_is_still_a_lost_message(net):
    # An ACK is urgent like a CHAL, but has no deadline: its loss is reported.
    bot, vjt = paired(net)
    net.drop = lambda *_: True
    for i in range(OUTQ_MAX):
        net.pump("bot", bot.send("vjt", {"t": "text", "body": f"m{i}"}))
    assert lost(bot.send("vjt", {"t": "ack", "nonce": "n"}).events) == [("queue-full", 1)]


def test_a_challenge_a_full_queue_refuses_is_not_a_lost_message(net):
    bot, vjt = paired(net)
    net.drop = lambda *_: True
    for i in range(OUTQ_MAX):
        net.pump("bot", bot.send("vjt", {"t": "text", "body": f"m{i}"}))
    _, res = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                           sender_mask="vjt!vjt@host", line=LINE)
    assert lost(res.events) == []
    net.clock.t += CHALLENGE_TTL + 1
    assert [e for e in bot.tick().events if isinstance(e, ChallengeExpired)]


def test_a_challenge_queued_for_a_replaced_key_is_not_a_lost_message(net):
    bot = net.add("bot")
    k1, k2 = net.add("k1"), net.add("k2")
    net.pins["bot"]["k"] = k1.fingerprint
    bot.set_pins(net.pins["bot"])
    net.pin("k2", "bot")
    r1 = bot.send("k", {"t": "text", "body": "for k1"})       # KEYREQ, queued for k1
    bot.challenge("k", network="TestNet", channel="#sbiffo", sender_mask="k!k@host", line=LINE)
    net.pins["bot"]["k"] = k2.fingerprint
    bot.set_pins(net.pins["bot"])
    res = Result()
    for _, body in k2.receive("bot", r1.outbound[0][1]).outbound:   # k2 is on "k" now
        res.extend(bot.receive("k", body))
    assert lost(res.events) == [("key-mismatch", 1)]


@pytest.mark.parametrize("nacker, reason", [("eve", "nack-from-another-nick"),
                                            ("vjt", "repinned"), ("vjt", "unpinned-key")])
def test_a_challenge_a_nack_cannot_resend_is_not_a_lost_message(net, nacker, reason):
    bot, vjt = establish(net)
    net.add("eve")
    net.pair("bot", "eve")
    _, res = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                           sender_mask="vjt!vjt@host", line=LINE)
    ref = framing.parse(res.outbound[0][1]).msgid
    text_ref = framing.parse(bot.send("vjt", {"t": "text", "body": "x"}).outbound[0][1]).msgid
    if reason == "repinned":
        net.pins["bot"]["vjt"] = net.engines["eve"].fingerprint
        net.pins["bot"]["vjtold"] = vjt.fingerprint
        bot.set_pins(net.pins["bot"])
    elif reason == "unpinned-key":
        del net.pins["bot"]["vjt"]
        bot.set_pins(net.pins["bot"])
    # From vjt's device (in `from`): only it may NACK what went to it.
    nack = {"v": 2, "ref": ref}
    assert lost(net.inject(nacker, "bot", "NACK", nack, frm=vjt.did).events) == []
    # the same NACK for a message a sender wrote is still its loss
    nack = {"v": 2, "ref": text_ref}
    assert lost(net.inject(nacker, "bot", "NACK", nack, frm=vjt.did).events) == [(reason, 1)]


def test_a_challenge_a_nack_cannot_rekey_for_is_not_a_lost_message(net):
    bot, vjt = paired(net)
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "hello"}))
    net.clock.t += 61
    vjt.forget_sessions(bot.fingerprint)          # a re-key, done: its minute runs
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "again"}))
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "back"}))   # on the new session
    _, res = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                           sender_mask="vjt!vjt@host", line=LINE)
    ref = framing.parse(res.outbound[0][1]).msgid
    text_ref = framing.parse(bot.send("vjt", {"t": "text", "body": "x"}).outbound[0][1]).msgid
    assert lost(net.inject("vjt", "bot", "NACK", {"v": 2, "ref": ref}).events) == []
    assert lost(net.inject("vjt", "bot", "NACK", {"v": 2, "ref": text_ref}).events) == \
        [("rekey-throttled", 1)]


def test_a_nacked_challenge_is_not_resent_on_a_new_session_nor_a_lost_message(net):
    # The re-key still happens (the session is broken), but a CHAL cannot go
    # on the new session (O1): its order fails closed, as ChallengeExpired.
    bot, vjt = establish(net)
    net.clock.t += 61                      # vjt answers the re-key's KEYREQ
    _, res = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                           sender_mask="vjt!vjt@host", line=LINE)
    ref = framing.parse(res.outbound[0][1]).msgid
    before = len(net.wire)
    nacked = net.inject("vjt", "bot", "NACK", {"v": 2, "ref": ref})
    assert lost(nacked.events) == []
    net.pump("bot", nacked)
    assert [framing.parse(b).verb for s, _, b in net.wire[before:] if s == "bot"] == ["KEYREQ"]
    assert net.take("vjt", Received) == []
    net.clock.t += CHALLENGE_TTL + 1
    assert [e for e in bot.tick().events if isinstance(e, ChallengeExpired)]


# --- a challenge to a peer with several devices ------------------------------

def devices_heard_from(net, n, quiet=0):
    """The bot and a user "vjt" with `n` devices, every one of which but the
    last `quiet` has written to a session of the bot's: what a CHAL needs
    (O1). The bot's sessions to the quiet ones would still write pre-key
    bodies, which a CHAL skips. Four are listed; a fifth is trusted on its
    certificate alone (a list holds four), so a CHAL to five goes as two
    messages."""
    bot, devs = net.add("bot"), net.add_user("vjt", n)
    net.pin("bot", "vjt")
    net.pin("vjt", "bot")
    mute = {d.did for d in devs[n - quiet:]}
    net.drop = lambda src, dst, body: src == "vjt" and framing.parse(body).src in mute
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "hello"}))   # each listreqs back
    net.drop = None
    if n > 4:
        net.relist("vjt", devs[:3] + devs[4:], 2)                      # devs[4] replaces devs[3]
        net.drop = lambda src, dst, body: src == "bot" and framing.parse(body).verb == "MSG"
        net.pump("vjt.4", devs[4].send("bot", {"t": "text", "body": "new laptop"}))
        net.drop = None
    return bot


def paced(res, t0=1000.0):
    """The CHAL messages in `res` through a Pacer at an empty bank, queued as
    PacedSender.submit_all queues them. Returns {msgid: (deadline, release
    time of each line)} and what the pacer dropped."""
    pacer = Pacer(fakelag=FakeLag())
    msgs = {}
    for target, body in res.outbound:
        msgs.setdefault(framing.parse(body).msgid, (target, []))[1].append(body)
    chals = {m: v for m, v in msgs.items() if res.urgent.get(m) is not None}
    for msgid, (target, lines) in chals.items():
        assert pacer.submit(target, lines, lane=Lane.URGENT, deadline=t0 + res.urgent[msgid])
    left, t = {}, t0
    while pacer.pending() and t is not None:
        left |= {line: t for _, line in pacer.due(t)}
        t = pacer.next_wakeup(t)
    return ({msgid: (t0 + res.urgent[msgid], [left.get(line) for line in lines])
             for msgid, (_, lines) in chals.items()}, pacer.take_dropped())


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5])
def test_a_challenge_to_every_device_leaves_at_an_empty_bank_in_time_to_be_answered(net, n):
    # One body per device: a CHAL on a session is 2 lines (8 s of bank) for
    # one device and 5 lines (23 to 24 s) for four, whose last line leaves 13
    # to 14 s after its first at an empty bank. Its window runs 15 s from
    # that last line (decision 5, amended): the pacer starts it, and the
    # peer has its 15 s once it has the whole CHAL.
    bot = devices_heard_from(net, n)
    ch, res = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                            sender_mask="vjt!vjt@host", line=LINE)
    sent, dropped = paced(res)
    assert len(sent) == (2 if n > 4 else 1)
    assert dropped == []
    for deadline, times in sent.values():
        assert deadline == 1000.0 + ch.expires_at - net.clock.t      # what the peer is told
        assert None not in times and times[-1] <= deadline - ACK_MARGIN
        assert deadline - times[-1] >= CHALLENGE_TTL - 1     # it expires at a whole second


def chal_cost(res):
    """What the CHAL lines in `res` cost the bank, as the pacer charges them."""
    return sum(line_cost(target, body) for target, body in res.outbound
               if framing.parse(body).msgid in res.urgent)


@pytest.mark.parametrize("quiet", [0, 1])
@pytest.mark.parametrize("n", [1, 2, 3, 4])
def test_a_challenge_is_sized_on_at_least_what_its_lines_cost(net, n, quiet):
    # Sized before it is encrypted, from its plaintext's length: never below
    # what its lines cost once they exist, for MSG bodies (the devices that
    # wrote to us) and for devices whose session would write a pre-key body
    # (`quiet`: the CHAL skips them, O1), whatever its length does to the
    # cipher's 16-byte blocks and to the lines.
    bot = devices_heard_from(net, n, quiet)
    peer = bot.pinned("vjt")
    for extra in range(0, 160, 5):
        now = net.clock.t = net.clock.t + 0.25
        ch, res = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                                sender_mask="vjt!vjt@" + "h" * (4 + extra), line=LINE)
        bound = bot._chal_cost("vjt", peer, len(bot._plaintext(ch.inner())))
        cost = chal_cost(res)
        assert len({framing.parse(b).msgid for _, b in res.outbound}) == (n > quiet)
        assert cost <= bound
        assert ch.expires_at == int(now) + CHALLENGE_TTL + max(0, bound - FAKE_LAG_CEILING)
        assert ch.expires_at >= int(now) + CHALLENGE_TTL + cost - FAKE_LAG_CEILING


def test_a_challenge_too_long_for_one_message_is_sized_one_message_a_device(net):
    # Two bodies past 64 fragments together go as one message each
    # (_grouped), and are sized so.
    bot = devices_heard_from(net, 2)
    ch, res = bot.challenge("vjt", network="TestNet", channel="#" + "x" * 12000,
                            sender_mask="vjt!vjt@host", line=LINE)
    assert len({framing.parse(b).msgid for _, b in res.outbound}) == 2
    bound = bot._chal_cost("vjt", bot.pinned("vjt"), len(bot._plaintext(ch.inner())))
    assert chal_cost(res) <= bound
    assert ch.expires_at == int(net.clock.t) + CHALLENGE_TTL + bound - FAKE_LAG_CEILING


def test_a_challenge_whose_lines_fit_the_bank_gets_its_15_s(net):
    # One device: two lines, under the bank's ceiling: they all leave at
    # once at an empty bank, so the window is CHALLENGE_TTL and no more.
    bot = devices_heard_from(net, 1)
    ch, res = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                            sender_mask="vjt!vjt@host", line=LINE)
    assert chal_cost(res) <= bot._chal_cost("vjt", bot.pinned("vjt"),
                                            len(bot._plaintext(ch.inner()))) <= FAKE_LAG_CEILING
    assert ch.expires_at == int(net.clock.t) + CHALLENGE_TTL
    assert set(res.urgent.values()) == {CHALLENGE_TTL}


def test_a_widened_challenge_expires_when_its_peer_is_told_it_does(net):
    bot = devices_heard_from(net, 4)
    devs = net.devices["vjt"]
    for i in range(4):
        net.take(f"vjt.{i}")
    ch, res = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                            sender_mask="vjt!vjt@host", line=LINE)
    other, more = bot.challenge("vjt", network="TestNet", channel="#sbiffo",
                                sender_mask="vjt!vjt@host", line=LINE)
    assert ch.expires_at > int(net.clock.t) + CHALLENGE_TTL
    assert other.expires_at == ch.expires_at
    assert set(res.urgent.values()) == {ch.expires_at - net.clock.t}
    net.pump("bot", res)
    told = [e.inner["expires_at"] for i in range(4) for e in net.take(f"vjt.{i}", Received)]
    assert told == [ch.expires_at] * 4
    net.clock.t = ch.expires_at
    assert not [e for e in bot.tick().events if isinstance(e, ChallengeExpired)]
    net.pump("vjt.3", devs[3].send("bot", {"t": "ack", "nonce": ch.nonce}))
    assert [e.challenge for e in net.take("bot", AckOk)] == [ch]
    net.clock.t += 1
    assert [e.challenge for e in bot.tick().events if isinstance(e, ChallengeExpired)] == [other]


def test_olm_body_bound_holds_on_vodozemac():
    # A normal message on a session that has heard back, past a chain's
    # first 128 messages (a two-byte chain index): never longer than the
    # bound, and only the chain index's spare bytes shorter.
    import vodozemac as vz
    a, b = vz.Account(), vz.Account()
    b.generate_one_time_keys(1)
    (otk,) = b.one_time_keys.values()
    out = a.create_outbound_session(b.curve25519_key, otk)
    first = vz.AnyOlmMessage.from_parts(*out.encrypt(b"hi").to_parts())
    back, _ = b.create_inbound_session(a.curve25519_key, first.to_pre_key())
    out.decrypt(vz.AnyOlmMessage.from_parts(*back.encrypt(b"ho").to_parts()))
    for i in range(300):
        size = (i * 7) % 600
        mtype, ct = out.encrypt(b"x" * size).to_parts()
        assert mtype == 1
        assert 0 <= olm_body_bound(size) - len(b64(ct)) <= 12
