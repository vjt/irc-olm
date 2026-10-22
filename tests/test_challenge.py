import hashlib
import re

import pytest

from irc_olm import framing
from irc_olm.engine import (OUTQ_MAX, OUTQ_TTL, AckOk, AckRejected, ChallengeExpired,
                            NotPinnedError, Received, Result, SendFailed, SendQueued)
from irc_olm.challenge import CHALLENGE_TTL


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
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "hello"}))   # the bot opened it
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
