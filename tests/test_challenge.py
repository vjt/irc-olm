import hashlib
import re

import pytest

from irc_olm.engine import (AckOk, AckRejected, ChallengeExpired, NotVerifiedError, Received)
from irc_olm.challenge import CHALLENGE_TTL


def establish(net, verify=True):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "hi"}))
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "hello"}))
    net.take("bot"), net.take("vjt")
    if verify:
        bot.verify(vjt.fingerprint)
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
    net.pump("eve", eve.send("bot", {"t": "text", "body": "hi"}))
    bot.verify(eve.fingerprint)
    ch = chal(net, bot)
    net.pump("eve", eve.send("bot", {"t": "ack", "nonce": ch.nonce}))
    assert [e.reason for e in net.take("bot", AckRejected)] == ["wrong-peer"]
    net.pump("vjt", vjt.send("bot", {"t": "ack", "nonce": ch.nonce}))
    assert len(net.take("bot", AckOk)) == 1


def test_no_challenge_to_an_unverified_key(net):
    bot, vjt = establish(net, verify=False)
    with pytest.raises(NotVerifiedError):
        bot.challenge("vjt", network="TestNet", channel="#x", sender_mask="m", line=b"x")
    with pytest.raises(NotVerifiedError):
        bot.challenge("nobody", network="TestNet", channel="#x", sender_mask="m", line=b"x")
