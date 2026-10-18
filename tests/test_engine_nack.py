from irc_olm import framing
from irc_olm.engine import (Received, Rekeying, SendFailed, Undecryptable)


def texts(events):
    return [e.inner["body"] for e in events if isinstance(e, Received)]


def chat(net, a, b, text):
    net.pump(a, net.engines[a].send(b, {"t": "text", "body": text}))


def establish(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    chat(net, "vjt", "bot", "hi")
    chat(net, "bot", "vjt", "hello")
    net.take("bot"), net.take("vjt")
    return bot, vjt


def test_wiped_session_recovers_through_nack_and_resends(net):
    bot, vjt = establish(net)
    net.clock.t += 61
    bot.forget_sessions(vjt.fingerprint)   # the bot restored an old backup, say
    chat(net, "vjt", "bot", "are you there?")
    bot_evs, vjt_evs = net.take("bot"), net.take("vjt")
    assert any(isinstance(e, Undecryptable) for e in bot_evs)
    assert any(isinstance(e, Rekeying) for e in vjt_evs)
    # vjt re-keyed and re-sent the lost message on a fresh session
    assert texts(bot_evs) == ["are you there?"]
    verbs = [v for _, v, _ in net.messages()]
    assert verbs[-5:] == ["MSG", "NACK", "KEYREQ", "KEYS", "PKMSG"]


def test_rekey_is_throttled_to_once_a_minute_per_peer(net):
    bot, vjt = establish(net)
    net.clock.t += 61
    bot.forget_sessions(vjt.fingerprint)
    chat(net, "vjt", "bot", "one")
    assert texts(net.take("bot")) == ["one"]
    net.take("vjt")
    net.clock.t += 11  # past the NACK interval, inside the re-key minute
    bot.forget_sessions(vjt.fingerprint)
    chat(net, "vjt", "bot", "two")
    assert [e.reason for e in net.take("vjt", SendFailed)] == ["rekey-throttled"]
    assert texts(net.take("bot")) == []


def test_nacks_are_rate_limited_per_nick(net):
    bot, vjt = establish(net)
    bot.forget_sessions(vjt.fingerprint)
    net.drop = lambda src, dst, body: framing.parse(body).verb != "MSG"  # NACKs vanish
    chat(net, "vjt", "bot", "a")
    chat(net, "vjt", "bot", "b")
    nacks = [v for _, v, _ in net.messages("bot") if v == "NACK"]
    assert len(nacks) == 1


def test_a_nack_for_someone_elses_message_is_ignored(net):
    from irc_olm.engine import Dropped
    bot, vjt = establish(net)
    eve = net.add("eve")
    net.pair("bot", "eve")
    out = bot.send("vjt", {"t": "text", "body": "x"}).outbound
    ref = framing.parse(out[0][1]).msgid
    res = bot.receive("eve", framing.fragment("NACK", framing.encode_payload({"v": 1, "ref": ref}),
                                              own_mask="eve!e@h", target="bot")[0])
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["unknown-nack-ref"]
    assert res.outbound == []


def test_a_late_nack_for_an_older_session_resends_on_the_fresh_one(net):
    bot, vjt = establish(net)
    net.clock.t += 61
    bot.forget_sessions(vjt.fingerprint)
    ra = vjt.send("bot", {"t": "text", "body": "a"})
    rb = vjt.send("bot", {"t": "text", "body": "b"})   # same old session
    net.pump("vjt", ra)
    assert texts(net.take("bot")) == ["a"]              # NACK, re-key, re-send
    net.clock.t += 11                                   # past the NACK interval
    net.pump("vjt", rb)
    assert net.take("vjt", SendFailed) == []
    assert texts(net.take("bot")) == ["b"]


def test_messages_sent_while_a_rekey_is_pending_wait_for_the_new_session(net):
    from irc_olm.engine import SendQueued
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    # Both sides open a session at once: each ends up with two.
    rb = bot.send("vjt", {"t": "text", "body": "x"})
    rv = vjt.send("bot", {"t": "text", "body": "y"})
    net.pump("bot", rb)
    net.pump("vjt", rv)
    assert len(vjt._sessions[bot.identity["curve25519"]]) == 2
    net.take("bot"), net.take("vjt")
    net.clock.t += 61
    bot.forget_sessions(vjt.fingerprint)                 # every session, not just one
    net.drop = lambda src, dst, body: framing.parse(body).verb == "KEYS"
    chat(net, "vjt", "bot", "z")                         # NACK -> re-key, KEYS lost
    rw = vjt.send("bot", {"t": "text", "body": "w"})
    assert any(isinstance(e, SendQueued) for e in rw.events) and rw.outbound == []
    net.drop = None
    net.clock.t += 31
    chat(net, "vjt", "bot", "v")
    assert texts(net.take("bot")) == ["z", "w", "v"]


def test_a_nack_older_than_the_resend_memory_is_ignored(net):
    from irc_olm.engine import SENT_MEMORY, Dropped
    bot, vjt = establish(net)
    out = bot.send("vjt", {"t": "text", "body": "old news"}).outbound
    ref = framing.parse(out[0][1]).msgid
    net.clock.t += SENT_MEMORY + 1
    res = net.inject("vjt", "bot", "NACK", {"v": 1, "ref": ref})
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["unknown-nack-ref"]
    assert res.outbound == []
