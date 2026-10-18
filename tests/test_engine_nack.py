from irc_olm import framing
from irc_olm.engine import (Received, RekeyThrottled, Rekeying, Undecryptable)


def texts(events):
    return [e.inner["body"] for e in events if isinstance(e, Received)]


def chat(net, a, b, text):
    net.pump(a, net.engines[a].send(b, {"t": "text", "body": text}))


def establish(net):
    bot, vjt = net.add("bot"), net.add("vjt")
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
    assert any(isinstance(e, RekeyThrottled) for e in net.take("vjt"))
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
    out = bot.send("vjt", {"t": "text", "body": "x"}).outbound
    ref = framing.parse(out[0][1]).msgid
    res = bot.receive("eve", framing.fragment("NACK", framing.encode_payload({"v": 1, "ref": ref}),
                                              own_mask="eve!e@h", target="bot")[0])
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["unknown-nack-ref"]
    assert res.outbound == []
