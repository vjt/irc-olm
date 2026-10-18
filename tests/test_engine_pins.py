import pytest

from irc_olm import framing
from irc_olm.engine import Dropped, KeyAlarm, Received, SendFailed


def texts(events):
    return [e.inner["body"] for e in events if isinstance(e, Received)]


def chat(net, a, b, text):
    net.pump(a, net.engines[a].send(b, {"t": "text", "body": text}))


def test_unpinned_peer_gets_silence_no_keys_no_nack(net):
    bot, eve = net.add("bot"), net.add("eve")
    net.pin("eve", "bot")          # eve knows the bot's key; the bot never pinned eve
    chat(net, "eve", "bot", "hi")
    evs = net.take("bot")
    assert texts(evs) == []
    assert [v for _, v, _ in net.messages("bot")] == []   # not a single line back
    assert any(isinstance(e, Dropped) and e.reason == "unpinned-nick" for e in evs)


def test_unpinned_key_presenting_a_pkmsg_gets_silence(net):
    bot, vjt, eve = net.add("bot"), net.add("vjt"), net.add("eve")
    net.pair("bot", "vjt")
    net.pin("eve", "bot")
    # eve asks the bot's keys while pretending to be vjt (nick squatting)...
    net.engines["vjt"] = eve
    chat(net, "vjt", "bot", "it's me, vjt")
    evs = net.take("bot")
    assert texts(evs) == []
    (alarm,) = [e for e in evs if isinstance(e, KeyAlarm)]
    assert alarm.pinned == vjt.fingerprint and alarm.presented == eve.fingerprint
    # the bot answered the KEYREQ (vjt's nick IS pinned) but never the PKMSG
    assert [v for _, v, _ in net.messages("bot")] == ["KEYS"]


def test_send_to_an_unpinned_nick_fails(net):
    bot = net.add("bot")
    res = bot.send("stranger", {"t": "text", "body": "x"})
    assert res.outbound == []
    assert [e.reason for e in res.events if isinstance(e, SendFailed)] == ["unpinned-nick"]


def test_pinned_key_is_accepted_under_another_nick_and_replies_follow(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    chat(net, "vjt", "bot", "hi")
    net.take("bot")
    net.engines["vjt_"] = vjt   # same engine (same key), new nick
    net.events["vjt_"] = []
    chat(net, "vjt_", "bot", "renamed")
    assert texts(net.take("bot")) == ["renamed"]
    assert bot.pinned("vjt_").ed25519 == vjt.fingerprint
    chat(net, "bot", "vjt_", "seen you")
    assert texts(net.take("vjt_")) == ["seen you"]


def test_keys_from_another_key_never_receive_what_was_queued(net):
    bot, vjt, eve = net.add("bot"), net.add("vjt"), net.add("eve")
    net.pair("bot", "vjt")
    net.pin("eve", "bot")
    net.engines["vjt"] = eve   # eve squats vjt's nick and answers the bot's KEYREQ
    chat(net, "bot", "vjt", "secret for the real vjt")
    evs = net.take("bot")
    assert any(isinstance(e, KeyAlarm) for e in evs)
    (failed,) = [e for e in evs if isinstance(e, SendFailed)]
    assert failed.reason == "key-mismatch" and failed.lost == 1
    assert [v for _, v, _ in net.messages("bot")] == ["KEYREQ"]   # no PKMSG ever left


def test_rotation_is_a_re_paste(net, tmp_path):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    chat(net, "vjt", "bot", "old phone")
    assert texts(net.take("bot")) == ["old phone"]
    # vjt's storage is wiped: a new identity. Until re-pasted, silence.
    (tmp_path / "vjt.testnet.state.json").unlink()
    new = net.add("vjt")
    net.pin("vjt", "bot")
    chat(net, "vjt", "bot", "new phone")
    assert texts(net.take("bot")) == []
    net.pin("bot", "vjt", key=new.fingerprint)            # the operator re-pastes
    assert all(p.ed25519 != vjt.fingerprint for p in bot.peers())   # old key gone
    net.clock.t += 31
    chat(net, "vjt", "bot", "new phone, again")
    assert "new phone, again" in texts(net.take("bot"))


def test_pins_survive_a_restart_only_through_the_configuration(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    chat(net, "vjt", "bot", "hi")
    net.pins["bot"] = {}
    bot = net.restart("bot")
    assert bot.pinned("vjt") is None and bot.peers() == []


def test_a_malformed_pinned_key_is_refused(net):
    bot = net.add("bot")
    with pytest.raises(Exception):
        bot.set_pins({"vjt": "not-a-key"})


def test_a_forged_identity_signature_is_dropped(net):
    bot, vjt, eve = net.add("bot"), net.add("vjt"), net.add("eve")
    net.pair("bot", "vjt")
    net.pair("bot", "eve")
    chat(net, "eve", "bot", "x")
    net.take("bot")
    out = eve.send("bot", {"t": "text", "body": "i am vjt"}).outbound
    p = framing.decode_payload("".join(framing.parse(b).chunk for _, b in out))
    p["id"]["ed25519"] = vjt.fingerprint
    for body in framing.fragment("PKMSG", framing.encode_payload(p), own_mask="eve!e@h", target="bot"):
        res = bot.receive("eve", body)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["bad-identity-signature"]
    assert texts(res.events) == []
