import pytest

from irc_olm.engine import KeyAlarm, PeerPinned, Received, SendFailed


def texts(events):
    return [e.inner["body"] for e in events if isinstance(e, Received)]


def chat(net, a, b, text):
    net.pump(a, net.engines[a].send(b, {"t": "text", "body": text}))


def test_first_sight_pins_the_key_unverified(net):
    net.add("bot"), net.add("vjt")
    chat(net, "vjt", "bot", "hi")
    (pinned,) = net.take("bot", PeerPinned)
    assert pinned.peer.ed25519 == net.engines["vjt"].fingerprint
    assert pinned.peer.verified is False
    assert net.engines["bot"].pinned("VJT").ed25519 == net.engines["vjt"].fingerprint  # folded


def test_nick_change_keeps_the_pin_and_updates_the_hint(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    chat(net, "vjt", "bot", "hi")
    chat(net, "bot", "vjt", "hello")
    net.take("bot")
    net.engines["vjt_"] = vjt   # same engine (same key), new nick
    net.events["vjt_"] = []
    chat(net, "vjt_", "bot", "renamed")
    evs = net.take("bot")
    assert texts(evs) == ["renamed"]
    assert not any(isinstance(e, KeyAlarm) for e in evs)
    assert bot.peer(vjt.fingerprint).nick == "vjt_"
    assert bot.pinned("vjt").ed25519 == vjt.fingerprint


def test_a_new_key_on_a_pinned_nick_is_an_alarm_never_a_replace(net, tmp_path):
    bot, vjt = net.add("bot"), net.add("vjt")
    chat(net, "vjt", "bot", "hi")
    bot.verify(vjt.fingerprint)
    net.take("bot")
    # vjt's storage is wiped: a brand new identity under the same nick.
    (tmp_path / "vjt.testnet.state.json").unlink()
    impostor = net.add("vjt")
    assert impostor.fingerprint != vjt.fingerprint
    chat(net, "vjt", "bot", "it's me, really")
    evs = net.take("bot")
    (alarm,) = [e for e in evs if isinstance(e, KeyAlarm)]
    assert alarm.pinned.ed25519 == vjt.fingerprint and alarm.pinned.verified
    assert alarm.presented.ed25519 == impostor.fingerprint and not alarm.presented.verified
    # the message is delivered, attributed to the NEW, unverified key
    (msg,) = [e for e in evs if isinstance(e, Received)]
    assert msg.peer.ed25519 == impostor.fingerprint and not msg.peer.verified
    # and the pin did not move
    assert bot.pinned("vjt").ed25519 == vjt.fingerprint


def test_keys_from_a_different_key_never_receive_what_was_queued_for_the_pin(net, tmp_path):
    bot, vjt = net.add("bot"), net.add("vjt")
    chat(net, "vjt", "bot", "hi")
    bot.verify(vjt.fingerprint)
    bot.forget_sessions(vjt.fingerprint)  # e.g. after a NACK
    (tmp_path / "vjt.testnet.state.json").unlink()
    impostor = net.add("vjt")
    net.take("bot"), net.take("vjt")
    chat(net, "bot", "vjt", "secret for the real vjt")
    evs = net.take("bot")
    assert any(isinstance(e, KeyAlarm) for e in evs)
    (failed,) = [e for e in evs if isinstance(e, SendFailed)]
    assert failed.reason == "key-mismatch" and failed.lost == 1
    assert texts(net.take("vjt")) == []
    assert not any(verb in ("PKMSG", "MSG") for src, verb, _ in net.messages("bot")[-1:])


def test_verifying_the_new_key_moves_the_pin(net, tmp_path):
    bot, vjt = net.add("bot"), net.add("vjt")
    chat(net, "vjt", "bot", "hi")
    (tmp_path / "vjt.testnet.state.json").unlink()
    new = net.add("vjt")
    chat(net, "vjt", "bot", "new phone")
    bot.verify(new.fingerprint)
    assert bot.pinned("vjt").ed25519 == new.fingerprint
    assert bot.peer(new.fingerprint).verified


def test_pins_and_verification_survive_a_restart(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    chat(net, "vjt", "bot", "hi")
    bot.verify(vjt.fingerprint)
    bot = net.restart("bot")
    assert bot.pinned("vjt").verified


def test_a_forged_identity_signature_is_dropped(net):
    from irc_olm import framing
    from irc_olm.engine import Dropped
    bot, vjt, eve = net.add("bot"), net.add("vjt"), net.add("eve")
    res = eve.send("bot", {"t": "text", "body": "x"})
    net.pump("eve", res)
    net.take("bot")
    # eve re-sends a PKMSG claiming vjt's Ed25519 key with eve's curve key
    out = eve.send("bot", {"t": "text", "body": "i am vjt"}).outbound
    p = framing.decode_payload("".join(framing.parse(b).chunk for _, b in out))
    p["id"]["ed25519"] = vjt.fingerprint
    for body in framing.fragment("PKMSG", framing.encode_payload(p), own_mask="eve!e@h", target="bot"):
        res = bot.receive("eve", body)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["bad-identity-signature"]
    assert texts(res.events) == []
