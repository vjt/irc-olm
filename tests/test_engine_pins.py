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


# --- review of 4a9b057: authentication before any state moves -------------

def _flipped(payload):
    import base64
    raw = bytearray(base64.b64decode(payload["body"] + "=" * (-len(payload["body"]) % 4)))
    raw[-1] ^= 1
    return {**payload, "body": base64.b64encode(bytes(raw)).decode().rstrip("=")}


def test_a_forged_msg_carrying_a_pinned_curve_moves_no_nick_hint(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    chat(net, "vjt", "bot", "hi")
    chat(net, "bot", "vjt", "hello")
    net.take("bot")
    out = vjt.send("bot", {"t": "text", "body": "x"}).outbound
    msg = framing.decode_payload("".join(framing.parse(b).chunk for _, b in out))
    res = net.inject("mallory", "bot", "MSG", _flipped(msg))
    assert texts(res.events) == []
    assert bot.pinned("mallory") is None
    assert [p.nick for p in bot.peers()] == ["vjt"]


def test_a_replayed_id_block_moves_no_nick_hint(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    chat(net, "vjt", "bot", "hi")
    net.take("bot")
    (pk,) = net.captured("PKMSG", "vjt")
    res = net.inject("mallory", "bot", "PKMSG", pk)
    assert texts(res.events) == []
    assert bot.pinned("mallory") is None
    assert [p.nick for p in bot.peers()] == ["vjt"]


def _claim(signer, curve):
    from irc_olm.engine import ID_SIG_PREFIX
    return {"ed25519": signer.fingerprint, "curve25519": curve,
            "sig": signer._sign(ID_SIG_PREFIX + curve)}


def test_a_curve_bound_to_one_pinned_key_cannot_be_claimed_by_another(net):
    bot, vjt, eve = net.add("bot"), net.add("vjt"), net.add("eve")
    net.pair("bot", "vjt")
    net.pair("bot", "eve")
    chat(net, "vjt", "bot", "hi")
    net.take("bot")
    # eve replays vjt's PKMSG under her own key, signing vjt's curve with it:
    # a valid signature over a curve she does not hold (unknown key-share).
    (pk,) = net.captured("PKMSG", "vjt")
    res = net.inject("eve", "bot", "PKMSG", {**pk, "id": _claim(eve, vjt.identity["curve25519"])})
    assert texts(res.events) == []
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["curve-already-bound"]
    assert {p.ed25519: p.curve25519 for p in bot.peers()}[eve.fingerprint] is None


def test_a_claimed_curve_is_bound_only_once_a_session_proves_it(net):
    bot, vjt, eve = net.add("bot"), net.add("vjt"), net.add("eve")
    net.pair("bot", "vjt")
    net.pair("bot", "eve")
    net.drop = lambda src, dst, body: framing.parse(body).verb == "PKMSG"
    chat(net, "eve", "bot", "mine")
    net.drop = None
    (pk,) = net.captured("PKMSG", "eve")
    # eve's own ciphertext, but claiming vjt's curve (vjt never talked yet)
    res = net.inject("eve", "bot", "PKMSG", {**pk, "id": _claim(eve, vjt.identity["curve25519"])})
    assert texts(res.events) == []
    assert {p.ed25519: p.curve25519 for p in bot.peers()}[eve.fingerprint] is None
    chat(net, "vjt", "bot", "the real vjt")
    assert texts(net.take("bot")) == ["the real vjt"]
    assert texts(net.inject("eve", "bot", "PKMSG", pk).events) == ["mine"]


def test_a_padded_pin_and_a_padded_id_key_are_the_same_key(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pin("bot", "vjt", key=vjt.fingerprint + "=")
    net.pin("vjt", "bot")
    assert [p.ed25519 for p in bot.peers()] == [vjt.fingerprint]
    net.drop = lambda src, dst, body: framing.parse(body).verb == "PKMSG"
    chat(net, "vjt", "bot", "padded")
    net.drop = None
    (pk,) = net.captured("PKMSG", "vjt")
    pk["id"]["ed25519"] += "="
    res = net.inject("vjt", "bot", "PKMSG", pk)
    assert texts(res.events) == ["padded"]
    assert not [e for e in res.events if isinstance(e, KeyAlarm)]


def test_an_id_block_signed_by_the_pinned_key_over_another_curve_is_dropped(net):
    import vodozemac as vz
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    chat(net, "vjt", "bot", "hi")
    net.take("bot")
    (pk,) = net.captured("PKMSG", "vjt")
    other = vz.Account().curve25519_key.to_base64()
    res = net.inject("vjt", "bot", "PKMSG", {**pk, "id": _claim(vjt, other)})
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["identity-curve-mismatch"]


def test_what_was_queued_for_a_replaced_key_never_goes_to_the_new_one(net, tmp_path):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    net.drop = lambda src, dst, body: framing.parse(body).verb == "KEYS"
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "for the old key"}))
    net.drop = None
    # vjt's storage is wiped, and the operator re-pastes the new key
    (tmp_path / "vjt.testnet.state.json").unlink()
    new = net.add("vjt")
    net.pin("vjt", "bot")
    net.pin("bot", "vjt", key=new.fingerprint)
    net.clock.t += 31                       # the KEYREQ retry is due
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "for the new key"}))
    assert texts(net.take("vjt")) == ["for the new key"]
    assert [(e.reason, e.lost) for e in net.take("bot", SendFailed)] == [("key-mismatch", 1)]
