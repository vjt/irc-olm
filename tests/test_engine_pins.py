import pytest

from conftest import keys_payload
from irc_olm import framing
from irc_olm.devices import did, id_text
from irc_olm.engine import Dropped, KeyAlarm, Received, SendFailed


def texts(events):
    return [e.inner["body"] for e in events if isinstance(e, Received)]


def bound(engine, other):
    """The curve `engine` bound to `other`'s device, or None."""
    book = engine._books.get(other.fingerprint)
    d = book and book.device(other.device_key)
    return d.curve25519 if d else None


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


@pytest.mark.parametrize("body", ["", "AAAA"])
def test_a_pkmsg_from_an_unpinned_master_keeps_nothing_whatever_its_body(net, body):
    bot, vjt, eve = net.add("bot"), net.add("vjt"), net.add("eve")
    net.pair("bot", "vjt")
    pk = {"v": 2, "id": eve.identity, "master": eve.master_ref, "bodies": {bot.did: body}}
    res = net.inject("vjt", "bot", "PKMSG", pk, frm=eve.did)     # eve on vjt's nick
    assert [e.presented for e in res.events if isinstance(e, KeyAlarm)] == [eve.fingerprint]
    assert eve.fingerprint not in bot._books and res.outbound == []


@pytest.mark.parametrize("forged", ["id-signature", "certificate", "certificate-version",
                                    "id-of-another-master"])
def test_a_pkmsg_that_fails_its_own_signatures_is_no_alarm(net, forged):
    # Anyone can type a master key next to junk: an alarm is for a block that
    # holds together under the master it presents.
    bot, vjt, eve, mallory = net.add("bot"), net.add("vjt"), net.add("eve"), net.add("mallory")
    net.pair("bot", "vjt")
    ident, ref = dict(eve.identity), dict(eve.master_ref)
    if forged == "id-signature":
        ident["sig"] = mallory.identity["sig"]
    elif forged == "certificate":
        ref["cert"] = mallory.master_ref["cert"]
    elif forged == "certificate-version":
        ref["ver"] += 1
    else:
        ident = mallory.identity
    pk = {"v": 2, "id": ident, "master": ref, "bodies": {bot.did: "AAAA"}}
    res = net.inject("vjt", "bot", "PKMSG", pk, frm=did(ident["ed25519"]))
    assert [type(e).__name__ for e in res.events] == ["Dropped"]
    assert [e.reason for e in res.events] == ["unpinned-key"] and res.outbound == []


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
    assert bot.pinned("vjt_").master == vjt.fingerprint
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
    assert all(p.master != vjt.fingerprint for p in bot.peers())   # old key gone
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
    eve.forget_sessions(bot.fingerprint)
    net.clock.t += 61
    net.drop = lambda src, dst, body: framing.parse(body).verb == "PKMSG"
    chat(net, "eve", "bot", "i am vjt")
    net.drop = None
    p = net.captured("PKMSG", "eve")[-1]
    p["id"]["ed25519"] = vjt.device_key       # eve's signature, vjt's device key
    res = net.inject("eve", "bot", "PKMSG", p, frm=vjt.did)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["bad-identity-signature"]
    assert texts(res.events) == []


def test_a_pkmsg_whose_from_is_not_its_devices_did_is_dropped(net):
    bot = net.add("bot")
    net.add("vjt")
    net.pair("bot", "vjt")
    net.drop = lambda src, dst, body: framing.parse(body).verb == "PKMSG"
    chat(net, "vjt", "bot", "hi")
    net.drop = None
    (pk,) = net.captured("PKMSG", "vjt")
    res = net.inject("vjt", "bot", "PKMSG", pk, frm=bot.did)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["from-mismatch"]
    assert texts(res.events) == [] and res.outbound == []


# --- review of 4a9b057: authentication before any state moves -------------

def _flipped(payload):
    import base64

    def flip(b):
        raw = bytearray(base64.b64decode(b + "=" * (-len(b) % 4)))
        raw[-1] ^= 1
        return base64.b64encode(bytes(raw)).decode().rstrip("=")
    return {**payload, "bodies": {k: flip(b) for k, b in payload["bodies"].items()}}


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
    """`signer`'s device claiming `curve` under `signer`'s master: a valid
    signature over a curve it may not hold."""
    return {"ed25519": signer.device_key, "curve25519": curve,
            "sig": signer._sign(id_text(curve, signer.fingerprint))}


def test_a_curve_bound_to_one_pinned_key_cannot_be_claimed_by_another(net):
    bot, vjt, eve = net.add("bot"), net.add("vjt"), net.add("eve")
    net.pair("bot", "vjt")
    net.pair("bot", "eve")
    chat(net, "vjt", "bot", "hi")
    net.take("bot")
    # eve replays vjt's PKMSG under her own key, signing vjt's curve with it:
    # a valid signature over a curve she does not hold (unknown key-share).
    (pk,) = net.captured("PKMSG", "vjt")
    res = net.inject("eve", "bot", "PKMSG", {**pk, "id": _claim(eve, vjt.identity["curve25519"]),
                                             "master": eve.master_ref})
    assert texts(res.events) == []
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["curve-already-bound"]
    assert bound(bot, eve) is None


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
    assert bound(bot, eve) is None
    chat(net, "vjt", "bot", "the real vjt")
    assert texts(net.take("bot")) == ["the real vjt"]
    assert texts(net.inject("eve", "bot", "PKMSG", pk).events) == ["mine"]


def test_a_padded_pin_is_the_key_and_a_padded_key_on_the_wire_is_malformed(net):
    # The configuration is canonicalised; the wire has one spelling per key
    # (wire v2, "Encodings"), so two spellings never both pass.
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pin("bot", "vjt", key=vjt.fingerprint + "=")
    net.pin("vjt", "bot")
    assert [p.master for p in bot.peers()] == [vjt.fingerprint]
    net.drop = lambda src, dst, body: framing.parse(body).verb == "PKMSG"
    chat(net, "vjt", "bot", "padded")
    net.drop = None
    (pk,) = net.captured("PKMSG", "vjt")
    padded = {**pk, "id": {**pk["id"], "ed25519": pk["id"]["ed25519"] + "="}}
    res = net.inject("vjt", "bot", "PKMSG", padded)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["malformed-id"]
    padded = {**pk, "master": {**pk["master"], "ed25519": vjt.fingerprint + "="}}
    res = net.inject("vjt", "bot", "PKMSG", padded)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["invalid-master"]
    assert texts(net.inject("vjt", "bot", "PKMSG", pk).events) == ["padded"]


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


def _keys(signer, curve, otk):
    from irc_olm.engine import OTK_SIG_PREFIX
    return {"v": 2, "master": signer.master_block, "devices": [{
        "id": _claim(signer, curve),
        "otk": {"key": otk, "fallback": True, "sig": signer._sign(OTK_SIG_PREFIX + otk)}}]}


def test_a_pinned_key_claiming_our_own_curve_is_refused(net):
    # Else it could hand us our own fallback key as its one-time key and
    # reflect our own PKMSG back to us as its message.
    bot, eve = net.add("bot"), net.add("eve")
    net.pin("bot", "eve")
    bot.send("eve", {"t": "text", "body": "for eve"})
    res = net.inject("eve", "bot", "KEYS", _keys(eve, bot.identity["curve25519"],
                                                 bot._fallback["key"]))
    assert "own-identity" in [e.reason for e in res.events if isinstance(e, Dropped)]
    # Nothing reachable: the queue waits, to be reported if it expires.
    assert [e for e in res.events if isinstance(e, SendFailed)] == []
    assert res.outbound == []
    assert bound(bot, eve) is None


def test_our_own_key_in_the_pins_is_never_a_peer(net):
    bot = net.add("bot")
    net.add("vjt")
    net.pair("bot", "vjt")
    chat(net, "vjt", "bot", "hi")
    (pk,) = net.captured("PKMSG", "vjt")
    net.pins["bot"]["me"] = bot.fingerprint
    bot.set_pins(net.pins["bot"])
    res = net.inject("me", "bot", "PKMSG", {**pk, "id": bot.identity, "master": bot.master_ref},
                     frm=bot.did)
    assert texts(res.events) == []
    assert "own-identity" in [e.reason for e in res.events if isinstance(e, Dropped)]


def test_a_curve_claimed_through_keys_never_locks_its_owner_out(net):
    import vodozemac as vz
    bot, vjt, eve = net.add("bot"), net.add("vjt"), net.add("eve")
    net.pair("bot", "vjt")
    net.pin("bot", "eve")
    bot.send("eve", {"t": "text", "body": "for eve"})        # KEYREQ to eve
    # eve answers claiming vjt's curve (public), before vjt ever talked
    junk = vz.Account().curve25519_key.to_base64()
    net.inject("eve", "bot", "KEYS", _keys(eve, vjt.identity["curve25519"], junk))
    chat(net, "vjt", "bot", "the real vjt")
    (got,) = [e for e in net.take("bot") if isinstance(e, Received)]
    assert got.peer.master == vjt.fingerprint and got.device == vjt.device_key
    assert bound(bot, vjt) == vjt.identity["curve25519"]
    assert bound(bot, eve) is None                           # the claim is gone
    bot2 = net.restart("bot")
    chat(net, "bot", "vjt", "after a restart")
    assert texts(net.take("vjt")) == ["after a restart"]
    assert bound(bot2, vjt) == vjt.identity["curve25519"]


def test_keys_cannot_claim_a_curve_another_key_already_claimed(net):
    import vodozemac as vz
    bot, vjt, eve = net.add("bot"), net.add("vjt"), net.add("eve")
    net.pin("bot", "vjt")
    net.pin("bot", "eve")
    bot.send("vjt", {"t": "text", "body": "for vjt"})
    bot.send("eve", {"t": "text", "body": "for eve"})
    curve = vz.Account().curve25519_key.to_base64()
    junk = vz.Account().curve25519_key.to_base64()
    net.inject("vjt", "bot", "KEYS", _keys(vjt, curve, junk))
    res = net.inject("eve", "bot", "KEYS", _keys(eve, curve, junk))
    assert "curve-already-bound" in [e.reason for e in res.events if isinstance(e, Dropped)]
    assert res.outbound == []


def _as_nick(net, src, as_nick, dst, result):
    """`src` speaks to `dst` from the nick `as_nick`, until the wire is quiet."""
    events, queue = [], [("up", result)]
    while queue:
        way, r = queue.pop(0)
        for _, body in r.outbound:
            if way == "up":
                rr = net.engines[dst].receive(as_nick, body)
                events += rr.events
                queue.append(("down", rr))
            else:
                queue.append(("up", net.engines[src].receive(dst, body)))
    return events


def test_a_nick_hint_belongs_to_the_key_that_spoke_from_it_last(net):
    bot, a, c = net.add("bot"), net.add("a"), net.add("c")
    net.pair("bot", "a")
    net.pair("bot", "c")
    chat(net, "a", "bot", "a1")
    chat(net, "c", "bot", "c1")
    _as_nick(net, "a", "x", "bot", a.send("bot", {"t": "text", "body": "a from x"}))
    _as_nick(net, "c", "x", "bot", c.send("bot", {"t": "text", "body": "c from x"}))
    assert bot.pinned("x").master == c.fingerprint
    assert bot.pinned("a").master == a.fingerprint           # a is back to its own nick


def test_lines_carrying_a_pinned_key_from_an_unmapped_nick_get_no_nack(net):
    net.add("bot")
    vjt = net.add("vjt")
    net.pair("bot", "vjt")
    chat(net, "vjt", "bot", "hi")
    chat(net, "bot", "vjt", "hello")
    (pk,) = net.captured("PKMSG", "vjt")
    msg = net.captured("MSG", "bot")[-1]
    for nick in ("mallory1", "mallory2"):
        replay = net.inject(nick, "bot", "PKMSG", pk)
        forged = net.inject(nick, "bot", "MSG", {**msg, "ck": vjt.identity["curve25519"]})
        assert replay.outbound == [] and forged.outbound == []


@pytest.mark.parametrize("verb", ["PKMSG", "KEYS"])
def test_an_ed25519_key_of_33_bytes_is_dropped_not_a_panic(net, verb):
    # vodozemac 0.10 panics on it, and a PanicException is a BaseException.
    import base64
    bot = net.add("bot")
    ed = base64.b64encode(bytes(33)).decode()
    ident = {"ed25519": ed, "curve25519": "A", "sig": "A"}
    if verb == "KEYS":
        net.add("vjt")
        net.pin("bot", "vjt")
        bot.send("vjt", {"t": "text", "body": "x"})
        payload = {"v": 2, "master": net.engines["vjt"].master_block,
                   "devices": [{"id": ident, "otk": {"key": "A", "fallback": True, "sig": "A"}}]}
    else:
        payload = {"v": 2, "id": ident, "master": {"ed25519": ed, "ver": 1, "cert": "A" * 86},
                   "bodies": {bot.did: "A"}}
    res = net.inject("vjt" if verb == "KEYS" else "mallory", "bot", verb, payload)
    assert [e for e in res.events if isinstance(e, Dropped)]


def test_a_pinned_key_of_33_bytes_is_a_value_error(net):
    import base64
    bot = net.add("bot")
    with pytest.raises(ValueError):
        bot.set_pins({"vjt": base64.b64encode(bytes(33)).decode()})


def test_a_panic_from_vodozemac_on_wire_input_is_a_drop(net, monkeypatch):
    import vodozemac as vz
    PanicException = type("PanicException", (BaseException,), {})
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    msg = vjt.send("bot", {"t": "text", "body": "x"})        # KEYREQ
    keys = bot.receive("vjt", msg.outbound[0][1])

    def panic(*a):
        raise PanicException("copy_from_slice")
    monkeypatch.setattr(vz.Account, "create_outbound_session", panic, raising=False)
    from irc_olm.engine import Result
    res = Result()
    for _, body in keys.outbound:
        res.extend(vjt.receive("bot", body))
    assert "bad-payload:PanicException" in [e.reason for e in res.events if isinstance(e, Dropped)]


def test_only_a_pre_key_message_proves_a_curve_and_the_proof_survives_a_restart(net):
    import json

    def proven(engine):
        doc = json.loads(engine.state_path.read_text())
        vjt = net.engines["vjt"]
        return doc["books"][vjt.fingerprint]["devices"][vjt.device_key]["proven"]

    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    chat(net, "bot", "vjt", "hello")          # KEYREQ, KEYS: our session, a claim
    chat(net, "vjt", "bot", "hi back")        # a MSG on it: a relay could have made that
    assert proven(bot) is False
    vjt.forget_sessions(bot.fingerprint)
    net.clock.t += 61
    chat(net, "vjt", "bot", "a session of its own")   # its PKMSG: proven
    assert proven(bot) is True
    net.restart("bot").set_pins(net.pins["bot"])
    assert proven(bot) is True


def test_a_pinned_key_relaying_another_ones_session_never_owns_its_curve(net):
    # mal claims bob's curve and hands us bob's own one-time key; bob's
    # messages then decrypt on "mal's" session. That proves bob holds the
    # curve, not that mal does: bob's first pre-key message takes it back.
    # Wire v2 closes the relay itself: the pre-key body names the device it
    # was built for (`fb`), so bob refuses what we built for mal's device.
    from irc_olm.engine import OTK_SIG_PREFIX
    bot, bob, mal = net.add("bot"), net.add("bob"), net.add("mal")
    for x, y in [("bot", "bob"), ("bot", "mal"), ("bob", "mal")]:
        net.pair(x, y)
    bob_curve = bob.identity["curve25519"]
    otk = keys_payload(net, "bob", "mal")["devices"][0]["otk"]["key"]
    bot.send("mal", {"t": "text", "body": "for mal"})
    r = net.inject("mal", "bot", "KEYS", {
        "v": 2, "master": mal.master_block, "devices": [{
            "id": _claim(mal, bob_curve),
            "otk": {"key": otk, "fallback": False, "sig": mal._sign(OTK_SIG_PREFIX + otk)}}]})
    (pk,) = [p for _, v, p in _messages(r) if v == "PKMSG"]
    # mal forwards our PKMSG to bob, re-addressed: bob's curve and one-time
    # key open the session, and the binding refuses it.
    fwd = net.inject("bot", "bob", "PKMSG", {**pk, "bodies": {bob.did: pk["bodies"][mal.did]}})
    assert [e.reason for e in fwd.events if isinstance(e, Dropped)] == ["inner-key-mismatch"]
    assert texts(fwd.events) == [] and bob.devices(bot.fingerprint) == []
    chat(net, "bob", "bot", "bob, a session of his own")
    (got,) = [e for e in net.take("bot") if isinstance(e, Received)]
    assert got.peer.master == bob.fingerprint
    assert bound(bot, bob) == bob_curve
    assert bound(bot, mal) is None


def _messages(res):
    """The logical messages in a Result: [(src, verb, payload)]."""
    out, open_ = [], {}
    for _, line in res.outbound:
        f = framing.parse(line)
        buf = open_.setdefault(f.msgid, [])
        buf.append(f.chunk)
        if len(buf) == f.total:
            out.append((f.src, f.verb, framing.decode_payload("".join(buf))))
    return out


def test_a_wire_v1_state_file_is_refused_not_misread(net):
    # Wire v2 is a new identity (a master key), and flag-day: the operator
    # moves the old state away and re-pins.
    import json
    from irc_olm.engine import StateMismatchError
    bot = net.add("bot")
    doc = json.loads(bot.state_path.read_text())
    bot.state_path.write_text(json.dumps({**doc, "v": 1}))
    with pytest.raises(StateMismatchError, match="re-pin"):
        net.restart("bot")
