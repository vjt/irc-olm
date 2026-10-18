import base64
import json

import pytest

from irc_olm import framing
from irc_olm.engine import (Dropped, KeyAlarm, PeerPinned, Received, Replayed,
                            SendQueued, Undecryptable)


def texts(events):
    return [e.inner["body"] for e in events if isinstance(e, Received) and e.inner.get("t") == "text"]


def verbs(net, sender=None):
    return [verb for _, verb, _ in net.messages(sender)]


def test_first_contact_keyreq_keys_pkmsg_then_reply_as_msg(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "ciao bot"}))
    assert texts(net.take("bot")) == ["ciao bot"]
    assert verbs(net) == ["KEYREQ", "KEYS", "PKMSG"]

    net.pump("bot", bot.send("vjt", {"t": "text", "body": "ciao vjt"}))
    assert texts(net.take("vjt")) == ["ciao vjt"]
    assert verbs(net)[-1] == "MSG"

    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "now MSG too"}))
    assert texts(net.take("bot")) == ["now MSG too"]
    assert verbs(net)[-1] == "MSG"


def test_messages_sent_before_the_keys_arrive_are_queued_in_order(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    r1 = vjt.send("bot", {"t": "text", "body": "uno"})
    assert any(isinstance(e, SendQueued) for e in r1.events)
    r2 = vjt.send("bot", {"t": "text", "body": "due"})
    assert r2.outbound == []  # one KEYREQ in flight is enough
    net.pump("vjt", r1)
    assert texts(net.take("bot")) == ["uno", "due"]


def test_long_message_is_fragmented_and_reassembled(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    body = "è" * 3000
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": body}))
    assert texts(net.take("bot")) == [body]
    pk = [b for s, _, b in net.wire if framing.parse(b).verb == "PKMSG"]
    assert len(pk) > 5
    for b in pk:
        assert len(f":{framing.conservative_mask('vjt', 'vjt')} PRIVMSG bot :{b}\r\n".encode()) <= 512


def test_payloads_match_the_wire_spec(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "x"}))
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "y"}))
    by_verb = {verb: payload for _, verb, payload in net.messages()}
    assert by_verb["KEYREQ"] == {"v": 1}
    keys = by_verb["KEYS"]
    assert keys["v"] == 1 and set(keys["id"]) == {"curve25519", "ed25519", "sig"}
    assert set(keys["otk"]) == {"key", "fallback", "sig"} and keys["otk"]["fallback"] is False
    assert keys["id"] == bot.identity
    assert set(by_verb["PKMSG"]) == {"v", "id", "body"} and by_verb["PKMSG"]["id"] == vjt.identity
    assert set(by_verb["MSG"]) == {"v", "ck", "body"}
    assert by_verb["MSG"]["ck"] == bot.identity["curve25519"]
    for value in (keys["id"]["sig"], keys["otk"]["key"], by_verb["MSG"]["body"]):
        assert "=" not in value  # unpadded base64


def test_session_survives_a_restart_of_both_sides(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "a"}))
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "b"}))
    net.take("bot"), net.take("vjt")
    bot, vjt = net.restart("bot"), net.restart("vjt")
    n = len(net.messages())
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "after restart"}))
    assert texts(net.take("bot")) == ["after restart"]
    assert [verb for _, verb, _ in net.messages()[n:]] == ["MSG"]


def test_identity_is_stable_across_restarts_and_networks_are_separate(net, tmp_path):
    bot = net.add("bot")
    ident = bot.identity
    assert net.restart("bot").identity == ident
    assert net.add("bot", network="othernet").identity != ident


def test_state_file_refuses_another_network(net, tmp_path):
    from irc_olm import store
    from irc_olm.engine import Engine, StateMismatchError
    bot = net.add("bot")
    with pytest.raises(StateMismatchError):
        Engine(bot.state_path, store.load_key(tmp_path / "bot.key"), network="elsewhere",
               nick="bot", ident="bot", clock=net.clock)


def test_wrong_key_refuses_to_load(net, tmp_path):
    from irc_olm.engine import Engine
    bot = net.add("bot")
    with pytest.raises(Exception):
        Engine(bot.state_path, b"\0" * 32, network="testnet", nick="bot", ident="bot", clock=net.clock)


def test_replayed_fallback_prekey_message_is_dropped(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    # The first KEYS (with a one-time key) is lost; vjt asks again after the
    # retry interval, and a second key inside a minute is the fallback key.
    dropped = []

    def drop_first_keys(src, dst, body):
        if framing.parse(body).verb == "KEYS" and not dropped:
            dropped.append(body)
            return True
        return False

    net.drop = drop_first_keys
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "order 66"}))
    assert texts(net.take("bot")) == []
    net.drop = None
    net.clock.t += 31
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "ping"}))
    assert texts(net.take("bot")) == ["order 66", "ping"]
    pkmsg = [(s, b) for s, _, b in net.wire if framing.parse(b).verb == "PKMSG"]
    keys = [p for _, verb, p in net.messages() if verb == "KEYS"]
    assert [k["otk"]["fallback"] for k in keys] == [False, True]
    # The bot loses its session (as after a NACK), then the PKMSG is replayed.
    bot.forget_sessions(vjt.identity["ed25519"])
    for s, b in pkmsg:
        res = bot.receive(s, b)
    assert texts(res.events) == []
    assert any(isinstance(e, Replayed) for e in res.events)


def test_undecryptable_message_triggers_a_nack(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "a"}))
    net.take("bot")
    msg = vjt.send("bot", {"t": "text", "body": "lost"})   # never delivered
    res = vjt.send("bot", {"t": "text", "body": "b"})
    # b is still a PKMSG (no reply yet) on the same session: decryptable.
    net.pump("vjt", res)
    assert texts(net.take("bot")) == ["b"]
    # Garble one: same session, broken MAC.
    frags = [framing.parse(b) for _, b in vjt.send("bot", {"t": "text", "body": "c"}).outbound]
    p = framing.decode_payload("".join(f.chunk for f in frags))
    raw = bytearray(base64.b64decode(p["body"] + "=" * (-len(p["body"]) % 4)))
    raw[-1] ^= 1
    p["body"] = base64.b64encode(bytes(raw)).decode().rstrip("=")
    for body in framing.fragment(frags[0].verb, framing.encode_payload(p), own_mask="vjt!x@y", target="bot"):
        res = bot.receive("vjt", body)
    assert any(isinstance(e, Undecryptable) for e in res.events)
    assert [framing.parse(b).verb for _, b in res.outbound] == ["NACK"]


def test_unsolicited_keys_are_dropped(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    keys_from_bot = bot.receive("vjt", vjt.send("bot", {"t": "text", "body": "x"}).outbound[0][1])
    # deliver bot's KEYS to a third party that never asked
    eve = net.add("eve")
    for _, body in keys_from_bot.outbound:
        res = eve.receive("bot", body)
    assert any(isinstance(e, Dropped) and e.reason == "unsolicited-keys" for e in res.events)
    assert eve.pinned("bot") is None


def test_received_event_repr_never_shows_plaintext(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "segreto"}))
    for e in net.take("bot"):
        assert "segreto" not in repr(e)
