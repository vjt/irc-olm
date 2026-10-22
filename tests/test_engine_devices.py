"""A bot talking to a user with several devices under one master (wire v2,
grappa-irc#2430): one message per nick with a body per trusted device,
revocation, certificates, NACKs per device."""

import pytest
import vodozemac as vz

from conftest import keys_payload
from irc_olm import framing
from irc_olm.devices import binding
from irc_olm.engine import (OTK_SIG_PREFIX, Dropped, Received, Rekeying, Replayed, SendFailed,
                            encode_inner)
from irc_olm.keys import b64


def texts(events):
    return [e.inner["body"] for e in events if isinstance(e, Received)]


def text(body):
    return {"t": "text", "body": body}


def setup(net, n=2):
    bot = net.add("bot")
    devs = net.add_user("alice", n)
    net.pin("bot", "alice")
    net.pin("alice", "bot")
    return bot, devs


def sent(net, sender):
    """`sender`'s logical messages on the wire: [(verb, to, payload)]."""
    out, open_ = [], {}
    for src, _, line in net.wire:
        if src != sender:
            continue
        f = framing.parse(line)
        buf = open_.setdefault(f.msgid, [])
        buf.append(f.chunk)
        if len(buf) == f.total:
            out.append((f.verb, f.dst, framing.decode_payload("".join(buf))))
    return out


def test_a_first_message_to_two_devices_is_one_pkmsg_with_a_body_each(net):
    bot, (a0, a1) = setup(net)
    net.pump("bot", bot.send("alice", text("ciao")))
    assert texts(net.take("alice.0")) == ["ciao"] and texts(net.take("alice.1")) == ["ciao"]
    msgs = sent(net, "bot")
    assert [(v, to) for v, to, _ in msgs[:2]] == [("KEYREQ", "*"), ("PKMSG", "*")]
    assert set(msgs[1][2]["bodies"]) == {a0.did, a1.did}
    # Each device then asks for the bot's list (our `lv` is news to it), and
    # gets it, on its own session: MSGs, one body each.
    assert sorted((v, to) for v, to, _ in msgs[2:]) == sorted([("MSG", a0.did), ("MSG", a1.did)])
    assert [(v, to) for v, to, _ in sent(net, "alice")][0] == ("KEYS", bot.did)


def test_msg_and_pkmsg_bodies_never_share_a_message_and_the_last_heard_goes_first(net):
    bot, (a0, a1) = setup(net)
    a1_did = a1.did
    # a1 never writes back (its listreq is lost): its session stays a PKMSG one.
    net.drop = lambda src, dst, body: src == "alice" and framing.parse(body).src == a1_did
    net.pump("bot", bot.send("alice", text("ciao")))
    net.pump("alice.0", a0.send("bot", text("from my phone")))     # a MSG: a0's session answered
    assert texts(net.take("bot")) == ["from my phone"]
    n = len(sent(net, "bot"))
    net.pump("bot", bot.send("alice", text("both")))
    assert texts(net.take("alice.0"))[-1] == "both" and texts(net.take("alice.1"))[-1] == "both"
    assert [(v, to, set(p["bodies"])) for v, to, p in sent(net, "bot")[n:]] == [
        ("MSG", a0.did, {a0.did}), ("PKMSG", a1.did, {a1.did})]


def test_a_device_dropped_from_a_newer_list_is_revoked_for_good(net):
    bot, (a0, a1, a2) = setup(net, 3)
    net.relist("alice", [a0, a1], 1)
    net.pump("bot", bot.send("alice", text("v1")))
    net.take("alice.1")
    # a1 is stolen: alice's master lists a0 and a2 under version 2.
    net.relist("alice", [a0, a2], 2)
    bot.forget_sessions(a0.fingerprint)         # so the next send asks for keys
    net.clock.t += 61
    net.pump("bot", bot.send("alice", text("v2")))
    assert texts(net.take("alice.0"))[-1] == "v2" and texts(net.take("alice.2")) == ["v2"]
    assert texts(net.take("alice.1")) == []
    assert sorted(d.ed25519 for d in bot.devices(a0.fingerprint)) == sorted([a0.device_key, a2.device_key])

    def from_a1(bot):
        # The stolen device still holds a session, and its certificate.
        n = len(net.wire)
        net.pump("alice.1", a1.send("bot", text("send me the money")))
        got = net.take("bot")
        assert texts(got) == []
        assert "revoked-device" in [e.reason for e in got if isinstance(e, Dropped)]
        assert [f.verb for f in (framing.parse(b) for s, _, b in net.wire[n:] if s == "bot")
                if f.verb == "NACK"] == []          # not an attack: no NACK

    from_a1(bot)
    a1.forget_sessions(bot.fingerprint)           # now a PKMSG, certificate and all
    net.clock.t += 61
    from_a1(bot)
    from_a1(net.restart("bot"))                   # and it is remembered


def test_a_device_the_list_does_not_hold_yet_is_trusted_on_its_certificate(net):
    bot, (a0, a1, a2) = setup(net, 3)
    net.relist("alice", [a0, a1], 1)
    net.pump("bot", bot.send("alice", text("hi")))
    net.relist("alice", [a0, a1, a2], 2)          # the bot has not heard of a2
    net.pump("alice.2", a2.send("bot", text("new laptop")))
    (got,) = [e for e in net.take("bot") if isinstance(e, Received)]
    assert (got.inner["body"], got.peer.master, got.device) == \
        ("new laptop", a0.fingerprint, a2.device_key)
    net.pump("bot", bot.send("alice", text("welcome")))
    assert [texts(net.take(f"alice.{i}"))[-1] for i in range(3)] == ["welcome"] * 3


def test_forgetting_a_masters_sessions_forgets_every_devices(net):
    bot, devs = setup(net, 3)
    net.pump("bot", bot.send("alice", text("hi")))
    assert all(bot._sessions.get(d.identity["curve25519"]) for d in devs)
    bot.forget_sessions(devs[0].fingerprint)
    assert not any(bot._sessions.get(d.identity["curve25519"]) for d in devs)


def test_a_nack_from_one_device_resends_to_that_device_alone(net):
    bot, (a0, a1) = setup(net)
    net.pump("bot", bot.send("alice", text("one")))
    net.take("alice.0"), net.take("alice.1")
    a1.forget_sessions(bot.fingerprint)           # a1 restored an old backup
    net.clock.t += 61
    n = len(sent(net, "bot"))
    net.pump("bot", bot.send("alice", text("two")))
    assert texts(net.take("alice.0")) == ["two"]          # once
    assert texts(net.take("alice.1")) == ["two"]          # after the re-key
    assert [e.device for e in net.take("bot") if isinstance(e, Rekeying)] == [a1.device_key]
    assert [(v, to, set(p.get("bodies", ()))) for v, to, p in sent(net, "bot")[n:]] == [
        ("MSG", "*", {a0.did, a1.did}), ("KEYREQ", "*", set()), ("PKMSG", a1.did, {a1.did})]


def test_a_nack_from_a_device_the_message_never_went_to_is_ignored(net):
    bot, (a0, a1, a2) = setup(net, 3)
    net.relist("alice", [a0, a1], 1)
    net.pump("bot", bot.send("alice", text("hi")))
    (_, _, pk), = [m for m in sent(net, "bot") if m[0] == "PKMSG"]
    ref = [framing.parse(b).msgid for s, _, b in net.wire
           if s == "bot" and framing.parse(b).verb == "PKMSG"][0]
    res = net.inject("alice.2", "bot", "NACK", {"v": 2, "ref": ref})
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["unknown-nack-ref"]
    assert res.outbound == []


def test_a_listed_device_grappa_has_no_key_for_is_asked_for_again_later(net):
    from irc_olm.engine import KEYREQ_RETRY
    bot, (a0, a1) = setup(net)
    net.no_keys = {a1.device_key}
    net.pump("bot", bot.send("alice", text("one")))
    assert texts(net.take("alice.0")) == ["one"] and texts(net.take("alice.1")) == []
    net.pump("bot", bot.send("alice", text("two")))      # inside the retry: no KEYREQ
    assert [v for v, _, _ in sent(net, "bot")].count("KEYREQ") == 1
    net.no_keys = set()
    net.clock.t += KEYREQ_RETRY
    net.pump("bot", bot.send("alice", text("three")))    # now a0 at once, a1 after the keys
    assert texts(net.take("alice.0")) == ["two", "three"]
    # a1's copies waited for its keys, within OUTQ_TTL: it has the whole talk.
    assert texts(net.take("alice.1")) == ["one", "two", "three"]
    assert net.take("bot", SendFailed) == []


def test_a_copy_that_waited_too_long_for_its_device_is_not_a_lost_message(net):
    from irc_olm.engine import OUTQ_TTL
    bot, (a0, a1) = setup(net)
    net.no_keys = {a1.device_key}
    net.pump("bot", bot.send("alice", text("one")))
    assert texts(net.take("alice.0")) == ["one"]
    net.clock.t += OUTQ_TTL + 1
    assert [e for e in bot.tick().events if isinstance(e, SendFailed)] == []   # a0 had it


def test_a_pkmsg_body_bound_to_another_device_is_refused_and_its_session_too(net):
    bot, (a0, a1) = setup(net)
    otk = keys_payload(net, "bot", "alice.0")["devices"][0]["otk"]["key"]
    session = a0._account.create_outbound_session(
        vz.Curve25519PublicKey.from_base64(bot.identity["curve25519"]),
        vz.Curve25519PublicKey.from_base64(otk))
    inner = {"t": "text", "body": "x", "lv": 1, "fb": binding(a0.device_key, a1.device_key)}
    _, ct = session.encrypt(encode_inner(inner)).to_parts()
    pk = {"v": 2, "id": a0.identity, "master": a0.master_ref, "bodies": {bot.did: b64(ct)}}
    res = net.inject("alice.0", "bot", "PKMSG", pk)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["inner-key-mismatch"]
    assert texts(res.events) == [] and bot.devices(a0.fingerprint) == []
    assert [e for e in net.inject("alice.0", "bot", "PKMSG", pk).events if isinstance(e, Replayed)]


@pytest.mark.parametrize("to, n", [("*", 1), ("did", 2), ("*", 5), ("*", 0)])
def test_bodies_that_do_not_match_the_frame_are_malformed(net, to, n):
    bot, (a0,) = setup(net, 1)
    bodies = {bot.did: "AAAA"} | {f"x{i:010d}": "AAAA" for i in range(n - 1)}
    if n == 0:
        bodies = {}
    res = net.inject("alice.0", "bot", "MSG", {"v": 2, "ck": a0.identity["curve25519"],
                                               "bodies": bodies},
                     to=bot.did if to == "did" else "*")
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["malformed-bodies"]
    assert res.outbound == []


def test_a_message_too_long_for_one_message_goes_as_one_per_device(net):
    bot, devs = setup(net, 4)
    body = "x" * 9000
    net.pump("bot", bot.send("alice", text(body)))
    assert [texts(net.take(f"alice.{i}")) for i in range(4)] == [[body]] * 4
    pks = [(to, set(p["bodies"])) for v, to, p in sent(net, "bot") if v == "PKMSG"]
    assert sorted(pks) == sorted((d.did, {d.did}) for d in devs)
    assert net.take("bot", SendFailed) == []


def test_keys_entries_for_an_unlisted_device_or_another_masters_are_skipped(net):
    # Trust rule 4: a device is usable only when listed, and when its id
    # block vouches for this master (S1: no other master can list it). An
    # entry that fails is skipped; the rest of the KEYS stands.
    bot, (a0, a1, a2) = setup(net, 3)
    mallory = net.add("mallory")
    net.relist("alice", [a0, a1], 1)
    keyreq = bot.send("alice", text("x")).outbound[0][1]
    res = net._grappa_keys("alice", "bot", keyreq)
    keys = framing.decode_payload("".join(framing.parse(b).chunk for _, b in res.outbound))
    otk = keys["devices"][0]["otk"]
    keys["devices"] += [{"id": a2.identity, "otk": otk}, {"id": mallory.identity, "otk": otk}]
    res = net.inject("alice", "bot", "KEYS", keys)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == \
        ["unlisted-device", "bad-identity-signature"]
    assert sorted(d.ed25519 for d in bot.devices(a0.fingerprint)) == \
        sorted([a0.device_key, a1.device_key])


def test_keys_signed_by_another_master_on_the_nick_are_the_alarm(net):
    from irc_olm.engine import KeyAlarm
    bot, (a0,) = setup(net, 1)
    mallory = net.add("mallory")
    net.pin("mallory", "bot")
    bot.send("alice", text("x"))
    keys = keys_payload(net, "mallory", "bot")
    res = net.inject("alice", "bot", "KEYS", keys)
    (alarm,) = [e for e in res.events if isinstance(e, KeyAlarm)]
    assert (alarm.pinned, alarm.presented) == (a0.fingerprint, mallory.fingerprint)
    assert [(e.reason, e.lost) for e in res.events if isinstance(e, SendFailed)] == \
        [("key-mismatch", 1)]


def test_one_time_keys_are_signed_by_their_own_device(net):
    bot, (a0, a1) = setup(net)
    keys = keys_payload(net, "alice.0", "bot")
    otk = vz.Account().curve25519_key.to_base64()
    keys["devices"][0]["otk"] = {"key": otk, "fallback": True,
                                 "sig": a1._sign(OTK_SIG_PREFIX + otk)}
    bot.send("alice", text("x"))
    res = net.inject("alice", "bot", "KEYS", keys)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["bad-otk-signature"]
