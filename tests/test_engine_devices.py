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
    bot, devs = setup(net)
    # The device that writes back sorts last by key: only having been heard
    # from puts it first.
    quiet, talker = sorted(devs, key=lambda d: d.device_key)
    t, q, quiet_did = devs.index(talker), devs.index(quiet), quiet.did
    # `quiet` never writes back (its listreq is lost): its session stays a PKMSG one.
    net.drop = lambda src, dst, body: src == "alice" and framing.parse(body).src == quiet_did
    net.pump("bot", bot.send("alice", text("ciao")))
    net.pump(f"alice.{t}", talker.send("bot", text("from my phone")))   # a MSG now
    assert texts(net.take("bot")) == ["from my phone"]
    n = len(sent(net, "bot"))
    net.pump("bot", bot.send("alice", text("both")))
    assert [texts(net.take(f"alice.{i}"))[-1] for i in (t, q)] == ["both", "both"]
    assert [(v, to, set(p["bodies"])) for v, to, p in sent(net, "bot")[n:]] == [
        ("MSG", talker.did, {talker.did}), ("PKMSG", quiet.did, {quiet.did})]


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


def test_a_cert_no_newer_than_the_list_the_bot_holds_trusts_no_unlisted_device(net):
    bot, (a0, a1) = setup(net)
    net.relist("alice", [a0], 1)
    net.pump("bot", bot.send("alice", text("hi")))
    net.relist("alice", [a0, a1], 2)              # a1 paired at 2, dropped at 3:
    net.relist("alice", [a0], 3)                  # the bot sees neither list yet
    net.pump("alice.0", a0.send("bot", text("news")))
    assert bot._books[a0.fingerprint].ver == 3
    net.take("bot")
    net.pump("alice.1", a1.send("bot", text("it is me")))
    got = net.take("bot")
    assert texts(got) == [] and "stale-certificate" in [e.reason for e in got if isinstance(e, Dropped)]
    assert a1.device_key not in {d.ed25519 for d in bot.devices(a0.fingerprint)}
    net.take("alice.0"), net.take("alice.1")
    net.pump("bot", bot.send("alice", text("for alice")))
    assert texts(net.take("alice.0")) == ["for alice"] and texts(net.take("alice.1")) == []


def test_a_list_passing_a_certified_devices_version_without_it_revokes_it(net):
    from irc_olm.engine import REKEY_INTERVAL
    bot, (a0, a1) = setup(net)
    net.relist("alice", [a0], 1)
    net.pump("bot", bot.send("alice", text("hi")))
    net.relist("alice", [a0, a1], 2)
    # a1 writes on its certificate; the list it would bring never arrives.
    net.drop = lambda src, dst, body: src == "bot" and framing.parse(body).verb == "MSG"
    net.pump("alice.1", a1.send("bot", text("new laptop")))
    net.drop = None
    assert texts(net.take("bot")) == ["new laptop"]
    assert bot._sessions.get(a1.identity["curve25519"])
    n = len(net.wire)
    net.pump("bot", bot.send("alice", text("to both")))
    assert texts(net.take("alice.1"))[-1:] == ["to both"]
    ref = [framing.parse(b).msgid for s, _, b in net.wire[n:]
           if s == "bot" and framing.parse(b).verb == "MSG"][0]
    net.relist("alice", [a0], 3)
    net.clock.t += 61                             # past the listreq minute a1 used
    net.pump("alice.0", a0.send("bot", text("news")))
    assert bot._books[a0.fingerprint].ver == 3
    assert not bot._sessions.get(a1.identity["curve25519"])
    assert a1.device_key not in {d.ed25519 for d in bot.devices(a0.fingerprint)}
    net.take("bot"), net.take("alice.0"), net.take("alice.1")
    n = len(net.wire)
    net.pump("alice.1", a1.send("bot", text("still me")))
    got = net.take("bot")
    assert texts(got) == [] and [e.reason for e in got if isinstance(e, Dropped)] == ["revoked-device"]
    assert [f.verb for f in (framing.parse(b) for s, _, b in net.wire[n:] if s == "bot")
            if f.verb == "NACK"] == []              # like a dropped key: no NACK
    net.clock.t += REKEY_INTERVAL
    res = net.inject("alice.1", "bot", "NACK", {"v": 2, "ref": ref})
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["revoked-device"]
    assert not [e for e in res.events if isinstance(e, Rekeying)] and res.outbound == []
    net.pump("bot", bot.send("alice", text("for alice")))
    assert texts(net.take("alice.0")) == ["for alice"] and texts(net.take("alice.1")) == []


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


def test_more_trusted_devices_than_a_message_holds_go_in_two_messages(net):
    from irc_olm.devices import MAX_DEVICES
    bot, devs = setup(net, 5)                     # a0..a3 listed
    net.pump("bot", bot.send("alice", text("hi")))
    net.relist("alice", devs[:3] + devs[4:], 2)   # a4 replaces a3
    # a4 writes first; the list that drops a3 has not reached the bot yet.
    net.drop = lambda src, dst, body: src == "bot" and framing.parse(body).verb == "MSG"
    net.pump("alice.4", devs[4].send("bot", text("new laptop")))
    net.drop = None
    assert texts(net.take("bot")) == ["new laptop"]
    n = len(sent(net, "bot"))
    net.pump("bot", bot.send("alice", text("welcome")))
    assert [texts(net.take(f"alice.{i}"))[-1:] for i in range(5)] == [["welcome"]] * 5
    groups = [set(p["bodies"]) for v, _, p in sent(net, "bot")[n:] if v in ("MSG", "PKMSG")]
    assert sorted(map(len, groups[:2])) == [1, MAX_DEVICES]
    assert set().union(*groups[:2]) == {d.did for d in devs}
    assert net.take("bot", SendFailed) == []


def held(net, n, verb, src=None):
    """The `verb` lines alice's side put on the wire since `n`, from the
    device address `src` if given: what net.drop held back is there too."""
    return [b for s, _, b in net.wire[n:] if s == "alice" and framing.parse(b).verb == verb
            and src in (None, framing.parse(b).src)]


def nacked_inside_the_budget(net):
    """Three devices: a1's grappa holds no keys for it, so every send asks;
    a0 and a2 restored old backups and NACK "two", and their NACKs come in
    after the KEYS that "two"'s KEYREQ drew. Returns the bot, the devices and
    the two NACK lines, a0's first, not delivered yet."""
    from irc_olm.engine import REKEY_INTERVAL
    bot, (a0, a1, a2) = setup(net, 3)
    net.no_keys = {a1.device_key}
    net.pump("bot", bot.send("alice", text("one")))       # a KEYREQ at t=0
    net.clock.t += REKEY_INTERVAL + 1
    a0.forget_sessions(bot.fingerprint)
    a2.forget_sessions(bot.fingerprint)
    n = len(net.wire)
    net.drop = lambda src, dst, body: src == "alice"      # alice's side answers late
    net.pump("bot", bot.send("alice", text("two")))       # a KEYREQ at t=61
    net.drop = None
    for line in held(net, n, "KEYS"):             # a0 and a2 still look fine: opens nothing
        bot.receive("alice", line)
    return bot, (a0, a1, a2), held(net, n, "NACK")


def test_a_rekey_inside_the_keyreq_budget_waits_for_it_and_later_nacks_join(net):
    from irc_olm.engine import KEYREQ_RETRY
    bot, (a0, a1, a2), nacks = nacked_inside_the_budget(net)
    net.clock.t += 1
    first = bot.receive("alice", nacks[0])
    assert [e.device for e in first.events if isinstance(e, Rekeying)] == [a0.device_key]
    assert first.outbound == []                   # one KEYREQ per nick per 30 s
    net.clock.t += 1
    second = bot.receive("alice", nacks[1])       # joins the re-key under way
    assert not [e for e in second.events if isinstance(e, (Rekeying, SendFailed))]
    assert second.outbound == []
    net.clock.t += KEYREQ_RETRY - 2
    net.pump("bot", bot.tick())                   # t=91: due, and asked
    assert [texts(net.take(f"alice.{i}"))[-1:] for i in (0, 2)] == [["two"], ["two"]]
    assert net.take("bot", SendFailed) == []


def test_a_due_rekey_asks_nothing_of_a_nick_unpinned_since(net):
    from irc_olm.engine import KEYREQ_RETRY
    bot, (a0, a1, a2), nacks = nacked_inside_the_budget(net)
    net.clock.t += 1
    assert [e for e in bot.receive("alice", nacks[0]).events if isinstance(e, Rekeying)]
    bot.set_pins({})
    net.clock.t += KEYREQ_RETRY
    assert bot.tick().outbound == []
    bot.set_pins({"alice": a0.fingerprint})       # and forgotten, not just skipped
    assert bot.tick().outbound == []


def test_a_rekey_whose_keys_open_nothing_still_counts_for_the_minute(net):
    from irc_olm.engine import REKEY_INTERVAL
    bot, (a0, a1) = setup(net)
    net.pump("bot", bot.send("alice", text("one")))
    net.clock.t += REKEY_INTERVAL + 1
    a0.forget_sessions(bot.fingerprint)
    a1.forget_sessions(bot.fingerprint)
    net.no_keys = {a0.device_key, a1.device_key}  # and their grappa holds no keys
    n, a1_did = len(net.wire), a1.did
    net.drop = lambda src, dst, body: src == "alice" and framing.parse(body).src == a1_did
    net.pump("bot", bot.send("alice", text("two")))       # a0's NACK: a re-key, for nothing
    net.drop = None
    assert [e.device for e in net.take("bot", Rekeying)] == [a0.device_key]
    net.clock.t += 10
    late = bot.receive("alice", held(net, n, "NACK", a1_did)[0])
    assert [e.reason for e in late.events if isinstance(e, SendFailed)] == ["rekey-throttled"]
    assert not [e for e in late.events if isinstance(e, Rekeying)] and late.outbound == []


def payload_of(res, verb):
    return framing.decode_payload("".join(
        f.chunk for f in (framing.parse(b) for _, b in res.outbound) if f.verb == verb))


@pytest.mark.parametrize("path", ["keys", "list"])
def test_a_revoked_devices_sessions_go_whichever_way_the_list_came(net, path):
    from irc_olm.engine import KEYREQ_RETRY
    bot, (a0, a1, a2) = setup(net, 3)
    net.no_keys = {a2.device_key}                 # so that a later send asks for keys
    net.pump("bot", bot.send("alice", text("one")))
    curve = a1.identity["curve25519"]
    assert bot._sessions.get(curve)
    net.relist("alice", [a0, a2], 2)              # a1 is stolen
    net.clock.t += KEYREQ_RETRY
    if path == "keys":
        net.pump("bot", bot.send("alice", text("two")))           # its KEYS holds list 2
    else:
        net.pump("alice.0", a0.send("bot", text("I revoked a1")))  # its lv draws list 2
    assert bot._books[a0.fingerprint].ver == 2
    assert curve not in bot._sessions


def test_keys_open_no_new_session_to_a_device_whose_session_works(net):
    from irc_olm.engine import KEYREQ_RETRY
    bot, (a0, a1) = setup(net)
    net.no_keys = {a1.device_key}
    net.pump("bot", bot.send("alice", text("one")))
    curve = a0.identity["curve25519"]
    working = [s.session_id for s in bot._sessions[curve]]
    net.no_keys = set()
    net.clock.t += KEYREQ_RETRY
    net.pump("bot", bot.send("alice", text("two")))       # its KEYS holds a0's entry too
    assert texts(net.take("alice.1")) == ["one", "two"]
    assert [s.session_id for s in bot._sessions[curve]] == working


def test_a_msg_reframed_as_another_devices_is_dropped(net):
    bot, (a0, a1) = setup(net)
    net.pump("bot", bot.send("alice", text("hi")))
    p = payload_of(a0.send("bot", text("from a0")), "MSG")
    res = net.inject("alice.0", "bot", "MSG", p, frm=a1.did)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["from-mismatch"]
    assert texts(res.events) == [] and res.outbound == []


def test_a_copy_that_reached_a_device_is_not_lost_to_a_full_queue(net):
    from irc_olm.engine import OUTQ_MAX
    bot, (a0, a1) = setup(net)
    net.no_keys = {a1.device_key}                 # every copy for a1 waits
    for i in range(OUTQ_MAX + 1):
        net.pump("bot", bot.send("alice", text(f"m{i}")))
    assert len(texts(net.take("alice.0"))) == OUTQ_MAX + 1
    assert net.take("bot", SendFailed) == []


def test_a_nack_from_a_device_revoked_since_is_dropped_and_rekeys_nothing(net):
    from irc_olm.engine import REKEY_INTERVAL
    bot, (a0, a1, a2) = setup(net, 3)
    net.pump("bot", bot.send("alice", text("one")))
    ref = [framing.parse(b).msgid for s, _, b in net.wire
           if s == "bot" and framing.parse(b).verb == "PKMSG"][0]
    net.relist("alice", [a0, a2], 2)
    net.pump("alice.0", a0.send("bot", text("I revoked a1")))
    assert bot._books[a0.fingerprint].ver == 2
    net.clock.t += REKEY_INTERVAL
    res = net.inject("alice.1", "bot", "NACK", {"v": 2, "ref": ref})
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["revoked-device"]
    assert not [e for e in res.events if isinstance(e, Rekeying)] and res.outbound == []


def test_unpinning_a_master_forgets_its_devices_but_not_its_list(net):
    from irc_olm.engine import KEYREQ_RETRY
    bot, (a0, a1) = setup(net)
    net.pump("bot", bot.send("alice", text("one")))
    bot.set_pins({})
    bot.set_pins({"alice": a0.fingerprint})
    assert bot.devices(a0.fingerprint) == []
    assert bot._books[a0.fingerprint].ver == 1    # a re-pin cannot roll it back
    net.clock.t += KEYREQ_RETRY
    res = bot.send("alice", text("two"))
    assert [framing.parse(b).verb for _, b in res.outbound] == ["KEYREQ"]


def test_the_engines_inner_fields_are_its_own_both_ways(net, monkeypatch):
    import json
    bot, (a0,) = setup(net, 1)

    def first_wins(text):
        # RFC 8259 leaves two equal names open: a peer whose parser keeps the
        # first must still read our `fb`, never one the application wrote.
        def pairs(items):
            out = {}
            for k, v in items:
                out.setdefault(k, v)
            return out
        return json.loads(text, object_pairs_hook=pairs)
    monkeypatch.setattr(framing, "loads", first_wins)
    net.pump("bot", bot.send("alice", {"t": "text", "body": "x", "lv": 99, "fb": "forged"}))
    (got,) = net.take("alice.0", Received)
    assert got.inner == {"t": "text", "body": "x"}


def test_a_first_session_the_device_cannot_open_is_rekeyed_at_once(net):
    # The minute counts re-keys after NACKs: the KEYS that opened the first
    # session is no re-key.
    from irc_olm.engine import KEYREQ_RETRY
    bot, (a0,) = setup(net, 1)
    before = a0._account.pickle(a0._key)
    serve = net._grappa_keys

    def stale(nick, asker, keyreq):               # grappa serves a one-time key
        res = serve(nick, asker, keyreq)          # the device no longer holds
        a0._account = vz.Account.from_pickle(before, a0._key)
        return res
    net._grappa_keys = stale
    net.pump("bot", bot.send("alice", text("hello")))
    net._grappa_keys = serve
    assert texts(net.take("alice.0")) == []
    assert [e.device for e in net.take("bot", Rekeying)] == [a0.device_key]
    net.clock.t += KEYREQ_RETRY
    net.pump("bot", bot.tick())
    assert texts(net.take("alice.0")) == ["hello"]
    assert net.take("bot", SendFailed) == []


def test_the_rekey_minute_runs_from_the_rekey_not_from_its_keys(net):
    from irc_olm.engine import KEYREQ_RETRY, REKEY_INTERVAL
    bot, (a0, a1, a2), nacks = nacked_inside_the_budget(net)
    net.no_keys = set()
    net.clock.t += 1
    start = net.clock.t
    assert [e for e in bot.receive("alice", nacks[0]).events if isinstance(e, Rekeying)]
    bot.receive("alice", nacks[1])                # a2 joins it
    net.clock.t += KEYREQ_RETRY - 1
    net.pump("bot", bot.tick())                   # its KEYREQ and KEYS, half a minute on
    assert [texts(net.take(f"alice.{i}"))[-1:] for i in (0, 2)] == [["two"], ["two"]]
    net.clock.t = start + REKEY_INTERVAL
    a0.forget_sessions(bot.fingerprint)           # lost again, a minute after the re-key
    net.pump("bot", bot.send("alice", text("three")))
    assert [e.device for e in net.take("bot", Rekeying)] == [a0.device_key]
    assert net.take("bot", SendFailed) == []


def test_a_keyreq_whose_keys_never_came_is_no_rekey_to_join_past_the_retry(net):
    from irc_olm.engine import KEYREQ_RETRY, REKEY_INTERVAL
    bot, devs = setup(net, 3)
    net.pump("bot", bot.send("alice", text("one")))
    net.clock.t += REKEY_INTERVAL + 1
    two = bot.send("alice", text("two"))
    (ref,) = {f.msgid for f in (framing.parse(b) for _, b in two.outbound) if f.verb == "MSG"}
    first = net.inject("alice.0", "bot", "NACK", {"v": 2, "ref": ref})   # its KEYS is lost
    assert [e.device for e in first.events if isinstance(e, Rekeying)] == [devs[0].device_key]
    net.clock.t += KEYREQ_RETRY
    late = net.inject("alice.1", "bot", "NACK", {"v": 2, "ref": ref})
    assert [e.reason for e in late.events if isinstance(e, SendFailed)] == ["rekey-throttled"]
    assert late.outbound == []


def test_a_resend_outlives_its_rekeys_wait_and_a_slow_keys(net):
    # The KEYREQ budget (30 s) and a three-device KEYS (its last line about
    # 32 s after its first, amendment O2(c)) back to back: the re-sent copy
    # is still queued when the keys land.
    from irc_olm.engine import KEYREQ_RETRY, Result
    bot, (a0, a1, a2), nacks = nacked_inside_the_budget(net)
    net.no_keys = set()
    net.clock.t += 1
    bot.receive("alice", nacks[0])                # a re-key, its KEYREQ due in 29 s
    net.clock.t += KEYREQ_RETRY - 1
    (keyreq,) = [b for _, b in bot.tick().outbound]
    lines = [b for _, b in net._grappa_keys("alice", "bot", keyreq).outbound]
    out, start = Result(), net.clock.t
    for i, line in enumerate(lines):
        while net.clock.t < start + 32 * i / (len(lines) - 1):
            net.clock.t += 1
            out.extend(bot.tick())
        out.extend(bot.receive("alice", line))
    net.pump("bot", out)
    assert texts(net.take("alice.0"))[-1:] == ["two"]
    assert [e for e in out.events if isinstance(e, SendFailed)] == []
