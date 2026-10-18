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


def test_every_undecryptable_message_gets_its_own_nack(net):
    bot, vjt = establish(net)
    bot.forget_sessions(vjt.fingerprint)
    net.drop = lambda src, dst, body: framing.parse(body).verb != "MSG"  # NACKs vanish
    chat(net, "vjt", "bot", "a")
    chat(net, "vjt", "bot", "b")
    nacks = [p["ref"] for _, v, p in net.messages("bot") if v == "NACK"]
    assert len(set(nacks)) == 2


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


def msgid_of(result, verb=None):
    return next(f.msgid for f in (framing.parse(b) for _, b in result.outbound)
                if verb is None or f.verb == verb)


def deliver_together(net, src, dst, results):
    """Lines already in flight reach `dst` back to back; its answers go back."""
    from irc_olm.engine import Result
    out = Result()
    for r in results:
        for _, body in r.outbound:
            net.wire.append((src, dst, body))
            out.extend(net.engines[dst].receive(src, body))
    net.pump(dst, out)
    return out


def test_every_message_sent_on_a_lost_session_comes_back(net):
    bot, vjt = establish(net)
    net.clock.t += 61
    bot.forget_sessions(vjt.fingerprint)
    sent = [vjt.send("bot", {"t": "text", "body": f"m{i}"}) for i in (1, 2, 3)]
    deliver_together(net, "vjt", "bot", sent)
    assert texts(net.take("bot")) == ["m1", "m2", "m3"]       # "hi", delivered before, is not
    vjt_evs = net.take("vjt")
    assert [e for e in vjt_evs if isinstance(e, SendFailed)] == []
    assert sum(isinstance(e, Rekeying) for e in vjt_evs) == 1


def test_a_nack_burst_rekeys_once(net):
    bot, vjt = establish(net)
    net.clock.t += 61
    sent = [vjt.send("bot", {"t": "text", "body": f"m{i}"}) for i in range(5)]
    events, keyreqs = [], 0
    for r in sent:
        res = net.inject("bot", "vjt", "NACK", {"v": 1, "ref": msgid_of(r)})
        events += res.events
        keyreqs += sum(framing.parse(b).verb == "KEYREQ" for _, b in res.outbound)
    assert sum(isinstance(e, Rekeying) for e in events) == 1
    assert keyreqs == 1


def test_a_message_is_resent_once_then_reported_lost(net):
    bot, vjt = establish(net)
    net.clock.t += 61
    r = vjt.send("bot", {"t": "text", "body": "again"})
    net.take("vjt")
    ref = msgid_of(r)
    for _ in range(3):
        net.clock.t += 61
        before = len(net.wire)
        net.pump("vjt", net.inject("bot", "vjt", "NACK", {"v": 1, "ref": ref}))
        resent = [b for s, _, b in net.wire[before:]
                  if s == "vjt" and framing.parse(b).verb in ("PKMSG", "MSG")]
        if resent:
            ref = framing.parse(resent[-1]).msgid
    assert texts(net.take("bot")) == ["again"]          # one re-send, not three
    assert [(e.reason, e.lost) for e in net.take("vjt", SendFailed)] == [("resend-failed", 1)]


def test_a_nack_from_another_nick_reports_the_loss_and_resends_nothing(net):
    bot, vjt = establish(net)
    net.add("eve")
    net.pair("bot", "eve")
    out = bot.send("vjt", {"t": "text", "body": "x"}).outbound
    ref = framing.parse(out[0][1]).msgid
    res = net.inject("eve", "bot", "NACK", {"v": 1, "ref": ref})
    assert [(e.nick, e.reason, e.lost) for e in res.events if isinstance(e, SendFailed)] == \
        [("vjt", "nack-from-another-nick", 1)]
    assert res.outbound == []


def test_a_nack_for_a_nick_pinned_to_another_key_since_resends_nothing(net):
    bot, vjt = establish(net)
    out = bot.send("vjt", {"t": "text", "body": "for the old key"}).outbound
    ref = framing.parse(out[0][1]).msgid
    net.add("vjt2")
    # The operator gives "vjt" a new key and keeps the old one under another nick.
    net.pins["bot"]["vjt"] = net.engines["vjt2"].fingerprint
    net.pins["bot"]["vjtold"] = vjt.fingerprint
    bot.set_pins(net.pins["bot"])
    res = net.inject("vjt", "bot", "NACK", {"v": 1, "ref": ref})
    assert [e.reason for e in res.events if isinstance(e, SendFailed)] == ["repinned"]
    assert res.outbound == []


def test_a_rekey_after_a_repin_delivers_what_was_queued_for_the_new_key(net):
    from irc_olm.engine import SendQueued
    bot = net.add("bot")
    k1, k2 = net.add("k1"), net.add("k2")
    net.pins["bot"]["k"] = k1.fingerprint
    bot.set_pins(net.pins["bot"])
    net.pins["k2"]["bot"] = bot.fingerprint
    k2.set_pins(net.pins["k2"])
    r1 = bot.send("k", {"t": "text", "body": "for k1"})       # KEYREQ, queued for k1
    net.pins["bot"]["k"] = k2.fingerprint
    bot.set_pins(net.pins["bot"])
    r2 = bot.send("k", {"t": "text", "body": "for k2"})       # inside KEYREQ_RETRY
    assert any(isinstance(e, SendQueued) for e in r2.events)
    from irc_olm.engine import Result
    keys = k2.receive("bot", r1.outbound[0][1])               # k2 is on "k" now
    res = Result()
    for _, body in keys.outbound:
        res.extend(bot.receive("k", body))
    assert [(e.reason, e.lost) for e in res.events if isinstance(e, SendFailed)] == \
        [("key-mismatch", 1)]
    got = []
    for _, body in res.outbound:
        got += k2.receive("bot", body).events
    assert texts(got) == ["for k2"]


def test_a_nack_after_unpin_and_repin_stores_no_session_under_no_curve(net):
    import json
    bot, vjt = establish(net)
    out = bot.send("vjt", {"t": "text", "body": "x"}).outbound
    ref = framing.parse(out[0][1]).msgid
    bot.set_pins({})
    net.pin("bot", "vjt")
    net.inject("vjt", "bot", "NACK", {"v": 1, "ref": ref})
    assert None not in bot._sessions
    state = json.loads(bot.state_path.read_text())
    assert "null" not in state["sessions"]


def test_keys_after_the_queue_expired_report_no_empty_loss(net):
    from irc_olm.engine import OUTQ_TTL, OTK_SIG_PREFIX
    bot = net.add("bot")
    net.add("vjt")
    net.pair("bot", "vjt")
    bot.send("vjt", {"t": "text", "body": "x"})
    net.clock.t += OUTQ_TTL + 1
    assert [e.reason for e in bot.tick().events if isinstance(e, SendFailed)] == ["keys-timeout"]
    eve = net.add("eve")                    # not pinned: an impostor's KEYS
    otk = eve._fallback["key"]
    res = net.inject("vjt", "bot", "KEYS", {
        "v": 1, "id": eve.identity,
        "otk": {"key": otk, "fallback": True, "sig": eve._sign(OTK_SIG_PREFIX + otk)}})
    assert [e for e in res.events if isinstance(e, SendFailed)] == []


def test_a_nack_for_an_older_session_while_a_rekey_is_pending_waits_for_it(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    # Both sides open a session at once: each ends up with two.
    rb, rv = bot.send("vjt", {"t": "text", "body": "x"}), vjt.send("bot", {"t": "text", "body": "y"})
    net.pump("bot", rb)
    net.pump("vjt", rv)
    net.take("bot"), net.take("vjt")
    curve = bot.identity["curve25519"]
    ra = vjt.send("bot", {"t": "text", "body": "a"})
    first = vjt._sessions[curve][0].session_id
    vjt._sessions[curve].reverse()          # as if the bot had last used the other one
    rb2 = vjt.send("bot", {"t": "text", "body": "b"})
    assert vjt._sessions[curve][0].session_id != first   # "a" and "b" on two sessions
    net.clock.t += 61
    bot.forget_sessions(vjt.fingerprint)
    deliver_together(net, "vjt", "bot", [rb2, ra])        # "b" NACKed first: the re-key
    assert sorted(texts(net.take("bot"))) == ["a", "b"]
    vjt_evs = net.take("vjt")
    assert [e for e in vjt_evs if isinstance(e, SendFailed)] == []
    assert sum(isinstance(e, Rekeying) for e in vjt_evs) == 1
