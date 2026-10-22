"""Device lists inside Olm (wire v2, grappa-irc#2430): the inner `lv`, the
`listreq` it draws, the `t:list` answering it; and order challenges to a
user with several devices (amendment O1)."""

from irc_olm import framing
from irc_olm.engine import (AckOk, AckRejected, Dropped, KeyAlarm, Received, Result)


def text(body):
    return {"t": "text", "body": body}


def setup(net, n):
    bot = net.add("bot")
    devs = net.add_user("alice", n)
    net.pin("bot", "alice")
    net.pin("alice", "bot")
    return bot, devs


def feed(engine, src, res):
    out = Result()
    for _, line in res.outbound:
        out.extend(engine.receive(src, line))
    return out


def olm_msgids(res):
    return {f.msgid for f in (framing.parse(b) for _, b in res.outbound)
            if f.verb in ("MSG", "PKMSG")}


def test_a_newer_lv_draws_a_listreq_and_the_list_it_brings_revokes(net):
    bot, (a0, a1, a2) = setup(net, 3)
    net.relist("alice", [a0, a1], 1)
    net.pump("bot", bot.send("alice", text("hi")))
    net.relist("alice", [a0, a2], 2)             # a1 is stolen
    asked = feed(bot, "alice", a0.send("bot", text("I changed my devices")))
    assert [e.inner["body"] for e in asked.events if isinstance(e, Received)] == \
        ["I changed my devices"]
    (listreq,) = olm_msgids(asked)               # to a0, the device holding the news
    assert listreq in asked.reactive and listreq not in asked.urgent
    answer = feed(a0, "bot", asked)
    (t_list,) = olm_msgids(answer)
    assert t_list in answer.reactive
    applied = feed(bot, "alice", answer)
    assert not [e for e in applied.events if isinstance(e, Received)]   # never shown
    assert bot._books[a0.fingerprint].ver == 2
    assert a1.device_key not in {d.ed25519 for d in bot.devices(a0.fingerprint)}
    late = feed(bot, "alice", a1.send("bot", text("send me the money")))
    assert [e.reason for e in late.events if isinstance(e, Dropped)] == ["revoked-device"]


def test_a_listreq_goes_once_per_lv_and_once_per_nick_a_minute(net):
    from irc_olm.engine import LISTREQ_INTERVAL
    bot, (a0, a1) = setup(net, 2)
    net.pump("bot", bot.send("alice", text("hi")))
    net.relist("alice", [a0, a1], 2)

    def listreqs(dev, body):
        return len(olm_msgids(feed(bot, "alice", dev.send("bot", text(body)))))

    assert listreqs(a0, "lv 2") == 1             # its answer is lost
    assert listreqs(a1, "lv 2 again") == 0       # same (nick, lv), and inside the minute
    net.clock.t += LISTREQ_INTERVAL
    assert listreqs(a0, "lv 2, later") == 0      # same (nick, lv)
    net.relist("alice", [a0, a1], 3)
    assert listreqs(a1, "lv 3") == 1
    assert listreqs(a0, "lv 3 again") == 0


def test_a_huge_lv_from_one_device_silences_no_later_listreq(net):
    from irc_olm.engine import LISTREQ_INTERVAL
    bot, (a0, a1, a2) = setup(net, 3)
    net.pump("bot", bot.send("alice", text("hi")))

    def listreqs(dev, body):
        return len(olm_msgids(feed(bot, "alice", dev.send("bot", text(body)))))

    a1._ver = 2**31 - 1                          # broken, or stolen
    assert listreqs(a1, "lv max") == 1
    a1._ver = 1
    net.clock.t += LISTREQ_INTERVAL
    net.relist("alice", [a0, a2], 2)             # its owner revokes it
    assert listreqs(a0, "I revoked a1") == 1


def test_a_listreq_is_answered_once_per_device_a_minute(net):
    from irc_olm.engine import LISTREQ_INTERVAL
    bot, (a0, a1) = setup(net, 2)
    net.pump("bot", bot.send("alice", text("hi")))   # each device asked once already
    net.clock.t += LISTREQ_INTERVAL

    def answered(dev):
        res = feed(bot, "alice", dev.send("bot", {"t": "listreq"}))
        assert not [e for e in res.events if isinstance(e, Received)]
        return olm_msgids(res), [e.reason for e in res.events if isinstance(e, Dropped)]

    assert len(answered(a0)[0]) == 1
    assert answered(a0) == (set(), ["listreq-rate-limited"])
    assert len(answered(a1)[0]) == 1             # per device
    net.clock.t += LISTREQ_INTERVAL
    assert len(answered(a0)[0]) == 1


def test_our_list_answers_carry_our_master_block(net):
    bot, (a0,) = setup(net, 1)
    net.pump("bot", bot.send("alice", text("hi")))
    got = feed(a0, "bot", feed(bot, "alice", a0.send("bot", {"t": "listreq"})))
    assert not [e for e in got.events if isinstance(e, Received)]
    assert a0._books[bot.fingerprint].ver == 1
    assert [d.ed25519 for d in a0.devices(bot.fingerprint)] == [bot.device_key]


def test_a_list_signed_by_another_master_is_the_alarm(net):
    bot, (a0,) = setup(net, 1)
    mallory = net.add("mallory")
    net.pump("bot", bot.send("alice", text("hi")))
    res = feed(bot, "alice", a0.send("bot", {"t": "list", "master": mallory.master_block}))
    (alarm,) = [e for e in res.events if isinstance(e, KeyAlarm)]
    assert (alarm.pinned, alarm.presented) == (a0.fingerprint, mallory.fingerprint)
    assert bot._books[a0.fingerprint].ver == 1
    res = feed(bot, "alice", a0.send("bot", {"t": "list", "master": {"ed25519": "x"}}))
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["invalid-list"]


def test_a_challenge_goes_to_every_device_that_wrote_to_us_and_any_may_ack(net):
    bot, (a0, a1, a2) = setup(net, 3)
    a2_did = a2.did
    net.drop = lambda src, dst, body: src == "alice" and framing.parse(body).src == a2_did
    net.pump("bot", bot.send("alice", text("hi")))   # a0 and a1 write back (listreq)
    net.drop = None
    for i in range(3):
        net.take(f"alice.{i}")
    ch, res = bot.challenge("alice", network="TestNet", channel="#sbiffo",
                            sender_mask="alice!a@host", line=b"!op")
    msgs = [p for _, v, p in _messages(res) if v in ("MSG", "PKMSG")]
    assert [(v, set(p["bodies"])) for _, v, p in _messages(res)] == [("MSG", {a0.did, a1.did})]
    net.pump("bot", res)
    nonces = [[e.inner["nonce"] for e in net.take(f"alice.{i}", Received)] for i in range(3)]
    assert nonces == [[ch.nonce], [ch.nonce], []]
    net.pump("alice.1", a1.send("bot", {"t": "ack", "nonce": ch.nonce}))   # who typed it
    (ok,) = net.take("bot", AckOk)
    assert ok.challenge == ch and ok.peer.master == a0.fingerprint
    net.pump("alice.0", a0.send("bot", {"t": "ack", "nonce": ch.nonce}))
    assert [e.reason for e in net.take("bot", AckRejected)] == ["unknown-nonce"]
    assert msgs


def _messages(res):
    out, open_ = [], {}
    for _, line in res.outbound:
        f = framing.parse(line)
        buf = open_.setdefault(f.msgid, [])
        buf.append(f.chunk)
        if len(buf) == f.total:
            out.append((f.src, f.verb, framing.decode_payload("".join(buf))))
    return out
