import base64

import pytest

from irc_olm import framing
from irc_olm.engine import Dropped, Received, Replayed, SendQueued, Undecryptable


def texts(events):
    return [e.inner["body"] for e in events if isinstance(e, Received) and e.inner.get("t") == "text"]


def verbs(net, sender=None):
    return [verb for _, verb, _ in net.messages(sender)]


def paired(net):
    bot, vjt = net.add("bot"), net.add("vjt")
    net.pair("bot", "vjt")
    return bot, vjt


def test_first_contact_keyreq_keys_pkmsg_then_reply_as_msg(net):
    bot, vjt = paired(net)
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
    bot, vjt = paired(net)
    r1 = vjt.send("bot", {"t": "text", "body": "uno"})
    assert any(isinstance(e, SendQueued) for e in r1.events)
    r2 = vjt.send("bot", {"t": "text", "body": "due"})
    assert r2.outbound == []  # one KEYREQ in flight is enough
    net.pump("vjt", r1)
    assert texts(net.take("bot")) == ["uno", "due"]


def test_long_message_is_fragmented_and_reassembled(net):
    bot, vjt = paired(net)
    body = "è" * 3000
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": body}))
    assert texts(net.take("bot")) == [body]
    pk = [b for s, _, b in net.wire if framing.parse(b).verb == "PKMSG"]
    assert len(pk) > 5
    for b in pk:
        assert len(f":{framing.conservative_mask('vjt', 'vjt')} PRIVMSG bot :{b}\r\n".encode()) <= 512


def test_payloads_match_the_wire_spec(net):
    bot, vjt = paired(net)
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
    bot, vjt = paired(net)
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "a"}))
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "b"}))
    net.take("bot"), net.take("vjt")
    bot, vjt = net.restart("bot"), net.restart("vjt")
    n = len(net.messages())
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "after restart"}))
    assert texts(net.take("bot")) == ["after restart"]
    assert [verb for _, verb, _ in net.messages()[n:]] == ["MSG"]


def test_identity_is_stable_across_restarts_and_networks_are_separate(net):
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
               nick="bot", ident="bot", pins={}, clock=net.clock)


def test_wrong_key_refuses_to_load(net):
    import vodozemac as vz
    from irc_olm.engine import Engine
    bot = net.add("bot")
    with pytest.raises(vz.PickleException):
        Engine(bot.state_path, b"\0" * 32, network="testnet", nick="bot", ident="bot",
               pins={}, clock=net.clock)


def test_state_file_carries_the_public_identity_in_clear(net):
    import json
    bot = net.add("bot")
    doc = json.loads(bot.state_path.read_text())
    assert doc["identity"] == {"ed25519": bot.fingerprint, "curve25519": bot.identity["curve25519"]}
    assert "pins" not in doc   # the configuration is the source of truth, never the state


def test_replayed_fallback_prekey_message_is_never_decrypted(net):
    bot, vjt = paired(net)
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
    bot.forget_sessions(vjt.fingerprint)
    for s, b in pkmsg:
        res = bot.receive(s, b)
    assert texts(res.events) == []
    assert any(isinstance(e, Replayed) for e in res.events)


def test_undecryptable_message_triggers_a_nack(net):
    bot, vjt = paired(net)
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "a"}))
    net.take("bot")
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
    bot, vjt = paired(net)
    eve = net.add("eve")
    net.pin("eve", "bot")
    keys_from_bot = bot.receive("vjt", vjt.send("bot", {"t": "text", "body": "x"}).outbound[0][1])
    for _, body in keys_from_bot.outbound:
        res = eve.receive("bot", body)
    assert any(isinstance(e, Dropped) and e.reason == "unsolicited-keys" for e in res.events)


def test_received_event_repr_never_shows_plaintext(net):
    bot, vjt = paired(net)
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "segreto"}))
    for e in net.take("bot"):
        assert "segreto" not in repr(e)


@pytest.mark.parametrize("payload", [
    {"v": 1},                                         # KEYS without id/otk
    {"v": 1, "id": "not a dict", "otk": {}},
    {"v": 1, "id": {"ed25519": "x", "curve25519": "y", "sig": "z"}, "otk": {"key": 1}},
])
def test_malformed_payloads_are_dropped_not_raised(net, payload):
    bot, vjt = paired(net)
    vjt.send("bot", {"t": "text", "body": "x"})   # so KEYS would be solicited
    for verb in ("KEYS", "PKMSG", "MSG", "NACK"):
        body = framing.fragment(verb, framing.encode_payload(payload), own_mask="bot!b@h", target="vjt")[0]
        res = vjt.receive("bot", body)
        assert all(isinstance(e, Dropped) or e.__class__.__name__ in ("SendFailed", "Undecryptable")
                   for e in res.events), (verb, res.events)


DEEP = "[" * 3000 + "]" * 3000


def test_a_deeply_nested_payload_is_dropped_not_raised(net):
    bot, vjt = paired(net)
    # A NACK whose ref is the nesting: undecodable where the scanner
    # recurses (< 3.12), an unhashable ref where it does not. Dropped both ways.
    body = base64.b64encode(('{"v":1,"ref":' + DEEP + "}").encode()).decode()
    for frag in framing.fragment("NACK", body, own_mask="vjt!x@h", target="bot"):
        res = bot.receive("vjt", frag)
    assert all(isinstance(e, Dropped) for e in res.events)
    assert res.outbound == []


def test_a_deeply_nested_inner_message_is_dropped_not_raised(net):
    bot, vjt = paired(net)
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "a"}))
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "b"}))
    net.take("bot")
    session = vjt._sessions[bot.identity["curve25519"]][0]
    _, ct = session.encrypt(('{"t":"text","body":"x","deep":' + DEEP + "}").encode()).to_parts()
    res = net.inject("vjt", "bot", "MSG", {"v": 1, "ck": vjt.identity["curve25519"],
                                           "body": base64.b64encode(ct).decode().rstrip("=")})
    # Delivered where the scanner does not recurse (>= 3.12), dropped where it does.
    if texts(res.events) != ["x"]:
        assert texts(res.events) == []
        assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["undecodable-inner"]


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_an_inner_message_json_cannot_spell_is_dropped(net, constant):
    # Python's json takes them, JSON.parse does not: a bot and cicchetto
    # would disagree on what the same bytes say.
    bot, vjt = paired(net)
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "a"}))
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "b"}))
    net.take("bot")
    session = vjt._sessions[bot.identity["curve25519"]][0]
    _, ct = session.encrypt(('{"t":"text","body":"x","n":' + constant + "}").encode()).to_parts()
    res = net.inject("vjt", "bot", "MSG", {"v": 1, "ck": vjt.identity["curve25519"],
                                           "body": base64.b64encode(ct).decode().rstrip("=")})
    assert texts(res.events) == []
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["undecodable-inner"]


def test_a_body_that_is_not_base64_is_dropped_not_raised(net):
    bot, vjt = paired(net)
    res = net.inject("bot", "vjt", "PKMSG", {"v": 1, "id": bot.identity, "body": "!!!"})
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["bad-payload:Error"]


def test_a_replayed_fallback_prekey_message_is_refused_after_a_restart(net):
    bot, vjt = paired(net)
    dropped = []

    def drop_first_keys(src, dst, body):
        if framing.parse(body).verb == "KEYS" and not dropped:
            dropped.append(body)
            return True
        return False

    net.drop = drop_first_keys
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "order 66"}))
    net.drop = None
    net.clock.t += 31
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "ping"}))
    assert texts(net.take("bot")) == ["order 66", "ping"]
    pk = net.captured("PKMSG", "vjt")[0]
    bot.forget_sessions(vjt.fingerprint)
    bot = net.restart("bot")
    res = net.inject("vjt", "bot", "PKMSG", pk)
    assert texts(res.events) == []
    assert any(isinstance(e, Replayed) for e in res.events)


def test_keyreq_answers_are_rate_limited_per_nick(net):
    # A KEYS is two lines, 8 s of our flood bank.
    from irc_olm.engine import KEYS_INTERVAL
    bot, vjt = paired(net)
    first = net.inject("vjt", "bot", "KEYREQ", {"v": 1})
    net.clock.t += KEYS_INTERVAL - 1
    second = net.inject("vjt", "bot", "KEYREQ", {"v": 1})
    assert {framing.parse(b).verb for _, b in first.outbound} == {"KEYS"}
    assert second.outbound == []
    assert [e.reason for e in second.events if isinstance(e, Dropped)] == ["keyreq-rate-limited"]
    net.clock.t += 1
    assert net.inject("vjt", "bot", "KEYREQ", {"v": 1}).outbound


def test_a_keys_answer_with_a_forged_one_time_key_signature_is_dropped(net):
    import vodozemac as vz
    bot, vjt = paired(net)
    vjt.send("bot", {"t": "text", "body": "queued"})
    keys = framing.decode_payload("".join(
        framing.parse(b).chunk for _, b in net.inject("vjt", "bot", "KEYREQ", {"v": 1}).outbound))
    keys["otk"]["key"] = vz.Account().curve25519_key.to_base64()   # sig no longer covers it
    res = net.inject("bot", "vjt", "KEYS", keys)
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["bad-otk-signature"]
    assert res.outbound == [] and vjt.peers()[0].curve25519 is None


def test_queued_messages_that_expire_are_reported_lost(net):
    from irc_olm.engine import OUTQ_TTL, SendFailed
    bot, vjt = paired(net)
    net.drop = lambda *_: True
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "nobody home"}))
    net.clock.t += OUTQ_TTL + 1
    (lost,) = [e for e in bot.tick().events if isinstance(e, SendFailed)]
    assert (lost.nick, lost.reason, lost.lost) == ("vjt", "keys-timeout", 1)
    assert [e for e in bot.tick().events if isinstance(e, SendFailed)] == []


def test_the_fallback_key_rotates_weekly(net):
    from irc_olm.engine import FALLBACK_ROTATE, KEYS_INTERVAL

    def fallback_after_two_keyreqs():
        net.inject("vjt", "bot", "KEYREQ", {"v": 1})
        net.clock.t += KEYS_INTERVAL     # inside the minute: the fallback key
        (k,) = [framing.decode_payload("".join(framing.parse(b).chunk for _, b in
                net.inject("vjt", "bot", "KEYREQ", {"v": 1}).outbound))["otk"]]
        assert k["fallback"] is True
        return k["key"]

    bot, vjt = paired(net)
    first = fallback_after_two_keyreqs()
    net.clock.t += FALLBACK_ROTATE + 1
    bot.tick()
    net.clock.t += 61
    assert fallback_after_two_keyreqs() != first


@pytest.mark.parametrize("bad", ["\ud800", float("nan"), object()])
def test_an_inner_message_that_cannot_be_encoded_is_a_send_failure(net, bad):
    from irc_olm.engine import SendFailed
    bot, vjt = paired(net)

    def refused(res):
        return [(e.reason, e.lost) for e in res.events if isinstance(e, SendFailed)]

    res = vjt.send("bot", {"t": "text", "body": bad})          # no session yet
    assert refused(res) == [("unencodable", 1)] and res.outbound == []
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "ok"}))
    assert texts(net.take("bot")) == ["ok"]                       # nothing stuck in the queue
    res = vjt.send("bot", {"t": "text", "body": bad})          # on an open session
    assert refused(res) == [("unencodable", 1)] and res.outbound == []


def test_a_message_too_long_for_64_fragments_is_a_send_failure(net):
    from irc_olm.engine import SendFailed
    bot, vjt = paired(net)
    huge = {"t": "text", "body": "x" * 40_000}

    def refused(events):
        return [(e.reason, e.lost) for e in events if isinstance(e, SendFailed)]

    first = vjt.send("bot", {"t": "text", "body": "before"})  # queued, KEYREQ out
    vjt.send("bot", huge)
    vjt.send("bot", {"t": "text", "body": "after"})
    net.pump("vjt", first)                                     # KEYS: the queue flushes
    assert refused(net.take("vjt")) == [("too-long", 1)]
    assert texts(net.take("bot")) == ["before", "after"]
    res = vjt.send("bot", huge)                                # on an open session
    assert refused(res.events) == [("too-long", 1)] and res.outbound == []
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "still fine"}))
    assert texts(net.take("bot")) == ["still fine"]



def test_a_message_too_long_leaves_the_olm_chain_where_it_was(net):
    # Review I, I4b: encrypted before its length was checked, each too-long
    # message moved the chain, so past 40 of them the receiver could no
    # longer decrypt a message sent before them that arrived after.
    from irc_olm.engine import SendFailed
    bot, vjt = paired(net)
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "ciao"}))
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "ciao"}))
    net.take("bot")
    early = vjt.send("bot", {"t": "text", "body": "early"})
    for _ in range(45):
        res = vjt.send("bot", {"t": "text", "body": "x" * 40_000})
        assert [e.reason for e in res.events if isinstance(e, SendFailed)] == ["too-long"]
    late = vjt.send("bot", {"t": "text", "body": "late"})
    events = []
    for r in (late, early):
        for _, body in r.outbound:
            events += bot.receive("vjt", body).events
    assert [e for e in events if isinstance(e, Undecryptable)] == []
    assert texts(events) == ["late", "early"]

def test_a_first_pkmsg_that_opens_no_session_gets_a_nack(net):
    import vodozemac as vz
    from irc_olm.engine import b64
    bot, vjt = paired(net)
    # vjt's first message, on a one-time key the bot never published
    junk = vz.Account().curve25519_key
    session = vjt._account.create_outbound_session(bot._account.curve25519_key, junk)
    _, ct = session.encrypt(b'{"t":"text","body":"x"}').to_parts()
    res = net.inject("vjt", "bot", "PKMSG", {"v": 1, "id": vjt.identity, "body": b64(ct)})
    assert [e.reason.split(":")[0] for e in res.events if isinstance(e, Undecryptable)] == \
        ["session-creation"]
    assert [framing.parse(b).verb for _, b in res.outbound] == ["NACK"]


@pytest.mark.parametrize("raw", [bytes(32), bytes(31)])
def test_keys_with_a_signed_but_unusable_one_time_key_keep_the_queue(net, raw):
    from irc_olm.engine import OTK_SIG_PREFIX, OUTQ_TTL, SendFailed
    bot, vjt = paired(net)
    bot.send("vjt", {"t": "text", "body": "waits"})
    otk = base64.b64encode(raw).decode().rstrip("=")
    res = net.inject("vjt", "bot", "KEYS", {
        "v": 1, "id": vjt.identity,
        "otk": {"key": otk, "fallback": True, "sig": vjt._sign(OTK_SIG_PREFIX + otk)}})
    assert [e for e in res.events if isinstance(e, Dropped)]
    net.clock.t += OUTQ_TTL + 1
    assert [(e.reason, e.lost) for e in bot.tick().events if isinstance(e, SendFailed)] == \
        [("keys-timeout", 1)]


def test_control_lines_and_challenges_are_urgent_text_is_not(net):
    from irc_olm.engine import Result

    def ids(res, verb):
        return {f.msgid for f in (framing.parse(b) for _, b in res.outbound) if f.verb == verb}

    def feed(engine, src, res):
        out = Result()
        for _, body in res.outbound:
            out.extend(engine.receive(src, body))
        return out

    bot, vjt = paired(net)
    r = vjt.send("bot", {"t": "text", "body": "hi"})
    assert ids(r, "KEYREQ") and ids(r, "KEYREQ") <= r.urgent.keys()
    keys = feed(bot, "vjt", r)
    assert ids(keys, "KEYS") and ids(keys, "KEYS") <= keys.urgent.keys()
    flushed = feed(vjt, "bot", keys)
    assert ids(flushed, "PKMSG") and not ids(flushed, "PKMSG") & flushed.urgent.keys()
    feed(bot, "vjt", flushed)
    _, chal = bot.challenge("vjt", network="n", channel="#c", sender_mask="vjt!v@h", line=b"!op")
    sent = ids(chal, "PKMSG") | ids(chal, "MSG")
    assert sent and sent <= chal.urgent.keys()
    # A CHAL is useless once expired: the pacer gets the seconds it has left.
    assert all(14 < chal.urgent[m] <= 15 for m in sent)
    assert {r.urgent[m] for m in ids(r, "KEYREQ")} == {None}
    bot.forget_sessions(vjt.fingerprint)
    nack = feed(bot, "vjt", vjt.send("bot", {"t": "text", "body": "lost"}))
    assert ids(nack, "NACK") and ids(nack, "NACK") <= nack.urgent.keys()


def test_olm_decrypts_a_message_that_overtook_as_many_as_the_pacer_lets_queue(net):
    # Pins the pacer's per-target text cap against vodozemac's skipped keys.
    from irc_olm.pacing import DEFAULT_MAX_TEXT_MESSAGES
    bot, vjt = paired(net)
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "ciao"}))
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "ciao"}))
    net.take("bot")
    queued = [vjt.send("bot", {"t": "text", "body": f"m{i}"}) for i in range(DEFAULT_MAX_TEXT_MESSAGES)]
    chal = vjt.send("bot", {"t": "chal", "nonce": "x"})
    events = []
    for r in [chal] + queued:                                  # the pacer's order
        for _, body in r.outbound:
            events += bot.receive("vjt", body).events
    assert [e for e in events if isinstance(e, Undecryptable)] == []
    assert len(texts(events)) == DEFAULT_MAX_TEXT_MESSAGES


@pytest.mark.parametrize("refused", [1, 8])
def test_olm_decrypts_the_queue_when_refused_messages_fill_the_rest_of_the_cap(net, refused):
    # A message the pacer refused was encrypted, so the receiver skips its
    # key too: the pacer counts it in the cap (Pacer.room), and Olm must
    # still decrypt the queue an urgent message overtook.
    from irc_olm.pacing import DEFAULT_MAX_TEXT_MESSAGES
    bot, vjt = paired(net)
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "ciao"}))
    net.pump("bot", bot.send("vjt", {"t": "text", "body": "ciao"}))
    net.take("bot")
    queued = []
    for i in range(DEFAULT_MAX_TEXT_MESSAGES):
        r = vjt.send("bot", {"t": "text", "body": f"m{i}"})
        if i % (DEFAULT_MAX_TEXT_MESSAGES // refused) or len(queued) >= DEFAULT_MAX_TEXT_MESSAGES - refused:
            queued.append(r)                                 # else refused: never sent
    assert len(queued) == DEFAULT_MAX_TEXT_MESSAGES - refused
    chal = vjt.send("bot", {"t": "chal", "nonce": "x"})
    events = []
    for r in [chal] + queued:
        for _, body in r.outbound:
            events += bot.receive("vjt", body).events
    assert [e for e in events if isinstance(e, Undecryptable)] == []
    assert len(texts(events)) == DEFAULT_MAX_TEXT_MESSAGES - refused


def test_a_challenge_that_expired_waiting_for_keys_is_not_sent(net):
    # Encrypting it would only open a gap in the receiver's Olm chain; the
    # application hears of it as ChallengeExpired.
    from irc_olm.challenge import CHALLENGE_TTL
    from irc_olm.engine import Result
    bot, vjt = paired(net)
    _, res = bot.challenge("vjt", network="n", channel="#c", sender_mask="vjt!v@h", line=b"!op")
    assert [framing.parse(b).verb for _, b in res.outbound] == ["KEYREQ"]
    net.clock.t += CHALLENGE_TTL + 1
    flushed = Result()
    for _, body in vjt.receive("bot", res.outbound[0][1]).outbound:
        flushed.extend(bot.receive("vjt", body))
    assert flushed.outbound == [] and flushed.urgent == {}


def test_a_retry_keyreq_that_crossed_faster_than_the_first_is_answered(net):
    # The interval runs from the first KEYREQ's ARRIVAL here, the asker's
    # retry from its SENDING there: a first KEYREQ that waited 8 s in the
    # asker's pacer, whose KEYS was then lost, must not cost the retry.
    from irc_olm.engine import KEYREQ_RETRY, SendFailed
    bot, vjt = paired(net)
    r1 = vjt.send("bot", {"t": "text", "body": "one"})
    net.clock.t += 8
    assert bot.receive("vjt", r1.outbound[0][1]).outbound        # a KEYS, lost on the way
    net.clock.t += KEYREQ_RETRY - 8
    r2 = vjt.send("bot", {"t": "text", "body": "two"})
    assert [framing.parse(b).verb for _, b in r2.outbound] == ["KEYREQ"]
    net.pump("bot", bot.receive("vjt", r2.outbound[0][1]))
    assert [e for e in net.take("vjt") if isinstance(e, SendFailed)] == []
    assert texts(net.take("bot")) == ["one", "two"]


def test_messages_the_pacer_refused_are_forgotten(net):
    # They never left: no NACK can come for them, and they must not push the
    # plaintexts of messages still on their way out of the bounded memory.
    bot, vjt = paired(net)
    net.pump("vjt", vjt.send("bot", {"t": "text", "body": "hi"}))
    sent = bot.send("vjt", {"t": "text", "body": "refused"})
    (msgid,) = {framing.parse(b).msgid for _, b in sent.outbound}
    bot.discard([msgid])
    res = net.inject("vjt", "bot", "NACK", {"v": 1, "ref": msgid})
    assert [e.reason for e in res.events if isinstance(e, Dropped)] == ["unknown-nack-ref"]
    assert res.outbound == []


def test_a_message_evicted_by_the_global_reassembly_cap_is_reported(net):
    # Evicted to make room for another sender's fragment: reported, with the
    # nick it came from, in the Result of the receive that caused it.
    from irc_olm.reassembly import Reassembler
    bot, vjt = paired(net)
    bot._reasm = Reassembler(max_bytes_total=1500, clock=net.clock)

    def frags(size):
        return framing.fragment("MSG", framing.encode_payload({"v": 1, "body": "x" * size}),
                                own_mask="x!x@h", target="bot")
    big = frags(900)
    assert len(big) == 3
    for f in big[:2]:
        assert bot.receive("nick0", f).events == []
    assert bot.receive("nick1", frags(600)[0]).events == []
    res = bot.receive("nick2", frags(600)[0])
    assert [(e.nick, e.reason, e.verb) for e in res.events] == \
        [("nick0", "reassembly:global-byte-cap", "MSG")]
