import base64
import re

import pytest

from irc_olm import framing
from irc_olm.framing import Fragment


MASK = "vjt-claude!claude@host.example.org"
TARGET = "vjt"


def wire_line(body, mask=MASK, target=TARGET):
    """The full line the RECEIVER sees, CRLF included."""
    return f":{mask} PRIVMSG {target} :{body}\r\n".encode()


# --- msgid ---------------------------------------------------------------

def test_new_msgid_is_8_random_bytes_unpadded_base64():
    ids = {framing.new_msgid() for _ in range(200)}
    assert len(ids) == 200
    for i in ids:
        assert re.fullmatch(r"[A-Za-z0-9+/]{11}", i)
        assert len(base64.b64decode(i + "=")) == 8


# --- payload ---------------------------------------------------------------

def test_payload_is_compact_json_text_with_no_base64_around_it():
    # Revision 2 (grappa-irc#2430, 6346686730): the frame carries the JSON
    # itself, which holds only base64, numbers and punctuation.
    enc = framing.encode_payload({"v": 2, "body": "QUJD+/9"})
    assert enc == '{"v":2,"body":"QUJD+/9"}'
    assert framing.decode_payload(enc) == {"v": 2, "body": "QUJD+/9"}


def test_payload_text_is_ascii_whatever_it_holds():
    enc = framing.encode_payload({"v": 2, "x": "è"})
    assert enc == '{"v":2,"x":"\\u00e8"}'
    assert framing.decode_payload(enc) == {"v": 2, "x": "è"}


def test_a_payload_whose_text_would_hold_a_space_is_refused():
    # JSON escapes every control character, and ensure_ascii everything past
    # ASCII; a space it leaves alone, and the frame splits on it.
    assert framing.encode_payload({"v": 2, "x": "a\tb\x01"}) == '{"v":2,"x":"a\\tb\\u0001"}'
    with pytest.raises(framing.PayloadError):
        framing.encode_payload({"v": 2, "x": "a b"})


@pytest.mark.parametrize("bad", [
    "[1,2]",                    # not an object
    "{nope",                    # not json
    '{"v":NaN}',                # not RFC 8259, though Python's json takes them
    '{"v":Infinity}',
    '{"v":-Infinity}',
    "eyJ2IjoyfQ==",             # a v1 payload: base64 of the JSON, no longer
])
def test_decode_payload_rejects_garbage(bad):
    with pytest.raises(framing.PayloadError):
        framing.decode_payload(bad)


# --- parse ---------------------------------------------------------------

DID_A = "AbCdEfGh-_0"
DID_B = "_Uw_z3-OAsk"


def test_parse_valid_fragment():
    f = framing.parse(f'\x01E2E MSG AAAAAAAAAAA 2/3 {DID_A} {DID_B} {{"v":2,"ck"\x01')
    assert f == Fragment("MSG", "AAAAAAAAAAA", 2, 3, DID_A, DID_B, '{"v":2,"ck"')


@pytest.mark.parametrize("verb,src,dst", [
    ("KEYREQ", DID_A, "*"),
    ("KEYS", "*", DID_A),
    ("PKMSG", DID_A, DID_B),
    ("PKMSG", DID_A, "*"),       # several bodies, one per device
    ("MSG", DID_A, DID_B),
    ("MSG", DID_A, "*"),
    ("NACK", DID_A, DID_B),
])
def test_parse_takes_every_combination_the_table_allows(verb, src, dst):
    f = framing.parse(f"\x01E2E {verb} AAAAAAAAAAA 1/1 {src} {dst} {{}}\x01")
    assert (f.verb, f.src, f.dst) == (verb, src, dst)


@pytest.mark.parametrize("verb,src,dst", [
    ("KEYREQ", DID_A, DID_B), ("KEYREQ", "*", "*"),
    ("KEYS", DID_A, DID_B), ("KEYS", DID_A, "*"), ("KEYS", "*", "*"),
    ("PKMSG", "*", DID_B), ("MSG", "*", "*"),
    ("NACK", DID_A, "*"), ("NACK", "*", DID_B),
])
def test_parse_drops_every_combination_outside_the_table(verb, src, dst):
    assert framing.parse(f"\x01E2E {verb} AAAAAAAAAAA 1/1 {src} {dst} {{}}\x01") is None


@pytest.mark.parametrize("body", [
    "hello",                                                     # not CTCP
    "\x01VERSION\x01",                                           # other CTCP
    f"\x01E2E MSG AAAAAAAAAAA 1/1 {DID_A} {DID_B} {{}}",            # unterminated
    f"\x01E2E FOO AAAAAAAAAAA 1/1 {DID_A} {DID_B} {{}}\x01",       # unknown verb: ignored
    f"\x01E2E OFFLINE AAAAAAAAAAA 1/1 {DID_A} {DID_B} {{}}\x01",   # dropped from the spec
    "\x01E2E MSG AAAAAAAAAAA 1/1 eyJ2IjoxfQ==\x01",                # a v1 line: no from, no to
    f"\x01E2E MSG AAAAAAAAAA 1/1 {DID_A} {DID_B} {{}}\x01",        # msgid too short
    f"\x01E2E MSG AAAAAAAAAAA= 1/1 {DID_A} {DID_B} {{}}\x01",      # padded msgid
    f"\x01E2E MSG AAAAAAAAAAA 0/1 {DID_A} {DID_B} {{}}\x01",       # 0-based index
    f"\x01E2E MSG AAAAAAAAAAA 2/1 {DID_A} {DID_B} {{}}\x01",       # index > total
    f"\x01E2E MSG AAAAAAAAAAA 1/65 {DID_A} {DID_B} {{}}\x01",      # over 64 fragments
    f"\x01E2E MSG AAAAAAAAAAA 01/2 {DID_A} {DID_B} {{}}\x01",      # leading zero
    f"\x01E2E MSG AAAAAAAAAAA 1/1 {DID_A} {DID_B} \x01",            # empty chunk
    f"\x01E2E MSG AAAAAAAAAAA 1/1 {DID_A} {DID_B} {{ }}\x01",       # space in chunk
    f"\x01E2E MSG AAAAAAAAAAA 1/1 {DID_A} {DID_B} {{\x02}}\x01",    # control in chunk
    f"\x01E2E MSG AAAAAAAAAAA 1/1 {DID_A} {DID_B} {{è}}\x01",       # non-ASCII in chunk
    "\x01E2E MSG AAAAAAAAAAA 1/1 AbCdEfGh+/0 _Uw_z3-OAsk {}\x01",   # a did in the std alphabet
    "\x01E2E MSG AAAAAAAAAAA 1/1 AbCdEfGh-_ _Uw_z3-OAsk {}\x01",    # a did too short
    f"\x01E2E  MSG AAAAAAAAAAA 1/1 {DID_A} {DID_B} {{}}\x01",      # double space
])
def test_parse_rejects(body):
    assert framing.parse(body) is None


def test_is_e2e_spots_every_e2e_ctcp_even_malformed():
    # The application must never surface these as ordinary CTCPs/messages.
    assert framing.is_e2e("\x01E2E FOO whatever\x01")
    assert framing.is_e2e("\x01E2E MSG")
    assert not framing.is_e2e("\x01VERSION\x01")
    assert not framing.is_e2e("E2E MSG x")


# --- fragment ------------------------------------------------------------

def frag(verb, payload, src=DID_A, dst=DID_B, **kw):
    return framing.fragment(verb, payload, src=src, dst=dst, own_mask=kw.pop("own_mask", MASK),
                            target=kw.pop("target", TARGET), **kw)


def test_single_short_payload_is_one_line_that_round_trips():
    payload = framing.encode_payload({"v": 2})
    bodies = frag("KEYREQ", payload, dst="*", msgid="AAAAAAAAAAA")
    assert bodies == [f"\x01E2E KEYREQ AAAAAAAAAAA 1/1 {DID_A} * {payload}\x01"]


def test_fragment_refuses_a_combination_outside_the_table():
    with pytest.raises(framing.PayloadError):
        frag("KEYS", framing.encode_payload({"v": 2}), src=DID_A, dst=DID_B)


@pytest.mark.parametrize("size", [1, 300, 301, 1000, 5000, 15000])
def test_fragments_fit_the_line_limit_as_the_receiver_sees_it(size):
    payload = framing.encode_payload({"v": 2, "body": "x" * size})
    bodies = frag("MSG", payload)
    for b in bodies:
        assert len(wire_line(b)) <= 512
    frags = [framing.parse(b) for b in bodies]
    assert all(frags)
    assert [f.index for f in frags] == list(range(1, len(bodies) + 1))
    assert {f.total for f in frags} == {len(bodies)}
    assert {(f.msgid, f.src, f.dst) for f in frags} == {(frags[0].msgid, DID_A, DID_B)}
    assert "".join(f.chunk for f in frags) == payload


def test_fragments_use_the_budget_not_a_safe_constant():
    payload = framing.encode_payload({"v": 2, "body": "x" * 5000})
    bodies = frag("MSG", payload)
    # Every fragment but the last fills the line to the byte, less the digits
    # a short index saves (the budget is sized for the widest "n/n").
    n = len(bodies)
    for i, b in enumerate(bodies[:-1], 1):
        assert len(wire_line(b)) == 512 - (len(str(n)) - len(str(i)))


def test_the_addresses_come_out_of_the_chunk_budget():
    payload = framing.encode_payload({"v": 2, "body": "x" * 5000})
    two_dids = frag("MSG", payload)
    one_star = frag("MSG", payload, dst="*")
    assert len(framing.parse(one_star[0]).chunk) - len(framing.parse(two_dids[0]).chunk) == 10


def test_budget_honours_a_larger_linelen():
    payload = framing.encode_payload({"v": 2, "body": "x" * 5000})
    short = frag("MSG", payload)
    long_ = frag("MSG", payload, linelen=1024)
    assert len(long_) < len(short)
    assert all(len(wire_line(b)) <= 1024 for b in long_)


def test_budget_counts_bytes_not_characters():
    mask = "vjt-claude!claude@hôst.example.org"
    payload = framing.encode_payload({"v": 2, "body": "x" * 3000})
    for b in frag("MSG", payload, own_mask=mask, target="vjté"):
        assert len(wire_line(b, mask=mask, target="vjté")) <= 512


def test_payload_needing_more_than_64_fragments_is_refused():
    payload = framing.encode_payload({"v": 2, "body": "x" * 40000})
    with pytest.raises(framing.PayloadError):
        frag("MSG", payload)


def test_conservative_mask_is_the_worst_case_bahamut_allows():
    m = framing.conservative_mask("vjt-claude", "claude")
    nick, rest = m.split("!")
    user, host = rest.split("@")
    assert nick == "vjt-claude"
    assert user == "~claude"
    assert len(host) == 63
    assert framing.conservative_mask("n", "a-very-long-ident").split("!")[1].split("@")[0] == "~a-very-lon"


def test_deeply_nested_json_is_a_payload_error_never_a_crash():
    # CPython < 3.12 raises RecursionError from the C scanner well before
    # this depth; the line must stay a PayloadError (or decode) everywhere.
    deep = '{"v":' + "[" * 3000 + "]" * 3000 + "}"
    try:
        framing.decode_payload(deep)
    except framing.PayloadError:
        pass
    with pytest.raises(framing.PayloadError):
        framing.decode_payload("[" * 3000 + "]" * 3000)
