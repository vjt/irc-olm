import base64
import json
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


# --- payload -------------------------------------------------------------

def test_payload_is_padded_base64_of_compact_utf8_json():
    enc = framing.encode_payload({"v": 1, "body": "è"})
    assert enc == base64.b64encode('{"v":1,"body":"è"}'.encode()).decode()
    assert framing.decode_payload(enc) == {"v": 1, "body": "è"}


@pytest.mark.parametrize("bad", [
    "!!!!",                                              # not base64
    base64.b64encode(b"\xff\xfe").decode(),              # not utf-8
    base64.b64encode(b"[1,2]").decode(),                 # not an object
    base64.b64encode(b"{nope").decode(),                 # not json
])
def test_decode_payload_rejects_garbage(bad):
    with pytest.raises(framing.PayloadError):
        framing.decode_payload(bad)


# --- parse ---------------------------------------------------------------

def test_parse_valid_fragment():
    f = framing.parse("\x01E2E MSG AAAAAAAAAAA 2/3 eyJ2IjoxfQ==\x01")
    assert f == Fragment("MSG", "AAAAAAAAAAA", 2, 3, "eyJ2IjoxfQ==")


@pytest.mark.parametrize("body", [
    "hello",                                             # not CTCP
    "\x01VERSION\x01",                                   # other CTCP
    "\x01E2E MSG AAAAAAAAAAA 1/1 eyJ2IjoxfQ==",          # unterminated
    "\x01E2E FOO AAAAAAAAAAA 1/1 eyJ2IjoxfQ==\x01",      # unknown verb: ignored
    "\x01E2E OFFLINE AAAAAAAAAAA 1/1 eyJ2IjoxfQ==\x01",  # dropped from the spec
    "\x01E2E MSG AAAAAAAAAA 1/1 eyJ2IjoxfQ==\x01",       # msgid too short
    "\x01E2E MSG AAAAAAAAAAA= 1/1 eyJ2IjoxfQ==\x01",     # padded msgid
    "\x01E2E MSG AAAAAAAAAAA 0/1 eyJ2IjoxfQ==\x01",      # 0-based index
    "\x01E2E MSG AAAAAAAAAAA 2/1 eyJ2IjoxfQ==\x01",      # index > total
    "\x01E2E MSG AAAAAAAAAAA 1/65 eyJ2IjoxfQ==\x01",     # over 64 fragments
    "\x01E2E MSG AAAAAAAAAAA 01/2 eyJ2IjoxfQ==\x01",     # leading zero
    "\x01E2E MSG AAAAAAAAAAA 1/1 \x01",                  # empty chunk
    "\x01E2E MSG AAAAAAAAAAA 1/1 eyJ2 IjoxfQ==\x01",     # space in chunk
    "\x01E2E MSG AAAAAAAAAAA 1/1 ey*J2\x01",             # non-base64 chunk
    "\x01E2E  MSG AAAAAAAAAAA 1/1 eyJ2IjoxfQ==\x01",     # double space
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

def test_single_short_payload_is_one_line_that_round_trips():
    payload = framing.encode_payload({"v": 1})
    bodies = framing.fragment("KEYREQ", payload, own_mask=MASK, target=TARGET, msgid="AAAAAAAAAAA")
    assert bodies == [f"\x01E2E KEYREQ AAAAAAAAAAA 1/1 {payload}\x01"]


@pytest.mark.parametrize("size", [1, 300, 301, 1000, 5000, 15000])
def test_fragments_fit_the_line_limit_as_the_receiver_sees_it(size):
    payload = framing.encode_payload({"v": 1, "body": "x" * size})
    bodies = framing.fragment("MSG", payload, own_mask=MASK, target=TARGET)
    for b in bodies:
        assert len(wire_line(b)) <= 512
    frags = [framing.parse(b) for b in bodies]
    assert all(frags)
    assert [f.index for f in frags] == list(range(1, len(bodies) + 1))
    assert {f.total for f in frags} == {len(bodies)}
    assert {f.msgid for f in frags} == {frags[0].msgid}
    assert "".join(f.chunk for f in frags) == payload


def test_fragments_use_the_budget_not_a_safe_constant():
    payload = framing.encode_payload({"v": 1, "body": "x" * 5000})
    bodies = framing.fragment("MSG", payload, own_mask=MASK, target=TARGET)
    # Every fragment but the last fills the line to the byte, less the digits
    # a short index saves (the budget is sized for the widest "n/n").
    n = len(bodies)
    for i, b in enumerate(bodies[:-1], 1):
        assert len(wire_line(b)) == 512 - (len(str(n)) - len(str(i)))


def test_budget_honours_a_larger_linelen():
    payload = framing.encode_payload({"v": 1, "body": "x" * 5000})
    short = framing.fragment("MSG", payload, own_mask=MASK, target=TARGET)
    long_ = framing.fragment("MSG", payload, own_mask=MASK, target=TARGET, linelen=1024)
    assert len(long_) < len(short)
    assert all(len(wire_line(b)) <= 1024 for b in long_)


def test_budget_counts_bytes_not_characters():
    mask = "vjt-claude!claude@hôst.example.org"
    payload = framing.encode_payload({"v": 1, "body": "x" * 3000})
    for b in framing.fragment("MSG", payload, own_mask=mask, target="vjté"):
        assert len(wire_line(b, mask=mask, target="vjté")) <= 512


def test_payload_needing_more_than_64_fragments_is_refused():
    payload = framing.encode_payload({"v": 1, "body": "x" * 40000})
    with pytest.raises(framing.PayloadError):
        framing.fragment("MSG", payload, own_mask=MASK, target=TARGET)


def test_conservative_mask_is_the_worst_case_bahamut_allows():
    m = framing.conservative_mask("vjt-claude", "claude")
    nick, rest = m.split("!")
    user, host = rest.split("@")
    assert nick == "vjt-claude"
    assert user == "~claude"
    assert len(host) == 63
    assert framing.conservative_mask("n", "a-very-long-ident").split("!")[1].split("@")[0] == "~a-very-lon"
