"""IRC framing for E2E traffic: one CTCP per PRIVMSG line (wire v2).

    \\x01E2E <verb> <msgid> <i>/<n> <from> <to> <chunk>\\x01

`from` and `to` are each a device's did or `*`, in the combinations ADDRESSES
allows. The payload (a JSON object) is written as compact ASCII JSON and that
text itself is cut into chunks: it holds only base64, numbers and
punctuation, so nothing in it needs a second encoding. The receiver
concatenates chunks 1..n and parses once. Spec: vjt/grappa-irc#2430, wire v2
(6346236542, 6346384093), revision 2 (6346686730) and the base64url did
(6348464388).
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass

# OFFLINE was in draft 7 and is gone (vjt, 2026-10-18 19:3x): no sender-side
# delivery notices of any kind. Should one appear, it parses as an unknown verb.
MAX_FRAGMENTS = 64
DEFAULT_LINELEN = 512

# bahamut's USERLEN and HOSTLEN: the longest mask a receiver can see for us
# when we do not know our own yet.
USERLEN = 10
HOSTLEN = 63

PREFIX = "\x01E2E "
ANY = "*"

# Who a line is from and to, per verb: a did, `*`, or either. A KEYREQ asks
# the user (`*`), a KEYS describes the user (`*`) to the device that asked,
# and a PKMSG or MSG holding bodies for several devices goes to `*`.
_DID, _STAR, _EITHER = "did", "star", "either"
ADDRESSES = {
    "KEYREQ": (_DID, _STAR),
    "KEYS": (_STAR, _DID),
    "PKMSG": (_DID, _EITHER),
    "MSG": (_DID, _EITHER),
    "NACK": (_DID, _DID),
}
VERBS = frozenset(ADDRESSES)
_ADDR = r"(?:[A-Za-z0-9_-]{11}|\*)"

_LINE = re.compile(
    r"\x01E2E (?P<verb>[A-Z]+) (?P<msgid>[A-Za-z0-9+/]{11}) "
    r"(?P<i>[1-9][0-9]?)/(?P<n>[1-9][0-9]?) "
    rf"(?P<src>{_ADDR}) (?P<dst>{_ADDR}) (?P<chunk>[\x21-\x7e]+)\x01"
)


def _fits(addr: str, rule: str) -> bool:
    if rule == _STAR:
        return addr == ANY
    if rule == _DID:
        return addr != ANY
    return True


def addressed(verb: str, src: str, dst: str) -> bool:
    """Whether `src` -> `dst` is a combination the table allows for `verb`."""
    rule = ADDRESSES.get(verb)
    return rule is not None and _fits(src, rule[0]) and _fits(dst, rule[1])


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def fold(nick: str) -> str:
    """CASEMAPPING=ascii fold: A-Z only, like grappa's canonical_target. Every
    nick used as a key (pins, queues, rate limits, reassembly) goes through it."""
    return nick.translate(_ASCII_LOWER)


class PayloadError(ValueError):
    """A payload that cannot be encoded, fragmented or decoded."""


@dataclass(frozen=True)
class Fragment:
    verb: str
    msgid: str
    index: int
    total: int
    src: str
    dst: str
    chunk: str


def is_e2e(body: str) -> bool:
    """True for anything that claims to be E2E traffic, well-formed or not.

    Callers use it to keep such lines out of every plaintext path: a malformed
    E2E line is dropped, never shown as an ordinary CTCP or message.
    """
    return body.startswith(PREFIX)


def parse(body: str) -> Fragment | None:
    """Parse a PRIVMSG body. None if it is not a well-formed fragment of a
    known verb (unknown verbs are ignored, never fatal)."""
    m = _LINE.fullmatch(body)
    if not m or not addressed(m["verb"], m["src"], m["dst"]):
        return None
    i, n = int(m["i"]), int(m["n"])
    if not i <= n <= MAX_FRAGMENTS:
        return None
    return Fragment(m["verb"], m["msgid"], i, n, m["src"], m["dst"], m["chunk"])


def new_msgid() -> str:
    return base64.b64encode(os.urandom(8)).decode().rstrip("=")


def encode_payload(obj: dict) -> str:
    """The payload's compact ASCII JSON text, which is what the chunks carry.
    JSON escapes every control character and ensure_ascii everything past
    ASCII, but not a space, on which a frame splits: a payload whose text
    would hold one is refused (no field of the wire can)."""
    text = json.dumps(obj, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    if " " in text:
        raise PayloadError("a payload's text holds a space")
    return text


def _refuse_constant(name: str):
    raise ValueError(f"{name} is not JSON")


def loads(text: str | bytes):
    """RFC 8259 JSON only. Python's json also takes NaN, Infinity and
    -Infinity, and JavaScript's JSON.parse does not: the same bytes must say
    the same thing to a bot and to cicchetto."""
    return json.loads(text, parse_constant=_refuse_constant)


def decode_payload(data: str) -> dict:
    try:
        obj = loads(data)
    except ValueError as e:
        raise PayloadError(f"undecodable payload: {e}") from e
    except RecursionError as e:
        # Deep nesting: the C scanner recurses on CPython < 3.12.
        raise PayloadError("payload nested too deeply") from e
    if not isinstance(obj, dict):
        raise PayloadError("payload is not a JSON object")
    return obj


def conservative_mask(nick: str, ident: str) -> str:
    """Our mask as the receiver might see it, at its longest, for when the
    server has not told us yet."""
    return f"{nick}!~{ident[:USERLEN]}@{'x' * HOSTLEN}"


def _chunk_budget(head_text: str, total: int, own_mask: str, target: str,
                  linelen: int) -> int:
    # What the receiver gets: ":" mask " PRIVMSG " target " :" body CRLF.
    envelope = len(f":{own_mask} PRIVMSG {target} :".encode()) + 2
    head = len(head_text.format(n=f"{total}/{total}").encode()) + 1  # + \x01
    return linelen - envelope - head


def fragment(verb: str, payload: str, *, src: str, dst: str, own_mask: str, target: str,
             linelen: int = DEFAULT_LINELEN, msgid: str | None = None) -> list[str]:
    """Cut an encoded payload into CTCP bodies from `src` to `dst` that each
    fit `linelen` once the receiver's server has prefixed our full mask."""
    if not addressed(verb, src, dst):
        raise PayloadError(f"{verb} cannot go from {src!r} to {dst!r}")
    if not payload:
        raise PayloadError("empty payload")
    msgid = msgid or new_msgid()
    head_text = f"{PREFIX}{verb} {msgid} {{n}} {src} {dst} "
    total = 1
    while True:
        budget = _chunk_budget(head_text, total, own_mask, target, linelen)
        if budget <= 0:
            raise PayloadError("no room for a chunk on the line")
        need = max(1, -(-len(payload) // budget))
        if need <= total:
            break
        total = need
        if total > MAX_FRAGMENTS:
            raise PayloadError(f"payload needs more than {MAX_FRAGMENTS} fragments")
    chunks = [payload[i:i + budget] for i in range(0, len(payload), budget)]
    return [f"{PREFIX}{verb} {msgid} {i}/{len(chunks)} {src} {dst} {c}\x01"
            for i, c in enumerate(chunks, 1)]
