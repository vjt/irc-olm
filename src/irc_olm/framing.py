"""IRC framing for E2E traffic: one CTCP per PRIVMSG line.

    \\x01E2E <verb> <msgid> <i>/<n> <chunk>\\x01

The payload (a JSON object) is UTF-8 encoded, base64'd once with the standard
padded alphabet, and the base64 text is cut into chunks; the receiver
concatenates chunks 1..n and decodes once. Spec: vjt/grappa-irc#2430 and the
wire comment there (2026-10-18), acked by both implementations.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from dataclasses import dataclass

VERBS = frozenset({"KEYREQ", "KEYS", "PKMSG", "MSG", "NACK", "OFFLINE"})
MAX_FRAGMENTS = 64
DEFAULT_LINELEN = 512

# bahamut's USERLEN and HOSTLEN: the longest mask a receiver can see for us
# when we do not know our own yet.
USERLEN = 10
HOSTLEN = 63

PREFIX = "\x01E2E "

_LINE = re.compile(
    r"\x01E2E (?P<verb>[A-Z]+) (?P<msgid>[A-Za-z0-9+/]{11}) "
    r"(?P<i>[1-9][0-9]?)/(?P<n>[1-9][0-9]?) (?P<chunk>[A-Za-z0-9+/=]+)\x01"
)


class PayloadError(ValueError):
    """A payload that cannot be encoded, fragmented or decoded."""


@dataclass(frozen=True)
class Fragment:
    verb: str
    msgid: str
    index: int
    total: int
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
    if not m or m["verb"] not in VERBS:
        return None
    i, n = int(m["i"]), int(m["n"])
    if not i <= n <= MAX_FRAGMENTS:
        return None
    return Fragment(m["verb"], m["msgid"], i, n, m["chunk"])


def new_msgid() -> str:
    return base64.b64encode(os.urandom(8)).decode().rstrip("=")


def encode_payload(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
    return base64.b64encode(raw).decode()


def decode_payload(data: str) -> dict:
    try:
        obj = json.loads(base64.b64decode(data, validate=True).decode())
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        raise PayloadError(f"undecodable payload: {e}") from e
    if not isinstance(obj, dict):
        raise PayloadError("payload is not a JSON object")
    return obj


def conservative_mask(nick: str, ident: str) -> str:
    """Our mask as the receiver might see it, at its longest, for when the
    server has not told us yet."""
    return f"{nick}!~{ident[:USERLEN]}@{'x' * HOSTLEN}"


def _chunk_budget(verb: str, msgid: str, total: int, own_mask: str, target: str,
                  linelen: int) -> int:
    # What the receiver gets: ":" mask " PRIVMSG " target " :" body CRLF.
    envelope = len(f":{own_mask} PRIVMSG {target} :".encode()) + 2
    head = len(f"{PREFIX}{verb} {msgid} {total}/{total} ".encode()) + 1  # + \x01
    return linelen - envelope - head


def fragment(verb: str, payload: str, *, own_mask: str, target: str,
             linelen: int = DEFAULT_LINELEN, msgid: str | None = None) -> list[str]:
    """Cut an encoded payload into CTCP bodies that each fit `linelen` once
    the receiver's server has prefixed our full mask."""
    if verb not in VERBS:
        raise PayloadError(f"unknown verb {verb!r}")
    if not payload:
        raise PayloadError("empty payload")
    msgid = msgid or new_msgid()
    total = 1
    while True:
        budget = _chunk_budget(verb, msgid, total, own_mask, target, linelen)
        if budget <= 0:
            raise PayloadError("no room for a chunk on the line")
        need = max(1, -(-len(payload) // budget))
        if need <= total:
            break
        total = need
        if total > MAX_FRAGMENTS:
            raise PayloadError(f"payload needs more than {MAX_FRAGMENTS} fragments")
    chunks = [payload[i:i + budget] for i in range(0, len(payload), budget)]
    return [f"{PREFIX}{verb} {msgid} {i}/{len(chunks)} {c}\x01"
            for i, c in enumerate(chunks, 1)]
