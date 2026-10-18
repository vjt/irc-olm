"""The E2E engine for one network: Olm account, peers, sessions, wire verbs.

Pure in the IRC sense: it never touches a socket. `receive()` takes the body
of a PRIVMSG that `framing.is_e2e()` recognised, `send()` takes an inner
message; both return a Result with the events for the application and the
CTCP bodies to send (through a pacing.PacedSender), one PRIVMSG per body.

Identity: one Olm account per network (vjt's ruling on grappa-irc#2430).

Pinned keys only (vjt's final ruling, 2026-10-18): a bot talks E2E only to the
Ed25519 keys an operator pasted into its configuration, and ignores every
other key: no KEYS, no NACK, no session. The pin is on the key, never on the
nick. The configured nick is where messages are sent; a pinned key that shows
up under another nick is still accepted, and a different key on a pinned nick
raises KeyAlarm (for the log) and is ignored. Rotating a key means re-pasting
it into the configuration and calling set_pins(). There is no SAS and no
trust-on-first-use here; SAS is for humans, in cicchetto.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable

import vodozemac as vz

from . import framing
from .challenge import Challenge, ChallengeBook, new_challenge
from .framing import PayloadError, fold
from .reassembly import Assembled, Reassembler, Rejected
from .store import StateFile

STATE_VERSION = 1
WIRE_VERSION = 1

ID_SIG_PREFIX = "irc-e2e:v1:id:"
OTK_SIG_PREFIX = "irc-e2e:v1:otk:"

KEYREQ_RETRY = 30.0          # re-ask for keys when still waiting after this long
OUTQ_TTL = 60.0              # queued plaintext waiting for keys
OUTQ_MAX = 16
REKEY_INTERVAL = 60.0        # spec: at most one new session per peer per minute
NACK_INTERVAL = 10.0         # at most one NACK per nick in this long
OTK_PER_NICK_INTERVAL = 60.0 # one one-time key per nick per minute, else the fallback
OTK_GLOBAL_PER_HOUR = 30
SENT_MEMORY = 120.0          # plaintexts kept for a re-send after a NACK
MAX_SESSIONS_PER_PEER = 5
SEEN_SESSIONS_MAX = 10_000


class StateMismatchError(ValueError):
    """A state file that belongs to another network."""


class NotPinnedError(ValueError):
    """An operation that needs a pinned key, for a nick without one."""


def b64u(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=")


def unb64u(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


# --- public types ----------------------------------------------------------

@dataclass(frozen=True)
class Peer:
    """A pinned identity. `curve25519` is learned from its first signed id
    block; `nick` is the last nick seen with this key, a routing hint only."""
    ed25519: str
    curve25519: str | None
    nick: str


@dataclass(frozen=True)
class Received:
    """A decrypted inner message. `inner` is plaintext: never log it."""
    nick: str
    peer: Peer
    inner: dict = field(repr=False)


@dataclass(frozen=True)
class KeyAlarm:
    """A nick pinned to one key presented another. Ignored; for the log."""
    nick: str
    pinned: str
    presented: str


@dataclass(frozen=True)
class Undecryptable:
    nick: str
    msgid: str
    reason: str


@dataclass(frozen=True)
class Replayed:
    nick: str
    session_id: str


@dataclass(frozen=True)
class Dropped:
    nick: str
    reason: str
    verb: str | None = None


@dataclass(frozen=True)
class SendQueued:
    nick: str
    queued: int


@dataclass(frozen=True)
class SendFailed:
    nick: str
    reason: str
    lost: int


@dataclass(frozen=True)
class Rekeying:
    nick: str
    peer: Peer


@dataclass(frozen=True)
class RekeyThrottled:
    nick: str
    peer: Peer


@dataclass(frozen=True)
class AckOk:
    nick: str
    peer: Peer
    challenge: Challenge


@dataclass(frozen=True)
class AckRejected:
    nick: str
    peer: Peer
    reason: str


@dataclass(frozen=True)
class ChallengeExpired:
    challenge: Challenge


@dataclass
class Result:
    events: list = field(default_factory=list)
    outbound: list[tuple[str, str]] = field(default_factory=list)

    def extend(self, other: "Result") -> "Result":
        self.events.extend(other.events)
        self.outbound.extend(other.outbound)
        return self


# --- internals ---------------------------------------------------------------

@dataclass
class _Queued:
    inner: dict
    at: float


@dataclass
class _Sent:
    nick: str
    ed25519: str
    session_id: str
    inner: dict
    at: float


class Engine:
    def __init__(self, state_path: str | os.PathLike, key: bytes, *, network: str,
                 nick: str, ident: str, pins: dict[str, str],
                 clock: Callable[[], float] = time.time,
                 linelen: int = framing.DEFAULT_LINELEN):
        self.state_path = Path(state_path)
        self.network = network
        self.nick = nick
        self.ident = ident
        self.linelen = linelen
        self.own_mask: str | None = None
        self._key = key
        self._clock = clock
        self._lock = threading.RLock()
        self._file = StateFile(self.state_path)
        self._reasm = Reassembler(clock=clock)

        self._peers: dict[str, Peer] = {}            # ed25519 -> Peer (pinned only)
        self._pins: dict[str, str] = {}              # folded nick -> ed25519, from config
        self._sessions: dict[str, list[vz.Session]] = {}  # curve25519 -> newest first
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._fallback: dict = {}

        self._outq: dict[str, list[_Queued]] = {}    # folded nick -> plaintexts
        self._keyreq_at: dict[str, float] = {}       # folded nick -> last KEYREQ
        self._keyreq_for: dict[str, str] = {}        # folded nick -> ed25519 asked for
        self._rekey_at: dict[str, float] = {}        # ed25519 -> last new outbound session
        self._nack_at: dict[str, float] = {}         # folded nick -> last NACK sent
        self._otk_at: dict[str, float] = {}          # folded nick -> last OTK handed out
        self._otk_log: list[float] = []
        self._sent: OrderedDict[str, _Sent] = OrderedDict()
        self._challenges = ChallengeBook()

        doc = self._file.load()
        if doc is None:
            self._account = vz.Account()
            self._new_fallback_key()
        else:
            self._load(doc)
        self.set_pins(pins)

    # --- identity --------------------------------------------------------------

    @property
    def identity(self) -> dict:
        curve = self._account.curve25519_key.to_base64()
        return {"curve25519": curve,
                "ed25519": self._account.ed25519_key.to_base64(),
                "sig": self._sign(ID_SIG_PREFIX + curve)}

    @property
    def fingerprint(self) -> str:
        return self._account.ed25519_key.to_base64()

    def set_own_mask(self, mask: str) -> None:
        with self._lock:
            self.own_mask = mask

    # --- pins -------------------------------------------------------------------

    def set_pins(self, pins: dict[str, str]) -> None:
        """Replace the pinned keys ({nick: ed25519}, from the operator's
        configuration). Keys no longer pinned lose their sessions."""
        with self._lock:
            new = {}
            for nick, ed in pins.items():
                vz.Ed25519PublicKey.from_base64(ed)  # raises on a malformed key
                new[fold(nick)] = ed
            self._pins = new
            keep = set(new.values())
            for ed in list(self._peers):
                if ed not in keep:
                    curve = self._peers.pop(ed).curve25519
                    self._sessions.pop(curve, None)
            for nick, ed in new.items():
                if ed not in self._peers:
                    self._peers[ed] = Peer(ed, None, nick)
            self._save()

    def peers(self) -> list[Peer]:
        with self._lock:
            return list(self._peers.values())

    def pinned(self, nick: str) -> Peer | None:
        """The pinned identity to talk to as `nick`: the one configured for
        that nick, else a pinned key last seen under it (a renamed peer)."""
        with self._lock:
            ed = self._pins.get(fold(nick))
            if ed:
                return self._peers[ed]
            return next((p for p in self._peers.values() if fold(p.nick) == fold(nick)), None)

    def forget_sessions(self, ed25519: str) -> None:
        with self._lock:
            p = self._peers.get(ed25519)
            if p and self._sessions.pop(p.curve25519, None) is not None:
                self._save()

    # --- sending -----------------------------------------------------------------

    def send(self, nick: str, inner: dict) -> Result:
        """Encrypt `inner` for the identity pinned to `nick`, or queue it and
        ask for keys when there is no session yet."""
        with self._lock:
            res = Result()
            key = fold(nick)
            peer = self.pinned(nick)
            if peer is None:
                res.events.append(SendFailed(nick, "unpinned-nick", 1))
                return res
            if self._sessions.get(peer.curve25519):
                return self._encrypt(nick, peer, inner, res)
            q = [x for x in self._outq.get(key, []) if x.at > self._now() - OUTQ_TTL]
            if len(q) >= OUTQ_MAX:
                res.events.append(SendFailed(nick, "queue-full", 1))
                return res
            q.append(_Queued(inner, self._now()))
            self._outq[key] = q
            res.events.append(SendQueued(nick, len(q)))
            self._maybe_keyreq(nick, peer, res)
            return res

    def _maybe_keyreq(self, nick: str, peer: Peer, res: Result) -> None:
        key = fold(nick)
        last = self._keyreq_at.get(key)
        if last is not None and self._now() - last < KEYREQ_RETRY:
            return
        self._keyreq_at[key] = self._now()
        self._keyreq_for[key] = peer.ed25519
        self._emit(nick, "KEYREQ", {"v": WIRE_VERSION}, res)

    def _encrypt(self, nick: str, peer: Peer, inner: dict, res: Result) -> Result:
        session = self._sessions[peer.curve25519][0]
        msg = session.encrypt(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode())
        mtype, ct = msg.to_parts()
        if mtype == 0:
            verb, payload = "PKMSG", {"v": WIRE_VERSION, "id": self.identity, "body": b64u(ct)}
        else:
            verb, payload = "MSG", {"v": WIRE_VERSION, "ck": self.identity["curve25519"],
                                    "body": b64u(ct)}
        self._save()
        msgid = self._emit(nick, verb, payload, res)
        self._sent[msgid] = _Sent(fold(nick), peer.ed25519, session.session_id, inner, self._now())
        self._trim_sent()
        return res

    def _emit(self, nick: str, verb: str, payload: dict, res: Result) -> str:
        mask = self.own_mask or framing.conservative_mask(self.nick, self.ident)
        msgid = framing.new_msgid()
        for body in framing.fragment(verb, framing.encode_payload(payload), own_mask=mask,
                                     target=nick, linelen=self.linelen, msgid=msgid):
            res.outbound.append((nick, body))
        return msgid

    # --- receiving ---------------------------------------------------------------

    def receive(self, nick: str, body: str) -> Result:
        with self._lock:
            res = Result()
            frag = framing.parse(body)
            if frag is None:
                res.events.append(Dropped(nick, "malformed-or-unknown-verb"))
                return res
            done = self._reasm.feed(fold(nick), frag)
            if done is None:
                return res
            if isinstance(done, Rejected):
                res.events.append(Dropped(nick, f"reassembly:{done.reason}", frag.verb))
                return res
            try:
                payload = framing.decode_payload(done.payload)
            except PayloadError:
                res.events.append(Dropped(nick, "undecodable-payload", done.verb))
                return res
            handler = {"KEYREQ": self._on_keyreq, "KEYS": self._on_keys,
                       "PKMSG": self._on_pkmsg, "MSG": self._on_msg,
                       "NACK": self._on_nack}[done.verb]
            try:
                handler(nick, done, payload, res)
            except (KeyError, TypeError, ValueError) as e:
                # A payload missing a field, or a key that does not decode:
                # malformed input from the wire, never a reason to crash.
                res.events.append(Dropped(nick, f"bad-payload:{type(e).__name__}", done.verb))
            return res

    def _on_keyreq(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        if self.pinned(nick) is None:
            res.events.append(Dropped(nick, "unpinned-nick", "KEYREQ"))
            return
        key, now = fold(nick), self._now()
        self._otk_log = [t for t in self._otk_log if t > now - 3600]
        last = self._otk_at.get(key)
        fresh_ok = ((last is None or now - last >= OTK_PER_NICK_INTERVAL)
                    and len(self._otk_log) < OTK_GLOBAL_PER_HOUR)
        if fresh_ok:
            self._account.generate_one_time_keys(1)
            (otk,) = self._account.one_time_keys.values()
            self._account.mark_keys_as_published()
            otk_b64 = otk.to_base64()
            entry = {"key": otk_b64, "fallback": False, "sig": self._sign(OTK_SIG_PREFIX + otk_b64)}
            self._otk_at[key] = now
            self._otk_log.append(now)
            self._save()
        else:
            entry = {"key": self._fallback["key"], "fallback": True, "sig": self._fallback["sig"]}
        self._emit(nick, "KEYS", {"v": WIRE_VERSION, "id": self.identity, "otk": entry}, res)

    def _on_keys(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        key = fold(nick)
        if key not in self._keyreq_at:
            res.events.append(Dropped(nick, "unsolicited-keys", "KEYS"))
            return
        otk = payload["otk"]
        if not self._sig_ok(payload["id"]["ed25519"], OTK_SIG_PREFIX + otk["key"], otk["sig"]):
            res.events.append(Dropped(nick, "bad-otk-signature", "KEYS"))
            return
        peer = self._identify(nick, payload["id"], res)
        if peer is None or peer.ed25519 != self._keyreq_for.get(key):
            # Not the identity we asked this nick for: what we queued was
            # meant for that one, never for this one.
            self._keyreq_at.pop(key, None)
            lost = len(self._outq.pop(key, []))
            res.events.append(SendFailed(nick, "key-mismatch", lost))
            return
        del self._keyreq_at[key]
        session = self._account.create_outbound_session(
            vz.Curve25519PublicKey.from_base64(peer.curve25519),
            vz.Curve25519PublicKey.from_base64(otk["key"]))
        self._add_session(peer.curve25519, session)
        self._rekey_at[peer.ed25519] = self._now()
        self._save()
        for q in self._outq.pop(key, []):
            if q.at > self._now() - OUTQ_TTL:
                self._encrypt(nick, peer, q.inner, res)

    def _on_pkmsg(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        peer = self._identify(nick, payload["id"], res)
        if peer is None:
            return
        any_msg = vz.AnyOlmMessage.from_parts(0, unb64u(payload["body"]))
        pre = any_msg.to_pre_key()
        sessions = self._sessions.get(peer.curve25519, [])
        for s in sessions:
            if s.session_matches(pre):
                return self._decrypted(nick, peer, msg, s, any_msg, res)
        sid = pre.session_id()
        if sid in self._seen:
            # Either a replay (a fallback-key PKMSG opens the same session
            # again and would re-deliver an old plaintext), or a peer still
            # sending on a session we lost. Never decrypt; NACK, so the
            # second case recovers. A replayer only gets a NACK back for a
            # msgid that is not its own.
            res.events.append(Replayed(nick, sid))
            return self._undecryptable(nick, msg.msgid, "replayed-session", res)
        try:
            session, plaintext = self._account.create_inbound_session(
                vz.Curve25519PublicKey.from_base64(peer.curve25519), pre)
        except vz.SessionCreationException as e:
            return self._undecryptable(nick, msg.msgid, f"session-creation:{e}", res)
        self._seen[sid] = None
        while len(self._seen) > SEEN_SESSIONS_MAX:
            self._seen.popitem(last=False)
        self._add_session(peer.curve25519, session)
        self._save()
        self._deliver(nick, peer, plaintext, res)

    def _on_msg(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        peer = next((p for p in self._peers.values() if p.curve25519 == payload["ck"]), None)
        if peer is None:
            if self.pinned(nick) is None:
                res.events.append(Dropped(nick, "unpinned-key", "MSG"))
                return
            # A pinned nick whose key we never saw a session for (our state
            # was lost?): a NACK makes it open a fresh one, with its id block.
            return self._undecryptable(nick, msg.msgid, "no-session", res)
        if not self._sessions.get(peer.curve25519):
            return self._undecryptable(nick, msg.msgid, "no-session", res)
        self._touch(peer, nick)
        any_msg = vz.AnyOlmMessage.from_parts(1, unb64u(payload["body"]))
        for s in list(self._sessions[peer.curve25519]):
            try:
                return self._decrypted(nick, peer, msg, s, any_msg, res)
            except vz.OlmDecryptionException:
                continue
        self._undecryptable(nick, msg.msgid, "decryption-failed", res)

    def _decrypted(self, nick, peer, msg, session, any_msg, res) -> None:
        try:
            plaintext = session.decrypt(any_msg)
        except vz.OlmDecryptionException:
            if msg.verb == "PKMSG":
                return self._undecryptable(nick, msg.msgid, "decryption-failed", res)
            raise
        # The session the peer just used is the one to answer on.
        lst = self._sessions[peer.curve25519]
        lst.remove(session)
        lst.insert(0, session)
        self._touch(peer, nick)
        self._save()
        self._deliver(nick, peer, plaintext, res)

    def _deliver(self, nick: str, peer: Peer, plaintext: bytes, res: Result) -> None:
        try:
            inner = json.loads(plaintext.decode())
        except (UnicodeDecodeError, ValueError):
            res.events.append(Dropped(nick, "undecodable-inner"))
            return
        if not isinstance(inner, dict) or not isinstance(inner.get("t"), str):
            res.events.append(Dropped(nick, "inner-without-type"))
            return
        peer = self._peers[peer.ed25519]
        if inner["t"] == "ack":
            self._on_ack(nick, peer, inner, res)
        else:
            res.events.append(Received(nick, peer, inner))

    def _on_nack(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        sent = self._sent.get(payload["ref"])
        if sent is None or sent.nick != fold(nick):
            res.events.append(Dropped(nick, "unknown-nack-ref", "NACK"))
            return
        peer = self._peers.get(sent.ed25519)
        if peer is None:
            return
        last = self._rekey_at.get(peer.ed25519)
        if last is not None and self._now() - last < REKEY_INTERVAL:
            res.events.append(RekeyThrottled(nick, peer))
            return
        del self._sent[payload["ref"]]
        lst = self._sessions.get(peer.curve25519, [])
        self._sessions[peer.curve25519] = [s for s in lst if s.session_id != sent.session_id]
        self._save()
        res.events.append(Rekeying(nick, peer))
        # Re-send the lost message on the new session (the spec's MAY).
        self._outq.setdefault(fold(nick), []).append(_Queued(sent.inner, self._now()))
        self._keyreq_at.pop(fold(nick), None)
        self._maybe_keyreq(nick, peer, res)

    def _undecryptable(self, nick: str, msgid: str, reason: str, res: Result) -> None:
        res.events.append(Undecryptable(nick, msgid, reason))
        key, now = fold(nick), self._now()
        last = self._nack_at.get(key)
        if last is not None and now - last < NACK_INTERVAL:
            return
        self._nack_at[key] = now
        self._emit(nick, "NACK", {"v": WIRE_VERSION, "ref": msgid}, res)

    # --- order challenges ---------------------------------------------------

    def challenge(self, nick: str, *, network: str, channel: str, sender_mask: str,
                  line: bytes) -> tuple[Challenge, Result]:
        """Send a CHAL for `line` to the key pinned to `nick`.
        `network` is the 005 NETWORK token; `line` the raw PRIVMSG text."""
        with self._lock:
            peer = self.pinned(nick)
            if peer is None:
                raise NotPinnedError(f"no key pinned to {nick!r}")
            ch = new_challenge(nick=nick, ed25519=peer.ed25519, network=network, channel=channel,
                               sender_mask=sender_mask, line=line, now=self._now())
            self._challenges.add(ch)
            return ch, self.send(nick, ch.inner())

    def _on_ack(self, nick: str, peer: Peer, inner: dict, res: Result) -> None:
        ch, reason = self._challenges.check(str(inner.get("nonce")), peer.ed25519, self._now())
        res.events.append(AckOk(nick, peer, ch) if ch else AckRejected(nick, peer, reason))

    # --- time --------------------------------------------------------------------

    def tick(self) -> Result:
        """Expire unanswered challenges. Call about once a second."""
        with self._lock:
            res = Result()
            now = self._now()
            for ch in self._challenges.expire(now):
                res.events.append(ChallengeExpired(ch))
            return res

    # --- identities and pins -------------------------------------------------

    def _identify(self, nick: str, ident: dict, res: Result) -> Peer | None:
        """The pinned peer behind a presented id block, or None: a bad
        signature, or a key nobody pinned (ignored, never answered)."""
        ed, curve = ident["ed25519"], ident["curve25519"]
        if not self._sig_ok(ed, ID_SIG_PREFIX + curve, ident["sig"]):
            res.events.append(Dropped(nick, "bad-identity-signature"))
            return None
        peer = self._peers.get(ed)
        if peer is None:
            pinned_ed = self._pins.get(fold(nick))
            if pinned_ed:
                res.events.append(KeyAlarm(nick, pinned_ed, ed))
            res.events.append(Dropped(nick, "unpinned-key"))
            return None
        if peer.curve25519 is None:
            peer = self._peers[ed] = replace(peer, curve25519=curve)
            self._save()
        elif peer.curve25519 != curve:
            res.events.append(Dropped(nick, "identity-curve-mismatch"))
            return None
        self._touch(peer, nick)
        return self._peers[ed]

    def _touch(self, peer: Peer, nick: str) -> None:
        cur = self._peers[peer.ed25519]
        if cur.nick != nick:
            self._peers[peer.ed25519] = replace(cur, nick=nick)
            self._save()

    # --- crypto helpers ------------------------------------------------------

    def _sign(self, text: str) -> str:
        return self._account.sign(text.encode()).to_base64()

    @staticmethod
    def _sig_ok(ed25519: str, text: str, sig: str) -> bool:
        try:
            vz.Ed25519PublicKey.from_base64(ed25519).verify_signature(
                text.encode(), vz.Ed25519Signature.from_base64(sig))
        except (vz.KeyException, vz.SignatureException, vz.DecodeException, ValueError):
            return False
        return True

    def _new_fallback_key(self) -> None:
        self._account.generate_fallback_key()
        (fb,) = self._account.fallback_key.values()
        self._account.mark_keys_as_published()
        key = fb.to_base64()
        self._fallback = {"key": key, "sig": self._sign(OTK_SIG_PREFIX + key)}

    def rotate_fallback_key(self) -> None:
        """vodozemac keeps the previous fallback key working, so a PKMSG on
        the old one still succeeds for one more rotation."""
        with self._lock:
            self._new_fallback_key()
            self._save()

    def _add_session(self, curve: str, session: vz.Session) -> None:
        lst = self._sessions.setdefault(curve, [])
        lst.insert(0, session)
        del lst[MAX_SESSIONS_PER_PEER:]

    def _trim_sent(self) -> None:
        cutoff = self._now() - SENT_MEMORY
        while self._sent and next(iter(self._sent.values())).at < cutoff:
            self._sent.popitem(last=False)

    def _now(self) -> float:
        return self._clock()

    # --- persistence -------------------------------------------------------------

    def _save(self) -> None:
        self._file.save({
            "v": STATE_VERSION,
            "network": self.network,
            # Public halves in clear, so `python -m irc_olm identity` can print
            # the key to paste without needing the pickle key.
            "identity": {"ed25519": self.fingerprint,
                         "curve25519": self._account.curve25519_key.to_base64()},
            "account": self._account.pickle(self._key),
            "fallback": self._fallback,
            "peers": {ed: {"curve25519": p.curve25519, "nick": p.nick}
                      for ed, p in self._peers.items()},
            "sessions": {c: [s.pickle(self._key) for s in lst] for c, lst in self._sessions.items()},
            "seen_sessions": list(self._seen),
        })

    def _load(self, doc: dict) -> None:
        if doc.get("v") != STATE_VERSION:
            raise StateMismatchError(f"state version {doc.get('v')!r}, expected {STATE_VERSION}")
        if doc.get("network") != self.network:
            raise StateMismatchError(
                f"{self.state_path} belongs to network {doc.get('network')!r}, not {self.network!r}")
        self._account = vz.Account.from_pickle(doc["account"], self._key)
        self._fallback = doc["fallback"]
        self._peers = {ed: Peer(ed, p["curve25519"], p["nick"]) for ed, p in doc["peers"].items()}
        self._sessions = {c: [vz.Session.from_pickle(s, self._key) for s in lst]
                          for c, lst in doc["sessions"].items()}
        self._seen = OrderedDict((sid, None) for sid in doc["seen_sessions"])
