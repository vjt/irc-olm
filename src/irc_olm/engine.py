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
KEYS_INTERVAL = KEYREQ_RETRY / 2  # at most one KEYS answer per nick in this long
                             # (two lines, 8 s of our flood bank). Half the retry:
                             # it runs from the KEYREQ's arrival here, the retry
                             # from its sending there, after a wait in a pacer
OUTQ_TTL = 60.0              # queued plaintext waiting for keys
OUTQ_MAX = 16
REKEY_INTERVAL = 60.0        # spec: at most one new session per peer per minute
OTK_PER_NICK_INTERVAL = 60.0 # one one-time key per nick per minute, else the fallback
OTK_GLOBAL_PER_HOUR = 30
SENT_MEMORY = 1800.0         # plaintexts kept for a re-send after a NACK: a full
                             # pacer backlog (480 s of bank) leaves in 24 minutes
                             # with a third of the bank left to text
SENT_MAX = 1200              # and at most this many: what the bank lets out in
                             # SENT_MEMORY (2 s a line at least) plus a backlog
MAX_SENDS = 2                # a message goes out at most twice: once, and once
                             # more on a fresh session after a NACK
URGENT_INNER = ("chal", "ack")  # inner types that may go ahead of text
MAX_SESSIONS_PER_PEER = 5
SEEN_SESSIONS_MAX = 10_000
FALLBACK_ROTATE = 7 * 86400  # vodozemac keeps the previous one: a fallback key
                             # stops opening sessions two rotations later


class StateMismatchError(ValueError):
    """A state file that belongs to another network."""


class NotPinnedError(ValueError):
    """An operation that needs a pinned key, for a nick without one."""


def b64u(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=")


def unb64u(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


def ed25519_key(key: str) -> vz.Ed25519PublicKey:
    """An Ed25519 key from base64. Raises ValueError on a malformed one.
    vodozemac 0.10 PANICS on a key of 33 bytes, and pyo3 raises that as a
    PanicException, a BaseException: it never sees anything but 32."""
    if len(unb64u(key)) != 32:
        raise ValueError("an Ed25519 key is 32 bytes")
    return vz.Ed25519PublicKey.from_base64(key)


def canonical_ed25519(key: str) -> str:
    """The one spelling of an Ed25519 key (vodozemac's unpadded to_base64()).
    Raises ValueError on a malformed key."""
    return ed25519_key(key).to_base64()


def canonical_curve25519(key: str) -> str:
    return vz.Curve25519PublicKey.from_base64(key).to_base64()


def encode_inner(inner: dict) -> bytes:
    """An inner message as the bytes Olm encrypts. Raises TypeError or
    ValueError (a lone surrogate, NaN, a value JSON has no form for)."""
    return json.dumps(inner, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode()


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
    # msgid -> seconds it stays useful (None: no deadline), for the outbound
    # messages that may go ahead of text: the KEYREQ/KEYS/NACK of the
    # protocol (the pacer budgets KEYS and NACK by their verb, a peer draws
    # them), and the messages carrying a CHAL or an ACK. A CHAL carries what
    # is left of its 15 s: the pacer starts it only while an ACK can still
    # make it back in time.
    urgent: dict[str, float | None] = field(default_factory=dict)

    def extend(self, other: "Result") -> "Result":
        self.events.extend(other.events)
        self.outbound.extend(other.outbound)
        self.urgent |= other.urgent
        return self


# --- internals ---------------------------------------------------------------

@dataclass(frozen=True)
class _Outgoing:
    plaintext: bytes = field(repr=False)
    urgent: bool     # a CHAL or an ACK: ahead of text in the pacer
    sends: int       # 1 for a first send, 2 for a re-send after a NACK
    expires: float | None   # a CHAL's expires_at: useless, and not sent, after it


@dataclass
class _Queued:
    nick: str
    ed25519: str     # the key it was meant for: it never goes to another one
    msg: _Outgoing
    at: float


@dataclass
class _Sent:
    nick: str
    ed25519: str
    session_id: str
    msg: _Outgoing
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
        self._proven: set[str] = set()               # ed25519 whose curve a decrypt proved
        self._pins: dict[str, str] = {}              # folded nick -> ed25519, from config
        self._sessions: dict[str, list[vz.Session]] = {}  # curve25519 -> newest first
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._fallback: dict = {}

        self._outq: dict[str, list[_Queued]] = {}    # folded nick -> plaintexts
        self._keyreq_at: dict[str, float] = {}       # folded nick -> last KEYREQ
        self._keys_at: dict[str, float] = {}         # folded nick -> last KEYS answer
        self._rekey_at: dict[str, float] = {}        # ed25519 -> last new outbound session
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
        with self._lock:
            curve = self._account.curve25519_key.to_base64()
            return {"curve25519": curve,
                    "ed25519": self._account.ed25519_key.to_base64(),
                    "sig": self._sign(ID_SIG_PREFIX + curve)}

    @property
    def fingerprint(self) -> str:
        with self._lock:
            return self._account.ed25519_key.to_base64()

    def set_own_mask(self, mask: str) -> None:
        with self._lock:
            self.own_mask = mask

    # --- pins -------------------------------------------------------------------

    def set_pins(self, pins: dict[str, str]) -> None:
        """Replace the pinned keys ({nick: ed25519}, from the operator's
        configuration). Keys no longer pinned lose their sessions."""
        with self._lock:
            new = {fold(nick): canonical_ed25519(ed) for nick, ed in pins.items()}
            self._pins = new
            keep = set(new.values())
            for ed in list(self._peers):
                if ed not in keep:
                    curve = self._peers.pop(ed).curve25519
                    self._sessions.pop(curve, None)
                    self._proven.discard(ed)
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
        return self._send_inner(nick, inner, expires=None)

    def _send_inner(self, nick: str, inner: dict, *, expires: float | None) -> Result:
        with self._lock:
            res = Result()
            peer = self.pinned(nick)
            if peer is None:
                res.events.append(SendFailed(nick, "unpinned-nick", 1))
                return res
            try:
                # Encoded once, here: past this point nothing can fail on it,
                # in a queue flush or a re-send least of all.
                plaintext = encode_inner(inner)
            except (TypeError, ValueError):
                res.events.append(SendFailed(nick, "unencodable", 1))
                return res
            urgent = isinstance(inner, dict) and inner.get("t") in URGENT_INNER
            self._send_to(nick, peer, _Outgoing(plaintext, urgent, 1, expires), res)
            return res

    def _send_to(self, nick: str, peer: Peer, msg: _Outgoing, res: Result) -> None:
        # While keys are asked for (first contact, or a re-key after a NACK)
        # the sessions we still hold are the ones that failed: wait.
        if self._sessions.get(peer.curve25519) and fold(nick) not in self._keyreq_at:
            self._encrypt(nick, peer, msg, res)
        else:
            self._enqueue(nick, peer, msg, res)

    def _enqueue(self, nick: str, peer: Peer, msg: _Outgoing, res: Result) -> None:
        key = fold(nick)
        q = self._live_queue(key, res)
        if len(q) >= OUTQ_MAX:
            self._lost(nick, "queue-full", [msg], res)
            return
        q.append(_Queued(nick, peer.ed25519, msg, self._now()))
        self._outq[key] = q
        res.events.append(SendQueued(nick, len(q)))
        self._maybe_keyreq(nick, peer, res)

    def _live_queue(self, key: str, res: Result) -> list[_Queued]:
        """The queue for a folded nick, minus what waited too long (reported).
        A CHAL past its deadline leaves first, unreported (_lost): it frees its
        place, and it can never wait long enough to count as a keys-timeout."""
        now = self._now()
        q = [x for x in self._outq.pop(key, []) if x.msg.expires is None or x.msg.expires > now]
        live = [x for x in q if x.at > now - OUTQ_TTL]
        if len(live) < len(q):
            res.events.append(SendFailed(q[0].nick, "keys-timeout", len(q) - len(live)))
        if live:
            self._outq[key] = live
        return live

    @staticmethod
    def _lost(nick: str, reason: str, msgs: list[_Outgoing], res: Result) -> None:
        """SendFailed for the messages in `msgs` the application wrote. A CHAL
        is not one of them: when it cannot go, its order ends as
        ChallengeExpired, and counting it here would report a lost reply
        nobody sent."""
        n = sum(1 for m in msgs if m.expires is None)
        if n:
            res.events.append(SendFailed(nick, reason, n))

    def _maybe_keyreq(self, nick: str, peer: Peer, res: Result) -> None:
        key = fold(nick)
        last = self._keyreq_at.get(key)
        if last is not None and self._now() - last < KEYREQ_RETRY:
            return
        self._keyreq_at[key] = self._now()
        self._emit(nick, "KEYREQ", {"v": WIRE_VERSION}, res, urgent=True)

    def _encrypt(self, nick: str, peer: Peer, msg: _Outgoing, res: Result) -> None:
        ttl = None if msg.expires is None else msg.expires - self._now()
        if ttl is not None and ttl <= 0:
            return          # a CHAL that expired waiting for keys: ChallengeExpired says so
        sessions = self._sessions[peer.curve25519]
        before = sessions[0].pickle(self._key)
        mtype, ct = sessions[0].encrypt(msg.plaintext).to_parts()
        if mtype == 0:
            verb, payload = "PKMSG", {"v": WIRE_VERSION, "id": self.identity, "body": b64u(ct)}
        else:
            verb, payload = "MSG", {"v": WIRE_VERSION, "ck": self.identity["curve25519"],
                                    "body": b64u(ct)}
        try:
            msgid = self._emit(nick, verb, payload, res, urgent=msg.urgent, ttl=ttl)
        except PayloadError:
            # More than 64 fragments: the session goes back to where it was,
            # leaving the peer no message key to skip (past 40 skipped, Olm
            # forgets the oldest, and the messages still on their way with
            # them). Nothing was saved, and nothing leaves.
            sessions[0] = vz.Session.from_pickle(before, self._key)
            res.events.append(SendFailed(nick, "too-long", 1))
            return
        self._save()        # before any of it leaves: the caller sends it
        self._sent[msgid] = _Sent(nick, peer.ed25519, sessions[0].session_id, msg, self._now())
        self._trim_sent()

    def _emit(self, nick: str, verb: str, payload: dict, res: Result, *, urgent: bool,
              ttl: float | None = None) -> str:
        mask = self.own_mask or framing.conservative_mask(self.nick, self.ident)
        msgid = framing.new_msgid()
        for body in framing.fragment(verb, framing.encode_payload(payload), own_mask=mask,
                                     target=nick, linelen=self.linelen, msgid=msgid):
            res.outbound.append((nick, body))
        if urgent:
            res.urgent[msgid] = ttl
        return msgid

    def discard(self, msgids: list[str]) -> None:
        """Forget the plaintexts of messages the pacer refused
        (PacedSender.submit_all): they never left, so no NACK can come for
        them, and they must not push out of SENT_MAX the ones still leaving."""
        with self._lock:
            for msgid in msgids:
                self._sent.pop(msgid, None)

    # --- receiving ---------------------------------------------------------------

    def receive(self, nick: str, body: str) -> Result:
        with self._lock:
            res = Result()
            frag = framing.parse(body)
            if frag is None:
                res.events.append(Dropped(nick, "malformed-or-unknown-verb"))
                return res
            done = self._reasm.feed(fold(nick), frag)
            for sender, gone in self._reasm.take_evicted():
                res.events.append(Dropped(sender, f"reassembly:{gone.reason}", gone.verb))
            if done is None:
                return res
            if isinstance(done, Rejected):
                res.events.append(Dropped(nick, f"reassembly:{done.reason}", done.verb))
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
            except BaseException as e:
                # vodozemac panicking on some input it should have refused:
                # pyo3 raises a PanicException, a BaseException no one can
                # import. Wire input again, so a drop; nothing else is.
                if type(e).__name__ != "PanicException":
                    raise
                res.events.append(Dropped(nick, "bad-payload:PanicException", done.verb))
            return res

    def _on_keyreq(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        if self.pinned(nick) is None:
            res.events.append(Dropped(nick, "unpinned-nick", "KEYREQ"))
            return
        key, now = fold(nick), self._now()
        last_keys = self._keys_at.get(key)
        if last_keys is not None and now - last_keys < KEYS_INTERVAL:
            res.events.append(Dropped(nick, "keyreq-rate-limited", "KEYREQ"))
            return
        self._keys_at[key] = now
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
        self._emit(nick, "KEYS", {"v": WIRE_VERSION, "id": self.identity, "otk": entry}, res,
                   urgent=True)

    def _on_keys(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        key = fold(nick)
        if key not in self._keyreq_at:
            res.events.append(Dropped(nick, "unsolicited-keys", "KEYS"))
            return
        otk = payload["otk"]
        if not self._sig_ok(payload["id"]["ed25519"], OTK_SIG_PREFIX + otk["key"], otk["sig"]):
            res.events.append(Dropped(nick, "bad-otk-signature", "KEYS"))
            return
        peer = self._identify(nick, payload["id"], res, proving=False)
        if peer is not None:
            # First, so that a one-time key vodozemac refuses (raised as a
            # Dropped) leaves the queue waiting, to be reported if it expires.
            session = self._account.create_outbound_session(
                vz.Curve25519PublicKey.from_base64(peer.curve25519),
                vz.Curve25519PublicKey.from_base64(otk["key"]))
        del self._keyreq_at[key]
        queue = self._live_queue(key, res)
        self._outq.pop(key, None)
        # Each queued message goes to the key it was meant for, or nowhere:
        # the nick may have been re-pinned since it was queued.
        mine = [q for q in queue if peer is not None and q.ed25519 == peer.ed25519]
        self._lost(nick, "key-mismatch",
                   [q.msg for q in queue if peer is None or q.ed25519 != peer.ed25519], res)
        if not mine:
            return
        self._bind(peer, proven=False)
        self._add_session(peer.curve25519, session)
        self._rekey_at[peer.ed25519] = self._now()
        for q in mine:
            self._encrypt(nick, peer, q.msg, res)

    def _on_pkmsg(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        peer = self._identify(nick, payload["id"], res, proving=True)
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
            return self._undecryptable(nick, msg.msgid, "replayed-session", peer, res)
        try:
            session, plaintext = self._account.create_inbound_session(
                vz.Curve25519PublicKey.from_base64(peer.curve25519), pre)
        except vz.SessionCreationException as e:
            return self._undecryptable(nick, msg.msgid, f"session-creation:{e}", peer, res)
        self._seen[sid] = None
        while len(self._seen) > SEEN_SESSIONS_MAX:
            self._seen.popitem(last=False)
        self._bind(peer, proven=True)
        self._add_session(peer.curve25519, session)
        self._touch(peer, nick)
        self._save()
        self._deliver(nick, peer, plaintext, res)

    def _on_msg(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        owner = self._curve_owner(canonical_curve25519(payload["ck"]))
        if owner is None:
            mapped = self.pinned(nick)
            if mapped is None:
                res.events.append(Dropped(nick, "unpinned-key", "MSG"))
                return
            # A pinned nick whose key we never saw a session for (our state
            # was lost?): a NACK makes it open a fresh one, with its id block.
            return self._undecryptable(nick, msg.msgid, "no-session", mapped, res)
        peer = self._peers[owner]
        if not self._sessions.get(peer.curve25519):
            return self._undecryptable(nick, msg.msgid, "no-session", peer, res)
        # Nothing about the peer moves before a decrypt succeeds: `ck` is
        # public, and anyone can put it on a line.
        any_msg = vz.AnyOlmMessage.from_parts(1, unb64u(payload["body"]))
        for s in list(self._sessions[peer.curve25519]):
            try:
                return self._decrypted(nick, peer, msg, s, any_msg, res)
            except vz.OlmDecryptionException:
                continue
        self._undecryptable(nick, msg.msgid, "decryption-failed", peer, res)

    def _decrypted(self, nick, peer, msg, session, any_msg, res) -> None:
        try:
            plaintext = session.decrypt(any_msg)
        except vz.OlmDecryptionException:
            if msg.verb == "PKMSG":
                return self._undecryptable(nick, msg.msgid, "decryption-failed", peer, res)
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
        except (UnicodeDecodeError, ValueError, RecursionError):
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
        self._trim_sent()
        sent = self._sent.pop(payload["ref"], None)
        if sent is None:
            res.events.append(Dropped(nick, "unknown-nack-ref", "NACK"))
            return
        peer = self._peers.get(sent.ed25519)
        if fold(sent.nick) != fold(nick):
            # NACKs are not authenticated: never re-send on the word of a
            # nick we did not send to. The recipient renamed, most likely.
            self._lost(sent.nick, "nack-from-another-nick", [sent.msg], res)
            return
        if peer is None:
            self._lost(nick, "unpinned-key", [sent.msg], res)
            return
        if not self._reached_at(nick, peer):
            self._lost(nick, "repinned", [sent.msg], res)
            return
        if sent.msg.sends >= MAX_SENDS:
            self._lost(nick, "resend-failed", [sent.msg], res)
            return
        lst = self._sessions.get(peer.curve25519) or []
        if lst and lst[0].session_id != sent.session_id or fold(nick) in self._keyreq_at:
            # The failed session is not our newest, or keys are already asked
            # for (a re-key for an earlier NACK of the same burst, say): re-send
            # on the newest, or queue behind the keys. No new session.
            self._drop_session(peer.curve25519, sent.session_id)
            return self._send_to(nick, peer, replace(sent.msg, sends=sent.msg.sends + 1), res)
        # The failed session is our newest: only a new one helps, and the
        # spec allows one per peer per minute.
        last = self._rekey_at.get(peer.ed25519)
        if last is not None and self._now() - last < REKEY_INTERVAL:
            self._lost(nick, "rekey-throttled", [sent.msg], res)
            return
        self._drop_session(peer.curve25519, sent.session_id)
        res.events.append(Rekeying(nick, peer))
        # Re-send the lost message on the new session (the spec's MAY).
        self._keyreq_at.pop(fold(nick), None)
        self._enqueue(nick, peer, replace(sent.msg, sends=sent.msg.sends + 1), res)

    def _undecryptable(self, nick: str, msgid: str, reason: str, peer: Peer,
                       res: Result) -> None:
        """Report it, and NACK when `nick` is where `peer`, the key the line
        claims, is reached: a pinned key's curve and id block are public, and
        anyone can put them on a line. Every such message gets its own NACK,
        one line out per message in: the sender re-sends what is NACKed, and
        a message without a NACK is lost without a word."""
        res.events.append(Undecryptable(nick, msgid, reason))
        if self._reached_at(nick, peer):
            self._emit(nick, "NACK", {"v": WIRE_VERSION, "ref": msgid}, res, urgent=True)

    def _reached_at(self, nick: str, peer: Peer) -> bool:
        """Whether sending to `nick` reaches `peer`'s key."""
        mapped = self.pinned(nick)
        return mapped is not None and mapped.ed25519 == peer.ed25519

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
            return ch, self._send_inner(nick, ch.inner(), expires=ch.expires_at)

    def _on_ack(self, nick: str, peer: Peer, inner: dict, res: Result) -> None:
        ch, reason = self._challenges.check(str(inner.get("nonce")), peer.ed25519, self._now())
        res.events.append(AckOk(nick, peer, ch) if ch else AckRejected(nick, peer, reason))

    # --- time --------------------------------------------------------------------

    def tick(self) -> Result:
        """Expire unanswered challenges and queued messages that waited too
        long for keys, forget old plaintexts, rotate the fallback key when it
        is due. Call about once a second."""
        with self._lock:
            res = Result()
            now = self._now()
            for ch in self._challenges.expire(now):
                res.events.append(ChallengeExpired(ch))
            for key in list(self._outq):
                self._live_queue(key, res)
            self._trim_sent()
            if now - self._fallback["at"] >= FALLBACK_ROTATE:
                self._new_fallback_key()
                self._save()
            return res

    # --- identities and pins -------------------------------------------------

    def _identify(self, nick: str, ident: dict, res: Result, *, proving: bool) -> Peer | None:
        """The pinned peer behind a presented id block, with the presented
        curve filled in but NOT stored, or None: a bad signature, our own
        identity, a key nobody pinned (ignored, never answered), or a curve
        that belongs to another key.

        An id block is public and replayable, and its signature only says the
        Ed25519 key CLAIMS that curve, not that it holds it. So the caller
        stores the curve (_bind) only once a session exists, and moves the
        nick hint (_touch) only once a message decrypted. A session we opened
        on keys we asked for proves nothing, and neither does a message on
        it (a pinned key can claim another's curve, hand us that one's
        one-time key and relay). Only a pre-key message the curve's holder
        built to us does: `proving` may take the curve from a key that only
        claimed it."""
        if not self._sig_ok(ident["ed25519"], ID_SIG_PREFIX + ident["curve25519"], ident["sig"]):
            res.events.append(Dropped(nick, "bad-identity-signature"))
            return None
        ed = canonical_ed25519(ident["ed25519"])
        curve = canonical_curve25519(ident["curve25519"])
        if curve == self._account.curve25519_key.to_base64():
            # Else a pinned key could claim our curve, hand us our own
            # fallback key as its one-time key, and reflect our own messages
            # back to us as its own. (Our own key cannot sign another curve.)
            res.events.append(Dropped(nick, "own-identity"))
            return None
        peer = self._peers.get(ed)
        if peer is None:
            pinned_ed = self._pins.get(fold(nick))
            if pinned_ed:
                res.events.append(KeyAlarm(nick, pinned_ed, ed))
            res.events.append(Dropped(nick, "unpinned-key"))
            return None
        if peer.curve25519 is not None and peer.curve25519 != curve:
            res.events.append(Dropped(nick, "identity-curve-mismatch"))
            return None
        owner = self._curve_owner(curve)
        if owner not in (None, ed) and (owner in self._proven or not proving):
            # One curve under two keys would let one peer's messages be
            # read as the other's (sessions and MSG lookups go by curve).
            res.events.append(Dropped(nick, "curve-already-bound"))
            return None
        return replace(peer, curve25519=curve)

    def _curve_owner(self, curve: str | None) -> str | None:
        if curve is None:
            return None
        return next((ed for ed, p in self._peers.items() if p.curve25519 == curve), None)

    def _bind(self, peer: Peer, *, proven: bool) -> None:
        """Store the curve a session was opened on; `proven` when a pre-key
        message decrypted on it. A proof evicts another key's claim on that
        curve, sessions included (_identify let it through only if
        unproven)."""
        owner = self._curve_owner(peer.curve25519)
        if owner not in (None, peer.ed25519):
            self._peers[owner] = replace(self._peers[owner], curve25519=None)
            self._sessions.pop(peer.curve25519, None)
        cur = self._peers[peer.ed25519]
        if cur.curve25519 is None:
            self._peers[peer.ed25519] = replace(cur, curve25519=peer.curve25519)
        if proven:
            self._proven.add(peer.ed25519)

    def _touch(self, peer: Peer, nick: str) -> None:
        """The nick hint follows the key that just spoke. A hint names one
        key: any other key last seen there is back at its configured nick."""
        for ed, p in list(self._peers.items()):
            if ed != peer.ed25519 and fold(p.nick) == fold(nick):
                self._peers[ed] = replace(p, nick=next(n for n, e in self._pins.items() if e == ed))
        self._peers[peer.ed25519] = replace(self._peers[peer.ed25519], nick=nick)

    # --- crypto helpers ------------------------------------------------------

    def _sign(self, text: str) -> str:
        return self._account.sign(text.encode()).to_base64()

    @staticmethod
    def _sig_ok(ed25519: str, text: str, sig: str) -> bool:
        try:
            ed25519_key(ed25519).verify_signature(
                text.encode(), vz.Ed25519Signature.from_base64(sig))
        except (vz.KeyException, vz.SignatureException, vz.DecodeException, ValueError):
            return False
        return True

    def _new_fallback_key(self) -> None:
        self._account.generate_fallback_key()
        (fb,) = self._account.fallback_key.values()
        self._account.mark_keys_as_published()
        key = fb.to_base64()
        self._fallback = {"key": key, "sig": self._sign(OTK_SIG_PREFIX + key), "at": self._now()}

    def _drop_session(self, curve: str | None, session_id: str) -> None:
        rest = [s for s in self._sessions.get(curve, []) if s.session_id != session_id]
        if rest:
            self._sessions[curve] = rest
        else:
            self._sessions.pop(curve, None)
        self._save()

    def _add_session(self, curve: str, session: vz.Session) -> None:
        lst = self._sessions.setdefault(curve, [])
        lst.insert(0, session)
        del lst[MAX_SESSIONS_PER_PEER:]

    def _trim_sent(self) -> None:
        cutoff = self._now() - SENT_MEMORY
        while self._sent and (len(self._sent) > SENT_MAX
                              or next(iter(self._sent.values())).at < cutoff):
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
            "peers": {ed: {"curve25519": p.curve25519, "nick": p.nick,
                           "proven": ed in self._proven}
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
        self._proven = {ed for ed, p in doc["peers"].items() if p.get("proven")}
        self._sessions = {c: [vz.Session.from_pickle(s, self._key) for s in lst]
                          for c, lst in doc["sessions"].items()}
        self._seen = OrderedDict((sid, None) for sid in doc["seen_sessions"])
