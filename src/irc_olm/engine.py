"""The E2E engine for one network: master key, Olm device, peers, wire verbs.

Pure in the IRC sense: it never touches a socket. `receive()` takes the body
of a PRIVMSG that `framing.is_e2e()` recognised, `send()` takes an inner
message; both return a Result with the events for the application and the
CTCP bodies to send (through a pacing.PacedSender), one PRIVMSG per body.

Identity (wire v2, grappa-irc#2430): one master Ed25519 key per network, and
under it one Olm device, this engine's. The master signs the list of its
devices (always just this one, for a bot) and a certificate for each; the
master is the key an operator pastes into its peers' configuration. A peer is
a master too, with 1 to 4 devices of its own, and a message to a peer is one
Olm message per nick holding one encrypted body for each trusted device.

Pinned keys only (vjt's final ruling, 2026-10-18): a bot talks E2E only to the
master keys an operator pasted into its configuration, and ignores every
other key: no KEYS, no NACK, no session. The pin is on the master, never on
the nick. The configured nick is where messages are sent; a pinned master
that shows up under another nick is still accepted, and a different master on
a pinned nick raises KeyAlarm (for the log) and is ignored. Rotating a key
means re-pasting it into the configuration and calling set_pins(). There is
no SAS and no trust-on-first-use here; SAS is for humans, in cicchetto.
"""

from __future__ import annotations

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
from .devices import (MAX_DEVICES, Book, Device, InvalidBlock, binding, cert_ok, did, id_block,
                      id_ok, parse_keys, parse_master, parse_master_ref, sign_cert,
                      sign_master, wire_int)
from .framing import PayloadError, fold
from .keys import b64, ed25519_key, is_key, sig_ok, unb64
from .reassembly import Assembled, Reassembler, Rejected
from .store import StateFile

STATE_VERSION = 2
WIRE_VERSION = 2

OTK_SIG_PREFIX = "irc-e2e:v1:otk:"   # wire v2 keeps v1's one-time key signature

KEYREQ_RETRY = 30.0          # re-ask for keys when still waiting after this long
KEYS_INTERVAL = KEYREQ_RETRY / 2  # at most one KEYS answer per nick in this long
                             # (two lines, 8 s of our flood bank). Half the retry:
                             # it runs from the KEYREQ's arrival here, the retry
                             # from its sending there, after a wait in a pacer
OUTQ_TTL = 60.0              # queued plaintext waiting for keys
OUTQ_MAX = 16
REKEY_INTERVAL = 60.0        # spec: at most one re-key per nick per minute
OTK_PER_NICK_INTERVAL = 60.0 # one one-time key per nick per minute, else the fallback
OTK_GLOBAL_PER_HOUR = 30
SENT_MEMORY = 1800.0         # plaintexts kept for a re-send after a NACK: a full
                             # pacer backlog (480 s of bank) leaves in 24 minutes
                             # with a third of the bank left to text
SENT_MAX = 1200              # and at most this many: what the bank lets out in
                             # SENT_MEMORY (2 s a line at least) plus a backlog
MAX_SENDS = 2                # a message goes out at most twice to a device: once,
                             # and once more on a fresh session after a NACK
URGENT_INNER = ("chal", "ack")  # inner types that may go ahead of text
LISTREQ_INTERVAL = 60.0      # a listreq per nick, and an answer per (nick, device), a minute
PROTOCOL_INNER = ("lv", "fb")   # inner fields the engine writes and reads itself
MAX_SESSIONS_PER_PEER = 5
SEEN_SESSIONS_MAX = 10_000
FALLBACK_ROTATE = 7 * 86400  # vodozemac keeps the previous one: a fallback key
                             # stops opening sessions two rotations later


class StateMismatchError(ValueError):
    """A state file that belongs to another network, or to another version."""


class NotPinnedError(ValueError):
    """An operation that needs a pinned key, for a nick without one."""


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


def _with_binding(plaintext: bytes, fb: str) -> bytes:
    """An encoded inner message with `fb` added. It is an object holding
    `lv` at least, so it ends in a `}` after one member or more."""
    return plaintext[:-1] + b',"fb":"' + fb.encode() + b'"}'


# --- public types ----------------------------------------------------------

@dataclass(frozen=True)
class Peer:
    """A pinned person: their master key, and the last nick a message from
    one of its devices came from, a routing hint only."""
    master: str
    nick: str


@dataclass(frozen=True)
class Received:
    """A decrypted inner message from `device`, one of `peer`'s Ed25519
    device keys. `inner` is plaintext: never log it."""
    nick: str
    peer: Peer
    device: str
    inner: dict = field(repr=False)


@dataclass(frozen=True)
class KeyAlarm:
    """A nick pinned to one master presented another. Ignored; for the log."""
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
    device: str


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
    # The msgids of the Olm messages a peer drew from us, the REACTIVE lane's
    # as KEYS and NACK are: a `listreq` and the `t:list` answering one.
    reactive: set[str] = field(default_factory=set)

    def extend(self, other: "Result") -> "Result":
        self.events.extend(other.events)
        self.outbound.extend(other.outbound)
        self.urgent |= other.urgent
        self.reactive |= other.reactive
        return self


# --- internals ---------------------------------------------------------------

@dataclass(frozen=True)
class _Outgoing:
    plaintext: bytes = field(repr=False)   # holds our `lv`; a pre-key body adds `fb`
    urgent: bool     # a CHAL or an ACK: ahead of text in the pacer
    sends: int       # 1 for a first send, 2 for a re-send after a NACK
    expires: float | None   # a CHAL's expires_at: useless, and not sent, after it
    reactive: bool   # a listreq or a t:list: the engine's own, on the REACTIVE lane

    @property
    def written(self) -> bool:
        """A message the application wrote: text or an ACK, whose loss is
        reported (SendFailed), and which waits in the queue for keys. A CHAL
        never does: it goes only on a session its device has written to (O1),
        and when it cannot go its order ends in the challenge book. Neither
        does a listreq or a t:list, which the next decrypt asks again."""
        return self.expires is None and not self.reactive


@dataclass
class _Queued:
    nick: str
    master: str      # the master it was meant for: it never goes to another one
    msg: _Outgoing
    at: float
    want: frozenset[str] | None   # the device keys it is for; None: all of them
    done: frozenset[str]          # the device keys it already went to


@dataclass
class _Sent:
    nick: str
    master: str
    msg: _Outgoing
    at: float
    bodies: dict[str, tuple[str, str]]   # did -> (device key, session id)


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

        self._peers: dict[str, Peer] = {}            # master -> Peer (pinned only)
        self._pins: dict[str, str] = {}              # folded nick -> master, from config
        self._books: dict[str, Book] = {}            # master -> its devices, as we know them
        self._sessions: dict[str, list[vz.Session]] = {}  # device curve25519 -> newest first
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._fallback: dict = {}

        self._outq: dict[str, list[_Queued]] = {}    # folded nick -> plaintexts
        self._keyreq_at: dict[str, float] = {}       # folded nick -> last KEYREQ
        self._keyreq_out: set[str] = set()           # folded nicks a KEYS is due from
        self._keys_at: dict[str, float] = {}         # folded nick -> last KEYS answer
        self._rekey_at: dict[str, float] = {}        # folded nick -> last re-key or session opened
        self._rekey_due: dict[str, str] = {}         # folded nick -> nick: a re-key's KEYREQ waits
        self._rekeying: set[str] = set()             # device keys waiting for fresh keys
        self._listreq_at: dict[str, float] = {}      # folded nick -> last listreq sent
        self._listreq_lv: dict[str, set[int]] = {}   # folded nick -> the lvs asked for
        self._listed_at: dict[tuple[str, str], float] = {}  # (nick, device) -> list sent
        self._otk_at: dict[str, float] = {}          # folded nick -> last OTK handed out
        self._otk_log: list[float] = []
        self._sent: OrderedDict[str, _Sent] = OrderedDict()   # msgid -> its bodies
        self._challenges = ChallengeBook()

        doc = self._file.load()
        if doc is None:
            self._account = vz.Account()     # the device
            self._master = vz.Account()      # only its Ed25519 key and sign() are used
            self._ver = 1
            self._new_fallback_key()
        else:
            self._load(doc)
        self._own_blocks()
        self.set_pins(pins)

    # --- identity --------------------------------------------------------------

    @property
    def identity(self) -> dict:
        """This device's id block: its keys, signed with its master."""
        return self._id_block

    @property
    def did(self) -> str:
        """This device's address on the wire: who its lines are from, and the
        only `to` it takes besides `*`."""
        return self._did

    @property
    def fingerprint(self) -> str:
        """The master key: what an operator pastes into a peer's pins."""
        return self._master_key

    @property
    def device_key(self) -> str:
        return self._device_key

    @property
    def master_block(self) -> dict:
        """Our signed device list, as KEYS carries it."""
        return self._own_block

    @property
    def master_ref(self) -> dict:
        """Our master and its certificate for this device, as a PKMSG
        carries them."""
        return {"ed25519": self._master_key, "cert": self._cert}

    def set_own_mask(self, mask: str) -> None:
        with self._lock:
            self.own_mask = mask

    # --- pins -------------------------------------------------------------------

    def set_pins(self, pins: dict[str, str]) -> None:
        """Replace the pinned masters ({nick: ed25519}, from the operator's
        configuration). A master no longer pinned loses its devices'
        sessions; its list and what it revoked stay, so a re-pin cannot roll
        them back."""
        with self._lock:
            new = {fold(nick): canonical_ed25519(ed) for nick, ed in pins.items()}
            self._pins = new
            keep = set(new.values())
            for master in list(self._peers):
                if master not in keep:
                    del self._peers[master]
                    self._forget_devices(master)
            for nick, master in new.items():
                if master not in self._peers:
                    self._peers[master] = Peer(master, nick)
            self._save()

    def peers(self) -> list[Peer]:
        with self._lock:
            return list(self._peers.values())

    def pinned(self, nick: str) -> Peer | None:
        """The pinned identity to talk to as `nick`: the one configured for
        that nick, else a pinned master last heard from under it (a renamed
        peer)."""
        with self._lock:
            master = self._pins.get(fold(nick))
            if master:
                return self._peers[master]
            return next((p for p in self._peers.values() if fold(p.nick) == fold(nick)), None)

    def devices(self, master: str) -> list[Device]:
        """The trusted devices of a pinned master that we hold a curve for,
        the most recently heard first."""
        with self._lock:
            book = self._books.get(master)
            return book.targets() if book and master in self._peers else []

    def forget_sessions(self, master: str) -> None:
        with self._lock:
            book = self._books.get(master)
            gone = [self._sessions.pop(d.curve25519, None) for d in (book.targets() if book else [])]
            if any(gone):
                self._save()

    def _forget_devices(self, master: str) -> None:
        book = self._books.get(master)
        if book is not None:
            for d in book.targets():
                self._sessions.pop(d.curve25519, None)
                self._rekeying.discard(d.ed25519)
            book.forget_devices()

    # --- sending -----------------------------------------------------------------

    def send(self, nick: str, inner: dict) -> Result:
        """Encrypt `inner` for every trusted device of the master pinned to
        `nick`, and queue it for the devices still without a session, asking
        for keys."""
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
                if not isinstance(inner, dict):
                    raise TypeError("an inner message is an object")
                own = {k: v for k, v in inner.items() if k not in PROTOCOL_INNER}
                plaintext = encode_inner(own | {"lv": self._ver})
            except (TypeError, ValueError):
                if expires is None:     # a CHAL's order ends in the book (_lost)
                    res.events.append(SendFailed(nick, "unencodable", 1))
                return res
            urgent = inner.get("t") in URGENT_INNER
            self._send_to(nick, peer, _Outgoing(plaintext, urgent, 1, expires, False), res)
            return res

    def _send_to(self, nick: str, peer: Peer, msg: _Outgoing, res: Result, *,
                 want: frozenset[str] | None = None, done: frozenset[str] = frozenset()) -> None:
        """`msg` now to the devices ready for it, and queued for the others,
        keys asked for: the devices listed or certified that have no session,
        those re-keying after a NACK, and every device not known yet while we
        hold no list."""
        book = self._books.get(peer.master)
        ready, lacking = self._split(book, want, done)
        if ready:
            done = done | self._encrypt(nick, peer, msg, ready, res)
        if msg.written and (lacking or (want is None and (book is None or book.ver == 0))):
            self._enqueue(nick, peer, msg, res, want=want, done=done)

    def _split(self, book: Book | None, want: frozenset[str] | None,
               done: frozenset[str]) -> tuple[list[Device], set[str]]:
        """The devices a message is for that are ready for it, in the order
        copies go (Book.targets), and the ones that are not."""
        if book is None:
            return [], set()
        wanted = (book.wanted() if want is None else want & book.wanted()) - done
        ready = [d for d in book.targets() if d.ed25519 in wanted and self._ready(book, d)]
        return ready, wanted - {d.ed25519 for d in ready}

    def _ready(self, book: Book, d: Device) -> bool:
        """A trusted device with a session we may send on: none while keys
        are asked for after it NACKed (the sessions we hold are the ones that
        failed)."""
        return (not book.revoked(d.ed25519) and d.ed25519 not in self._rekeying
                and bool(self._sessions.get(d.curve25519)))

    def _enqueue(self, nick: str, peer: Peer, msg: _Outgoing, res: Result, *,
                 want: frozenset[str] | None, done: frozenset[str]) -> None:
        key = fold(nick)
        q = self._live_queue(key, res)
        if len(q) >= OUTQ_MAX:
            # A copy that already reached some device is not lost: the ones
            # still without a session miss it.
            if not done:
                self._lost(nick, "queue-full", [msg], res)
            return
        q.append(_Queued(nick, peer.master, msg, self._now(), want, done))
        self._outq[key] = q
        if not done:
            res.events.append(SendQueued(nick, len(q)))
        self._maybe_keyreq(nick, res)

    def _live_queue(self, key: str, res: Result) -> list[_Queued]:
        """The queue for a folded nick, minus what waited too long (reported
        when it reached no device, a CHAL excepted: see _lost). A CHAL past
        its deadline stays until OUTQ_TTL like the rest, never sent
        (_encrypt): when the keys come back, it is what says they are the
        keys of the master it was queued for (_on_keys)."""
        q = self._outq.pop(key, [])
        cutoff = self._now() - OUTQ_TTL
        live = [x for x in q if x.at > cutoff]
        if len(live) < len(q):
            self._lost(q[0].nick, "keys-timeout",
                       [x.msg for x in q if x.at <= cutoff and not x.done], res)
        if live:
            self._outq[key] = live
        return live

    @staticmethod
    def _lost(nick: str, reason: str, msgs: list[_Outgoing], res: Result) -> None:
        """SendFailed for the messages in `msgs` the application wrote
        (_Outgoing.written). A CHAL is not one of them: when it cannot go, its
        order ends in the challenge book (ChallengeExpired, unless an ACK
        still comes), and counting it here would report a lost reply nobody
        sent."""
        n = sum(1 for m in msgs if m.written)
        if n:
            res.events.append(SendFailed(nick, reason, n))

    def _maybe_keyreq(self, nick: str, res: Result) -> None:
        key = fold(nick)
        last = self._keyreq_at.get(key)
        if last is not None and self._now() - last < KEYREQ_RETRY:
            return
        self._keyreq_at[key] = self._now()
        self._keyreq_out.add(key)
        self._rekey_due.pop(key, None)
        self._emit(nick, "KEYREQ", {"v": WIRE_VERSION}, res, to=framing.ANY, urgent=True)

    def _encrypt(self, nick: str, peer: Peer, msg: _Outgoing, ready: list[Device],
                 res: Result) -> frozenset[str]:
        """One body per device in `ready`: MSG bodies for the devices whose
        session has heard from them, PKMSG bodies for the rest, never both
        kinds in one message. Returns the device keys it went to, or tried
        to."""
        tried = frozenset(d.ed25519 for d in ready)
        ttl = None if msg.expires is None else msg.expires - self._now()
        if ttl is not None and ttl <= 0:
            return tried    # a CHAL that expired waiting for keys: ChallengeExpired says so
        # In the order of `ready`: the kind holding the device heard from
        # last leaves first.
        kinds: dict[int, dict[str, tuple[Device, str, str]]] = {}
        for d in ready:
            sessions = self._sessions[d.curve25519]
            before = sessions[0].pickle(self._key)
            mtype, ct = sessions[0].encrypt(msg.plaintext).to_parts()
            if mtype == 0 and msg.expires is not None:
                # A CHAL is never a pre-key message (O1): only a device that
                # has written to this session gets one, so a device we never
                # heard from cannot answer for an order it did not give.
                sessions[0] = vz.Session.from_pickle(before, self._key)
                continue
            if mtype == 0:
                # A pre-key body binds both device keys (`fb`), and which kind
                # a session writes shows only once it has: write it again,
                # from where the session was, with the binding.
                sessions[0] = vz.Session.from_pickle(before, self._key)
                fb = binding(self._device_key, d.ed25519)
                mtype, ct = sessions[0].encrypt(_with_binding(msg.plaintext, fb)).to_parts()
            kinds.setdefault(mtype, {})[did(d.ed25519)] = (d, before, b64(ct))
        failed: list[tuple[Device, str, str]] = []
        for mtype, bodies in kinds.items():
            # A message holds MAX_DEVICES bodies at most, and a full list
            # plus a device trusted on its certificate alone is one more.
            group = list(bodies.items())
            for i in range(0, len(group), MAX_DEVICES):
                failed += self._emit_group(nick, peer, mtype, dict(group[i:i + MAX_DEVICES]),
                                           msg, ttl, res)
        for d, before, _ in failed:
            # The session goes back to where it was, leaving the peer no
            # message key to skip (past 40 skipped, Olm forgets the oldest,
            # and the messages still on their way with them).
            self._sessions[d.curve25519][0] = vz.Session.from_pickle(before, self._key)
        if failed:
            self._lost(nick, "too-long", [msg], res)
        self._save()        # before any of it leaves: the caller sends it
        return tried

    def _emit_group(self, nick: str, peer: Peer, mtype: int,
                    bodies: dict[str, tuple[Device, str, str]], msg: _Outgoing,
                    ttl: float | None, res: Result) -> list[tuple[Device, str, str]]:
        """`bodies` in one message, else one message each; the bodies that
        did not fit even alone."""
        try:
            self._emit_bodies(nick, peer, mtype, bodies, msg, ttl, res)
            return []
        except PayloadError:
            # More than 64 fragments together: one message per device,
            # each with its own body, is what still fits, if anything.
            if len(bodies) == 1:
                return list(bodies.values())
        failed = []
        for addr, body in bodies.items():
            try:
                self._emit_bodies(nick, peer, mtype, {addr: body}, msg, ttl, res)
            except PayloadError:
                failed.append(body)
        return failed

    def _emit_bodies(self, nick: str, peer: Peer, mtype: int,
                     bodies: dict[str, tuple[Device, str, str]], msg: _Outgoing,
                     ttl: float | None, res: Result) -> None:
        wire = {addr: ct for addr, (_, _, ct) in bodies.items()}
        if mtype == 0:
            verb, payload = "PKMSG", {"v": WIRE_VERSION, "id": self._id_block,
                                      "master": self.master_ref, "bodies": wire}
        else:
            verb, payload = "MSG", {"v": WIRE_VERSION, "ck": self._id_block["curve25519"],
                                    "bodies": wire}
        to = next(iter(wire)) if len(wire) == 1 else framing.ANY
        msgid = self._emit(nick, verb, payload, res, to=to, urgent=msg.urgent, ttl=ttl)
        if msg.reactive:
            res.reactive.add(msgid)
        self._sent[msgid] = _Sent(nick, peer.master, msg, self._now(), {
            addr: (d.ed25519, self._sessions[d.curve25519][0].session_id)
            for addr, (d, _, _) in bodies.items()})
        self._trim_sent()

    def _emit(self, nick: str, verb: str, payload: dict, res: Result, *, to: str, urgent: bool,
              ttl: float | None = None) -> str:
        """Frame `payload` for `nick`. Raises PayloadError, before anything is
        added to `res`, when it needs more than 64 fragments."""
        mask = self.own_mask or framing.conservative_mask(self.nick, self.ident)
        msgid = framing.new_msgid()
        src = framing.ANY if verb == "KEYS" else self._did   # a KEYS describes the user
        for body in framing.fragment(verb, framing.encode_payload(payload), src=src, dst=to,
                                     own_mask=mask, target=nick, linelen=self.linelen,
                                     msgid=msgid):
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
            key = fold(nick)
            if frag.verb == "KEYS" and frag.dst == self._did and key in self._keyreq_out:
                # A KEYS on its way: the retry waits for it, however long its
                # lines take to come (amendment O2).
                self._keyreq_at[key] = self._now()
            done = self._reasm.feed(key, frag)
            for sender, gone in self._reasm.take_evicted():
                res.events.append(Dropped(sender, f"reassembly:{gone.reason}", gone.verb))
            if done is None:
                return res
            if isinstance(done, Rejected):
                res.events.append(Dropped(nick, f"reassembly:{done.reason}", done.verb))
                return res
            if done.dst not in (self._did, framing.ANY):
                # Another device's line (grappa routes by `to`; a bot sees
                # whatever IRC brings it).
                res.events.append(Dropped(nick, "not-for-this-device", done.verb))
                return res
            try:
                payload = framing.decode_payload(done.payload)
            except PayloadError:
                res.events.append(Dropped(nick, "undecodable-payload", done.verb))
                return res
            if wire_int(payload.get("v")) != WIRE_VERSION:
                res.events.append(Dropped(nick, "wire-version", done.verb))
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
        self._emit(nick, "KEYS", {"v": WIRE_VERSION, "master": self._own_block,
                                  "devices": [{"id": self._id_block, "otk": entry}]},
                   res, to=msg.src, urgent=True)

    def _on_keys(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        key = fold(nick)
        if key not in self._keyreq_out:
            res.events.append(Dropped(nick, "unsolicited-keys", "KEYS"))
            return
        try:
            lst, entries = parse_keys(payload)
        except InvalidBlock:
            res.events.append(Dropped(nick, "invalid-keys", "KEYS"))
            return
        # A KEYS answers the KEYREQ we sent to `nick`: it must describe the
        # master we asked there, wherever else that master is pinned.
        peer = self.pinned(nick)
        if peer is not None and peer.master != lst.master:
            res.events.append(KeyAlarm(nick, peer.master, lst.master))
            res.events.append(Dropped(nick, "wrong-master", "KEYS"))
            peer = None
        if peer is not None:
            book = self._book(peer.master)
            self._revoke(book, book.apply(lst)[1])
            if self._open_sessions(nick, book, entries, res):
                self._rekey_at[key] = self._now()
        self._keyreq_out.discard(key)
        queue = self._live_queue(key, res)
        self._outq.pop(key, None)
        # Each queued message goes to the master it was meant for, or nowhere:
        # the nick may have been re-pinned since it was queued.
        self._lost(nick, "key-mismatch", [q.msg for q in queue if not q.done and (
            peer is None or q.master != peer.master)], res)
        # The copies for devices still without a session (no entry in this
        # KEYS, a one-time key vodozemac refused) wait for the next KEYS, to
        # be reported if they expire having reached no device.
        rest = [r for q in queue if peer is not None and q.master == peer.master
                and (r := self._flush(nick, peer, q, res)) is not None]
        if rest:
            self._outq[key] = rest
        self._save()

    def _flush(self, nick: str, peer: Peer, q: _Queued, res: Result) -> _Queued | None:
        """A queued message to the devices now ready for it; what is left of
        it, for the devices that still are not, or None."""
        ready, lacking = self._split(self._books.get(peer.master), q.want, q.done)
        done = q.done | self._encrypt(nick, peer, q.msg, ready, res) if ready else q.done
        return replace(q, done=done) if lacking else None

    def _open_sessions(self, nick: str, book: Book, entries: list[dict], res: Result) -> int:
        """A session to each usable entry of a KEYS (trust rule 4 and a good
        one-time key signature) whose device has no working session; the
        other one-time keys stay unused. Returns how many it opened."""
        opened = 0
        for e in entries:
            ident, otk = e["id"], e["otk"]
            reason = self._refusal(book, ident, cert=None, proving=False)
            if reason is None and not sig_ok(ident["ed25519"], OTK_SIG_PREFIX + otk["key"],
                                             otk["sig"]):
                reason = "bad-otk-signature"
            if reason is not None:
                res.events.append(Dropped(nick, reason, "KEYS"))
                continue
            d = book.device(ident["ed25519"])
            if d is not None and self._ready(book, d):
                continue
            try:
                session = self._account.create_outbound_session(
                    vz.Curve25519PublicKey.from_base64(ident["curve25519"]),
                    vz.Curve25519PublicKey.from_base64(otk["key"]))
            except ValueError:
                res.events.append(Dropped(nick, "bad-one-time-key", "KEYS"))
                continue
            self._bind_device(book, ident, proven=False, cert=None)
            self._add_session(ident["curve25519"], session)
            self._rekeying.discard(ident["ed25519"])
            opened += 1
        return opened

    def _on_pkmsg(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        ident = payload["id"]
        if not isinstance(ident, dict) or not is_key(ident.get("ed25519")):
            res.events.append(Dropped(nick, "malformed-id", "PKMSG"))
            return
        if did(ident["ed25519"]) != msg.src:
            res.events.append(Dropped(nick, "from-mismatch", "PKMSG"))
            return
        try:
            master, cert = parse_master_ref(payload["master"])
        except InvalidBlock:
            res.events.append(Dropped(nick, "invalid-master", "PKMSG"))
            return
        body = self._own_body(nick, msg, payload, res)
        if body is None:
            return
        peer = self._master_peer(nick, ident, master, cert, res)
        if peer is None:
            return
        book = self._book(master)
        reason = self._refusal(book, ident, cert=cert, proving=True)
        if reason is not None:
            res.events.append(Dropped(nick, reason, "PKMSG"))
            return
        ed, curve = ident["ed25519"], ident["curve25519"]
        any_msg = vz.AnyOlmMessage.from_parts(0, unb64(body))
        pre = any_msg.to_pre_key()
        d = book.device(ed)     # bound to this very curve, if at all (_refusal)
        for s in self._sessions.get(curve, []) if d is not None else []:
            if s.session_matches(pre):
                return self._decrypted(nick, peer, d, msg, s, any_msg, res)
        sid = pre.session_id()
        if sid in self._seen:
            # Either a replay (a fallback-key PKMSG opens the same session
            # again and would re-deliver an old plaintext), or a peer still
            # sending on a session we lost. Never decrypt; NACK, so the
            # second case recovers. A replayer only gets a NACK back for a
            # msgid that is not its own.
            res.events.append(Replayed(nick, sid))
            return self._undecryptable(nick, msg, "replayed-session", peer, res)
        try:
            session, plaintext = self._account.create_inbound_session(
                vz.Curve25519PublicKey.from_base64(curve), pre)
        except vz.SessionCreationException as e:
            return self._undecryptable(nick, msg, f"session-creation:{e}", peer, res)
        self._seen[sid] = None
        while len(self._seen) > SEEN_SESSIONS_MAX:
            self._seen.popitem(last=False)
        inner = self._inner(nick, plaintext, ed, res)
        if inner is None:
            # Not bound to this device and us (or unreadable): the session is
            # discarded, and its id stays seen.
            self._save()
            return
        d = self._bind_device(book, ident, proven=True, cert=cert)
        self._add_session(curve, session)
        self._heard(peer, book, d, nick)
        self._save()
        self._deliver(nick, peer, d, inner, res)

    def _on_msg(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        body = self._own_body(nick, msg, payload, res)
        if body is None:
            return
        ck = canonical_curve25519(payload["ck"])
        owner = self._curve_owner(ck)
        if owner is None:
            mapped = self.pinned(nick)
            if mapped is None:
                res.events.append(Dropped(nick, "unpinned-key", "MSG"))
                return
            # A pinned nick whose device we never saw a session for (our state
            # was lost?): a NACK makes it open a fresh one, with its id block.
            return self._undecryptable(nick, msg, "no-session", mapped, res)
        book, d = owner
        if book.revoked(d.ed25519):
            # Not an attack: dropped without a NACK and without an alarm.
            res.events.append(Dropped(nick, "revoked-device", "MSG"))
            return
        if did(d.ed25519) != msg.src:
            res.events.append(Dropped(nick, "from-mismatch", "MSG"))
            return
        peer = self._peers[book.master]
        if not self._sessions.get(ck):
            return self._undecryptable(nick, msg, "no-session", peer, res)
        # Nothing about the peer moves before a decrypt succeeds: `ck` is
        # public, and anyone can put it on a line.
        any_msg = vz.AnyOlmMessage.from_parts(1, unb64(body))
        for s in list(self._sessions[ck]):
            try:
                return self._decrypted(nick, peer, d, msg, s, any_msg, res)
            except vz.OlmDecryptionException:
                continue
        self._undecryptable(nick, msg, "decryption-failed", peer, res)

    def _own_body(self, nick: str, msg: Assembled, payload: dict, res: Result) -> str | None:
        """This device's body of a PKMSG or MSG. A message to one device goes
        `to` its did, to several `to` `*`."""
        bodies = payload["bodies"]
        if not isinstance(bodies, dict) or not 1 <= len(bodies) <= MAX_DEVICES \
                or (msg.dst == framing.ANY) != (len(bodies) > 1):
            res.events.append(Dropped(nick, "malformed-bodies", msg.verb))
            return None
        body = bodies.get(self._did)
        if not isinstance(body, str):
            res.events.append(Dropped(nick, "not-for-this-device", msg.verb))
            return None
        return body

    def _decrypted(self, nick: str, peer: Peer, d: Device, msg: Assembled,
                   session: vz.Session, any_msg: vz.AnyOlmMessage, res: Result) -> None:
        try:
            plaintext = session.decrypt(any_msg)
        except vz.OlmDecryptionException:
            if msg.verb == "PKMSG":
                return self._undecryptable(nick, msg, "decryption-failed", peer, res)
            raise
        # The session the peer just used is the one to answer on.
        lst = self._sessions[d.curve25519]
        lst.remove(session)
        lst.insert(0, session)
        self._heard(peer, self._books[peer.master], d, nick)
        self._save()
        inner = self._inner(nick, plaintext, d.ed25519 if msg.verb == "PKMSG" else None, res)
        if inner is not None:
            self._deliver(nick, peer, d, inner, res)

    def _inner(self, nick: str, plaintext: bytes, sender: str | None,
               res: Result) -> dict | None:
        """The inner message, without the fields the engine reads itself. In a
        pre-key body (`sender` given) `fb` must bind the sender's device key
        and ours, else it is `inner-key-mismatch`: a message built for
        another device, or claimed by another one."""
        try:
            inner = framing.loads(plaintext.decode())
        except (UnicodeDecodeError, ValueError, RecursionError):
            res.events.append(Dropped(nick, "undecodable-inner"))
            return None
        if not isinstance(inner, dict) or not isinstance(inner.get("t"), str):
            res.events.append(Dropped(nick, "inner-without-type"))
            return None
        fb = inner.pop("fb", None)
        if sender is not None and fb != binding(sender, self._device_key):
            res.events.append(Dropped(nick, "inner-key-mismatch"))
            return None
        return inner

    def _deliver(self, nick: str, peer: Peer, d: Device, inner: dict, res: Result) -> None:
        peer = self._peers[peer.master]
        lv = wire_int(inner.pop("lv", None))
        if inner["t"] == "ack":
            self._on_ack(nick, peer, inner, res)
        elif inner["t"] == "list":
            self._on_list(nick, peer, inner, res)
        elif inner["t"] == "listreq":
            self._on_listreq(nick, peer, d, res)
        else:
            res.events.append(Received(nick, peer, d.ed25519, inner))
        if lv is not None and lv > self._books[peer.master].ver:
            self._maybe_listreq(nick, peer, d, lv, res)

    # --- device lists inside Olm ---------------------------------------------

    def _on_list(self, nick: str, peer: Peer, inner: dict, res: Result) -> None:
        """A `t:list` from one of the peer's devices: the KEYS steps 3 to 5,
        so another master is the alarm here too."""
        try:
            lst = parse_master(inner.get("master"))
        except InvalidBlock:
            res.events.append(Dropped(nick, "invalid-list"))
            return
        if lst.master != peer.master:
            res.events.append(KeyAlarm(nick, peer.master, lst.master))
            res.events.append(Dropped(nick, "wrong-master"))
            return
        book = self._books[peer.master]
        self._revoke(book, book.apply(lst)[1])
        self._save()

    def _on_listreq(self, nick: str, peer: Peer, d: Device, res: Result) -> None:
        """Our list, to the device that asked: once per (nick, device) a
        minute, any other ask in that minute dropped."""
        now, ask = self._now(), (fold(nick), d.ed25519)
        self._listed_at = {k: t for k, t in self._listed_at.items()
                           if now - t < LISTREQ_INTERVAL}
        if ask in self._listed_at:
            res.events.append(Dropped(nick, "listreq-rate-limited"))
            return
        self._listed_at[ask] = now
        self._send_reactive(nick, peer, d, {"t": "list", "master": self._own_block}, res)

    def _maybe_listreq(self, nick: str, peer: Peer, d: Device, lv: int, res: Result) -> None:
        """The device holds a newer list than ours (its `lv`): ask it, once
        per (nick, lv) and once per nick a minute. An lv asked for is
        remembered until we store a list as new: never a high-water mark,
        or one device announcing a huge lv silences every other."""
        key, now = fold(nick), self._now()
        ver, last = self._books[peer.master].ver, self._listreq_at.get(key)
        asked = self._listreq_lv[key] = {v for v in self._listreq_lv.get(key, ()) if v > ver}
        if lv in asked or (last is not None and now - last < LISTREQ_INTERVAL):
            return
        asked.add(lv)
        self._listreq_at[key] = now
        self._send_reactive(nick, peer, d, {"t": "listreq"}, res)

    def _send_reactive(self, nick: str, peer: Peer, d: Device, inner: dict,
                       res: Result) -> None:
        """An inner message of the engine's own to one device, on the
        REACTIVE lane: sent if that device is ready for it, else not at all."""
        msg = _Outgoing(encode_inner(inner | {"lv": self._ver}), False, 1, None, True)
        self._send_to(nick, peer, msg, res, want=frozenset({d.ed25519}))

    def _on_nack(self, nick: str, msg: Assembled, payload: dict, res: Result) -> None:
        self._trim_sent()
        ref = payload["ref"]
        sent = self._sent.get(ref) if isinstance(ref, str) else None
        body = sent.bodies.pop(msg.src, None) if sent else None
        if body is None:
            # Only a device we really sent `ref` to may NACK it.
            res.events.append(Dropped(nick, "unknown-nack-ref", "NACK"))
            return
        if not sent.bodies:
            del self._sent[ref]
        ed, session_id = body
        if fold(sent.nick) != fold(nick):
            # NACKs are not authenticated: never re-send on the word of a
            # nick we did not send to. The recipient renamed, most likely.
            self._lost(sent.nick, "nack-from-another-nick", [sent.msg], res)
            return
        peer = self._peers.get(sent.master)
        if peer is None:
            self._lost(nick, "unpinned-key", [sent.msg], res)
            return
        if not self._reached_at(nick, peer):
            self._lost(nick, "repinned", [sent.msg], res)
            return
        book = self._books[peer.master]
        d = book.device(ed)
        if d is None or book.revoked(ed):
            res.events.append(Dropped(nick, "revoked-device", "NACK"))
            return
        if sent.msg.sends >= MAX_SENDS:
            self._lost(nick, "resend-failed", [sent.msg], res)
            return
        again, only, key = replace(sent.msg, sends=sent.msg.sends + 1), frozenset({ed}), fold(nick)
        lst = self._sessions.get(d.curve25519) or []
        if lst and lst[0].session_id != session_id:
            # The failed session is not our newest: re-send on the newest.
            self._drop_session(d.curve25519, session_id)
            return self._send_to(nick, peer, again, res, want=only)
        if key not in self._keyreq_out and key not in self._rekey_due:
            # The failed session is our newest: only a new one helps, and the
            # spec allows one re-key per nick per minute, however many of its
            # devices NACKed: a NACK while one is under way joins it. Its
            # KEYREQ keeps to the one budget, one per nick per 30 s: it goes
            # now, or when tick() finds it due.
            last = self._rekey_at.get(key)
            if last is not None and self._now() - last < REKEY_INTERVAL:
                self._lost(nick, "rekey-throttled", [sent.msg], res)
                return
            res.events.append(Rekeying(nick, peer, ed))
            self._rekey_at[key], self._rekey_due[key] = self._now(), nick
        self._drop_session(d.curve25519, session_id)
        self._rekeying.add(ed)
        # Re-send the lost message on the new session (the spec's MAY), to
        # that device only: the application's waits for the keys. A CHAL
        # cannot go on a new session (O1), and a listreq or a t:list is asked
        # again: the keys are asked for all the same.
        self._send_to(nick, peer, again, res, want=only)
        if not again.written:
            self._maybe_keyreq(nick, res)

    def _undecryptable(self, nick: str, msg: Assembled, reason: str, peer: Peer,
                       res: Result) -> None:
        """Report it, and NACK, from this device to the one the line came
        from, when `nick` is where `peer`, the master the line claims, is
        reached: a device's curve and id block are public, and anyone can put
        them on a line. Every such message gets its own NACK, one line out per
        message in: the sender re-sends what is NACKed, and a message without
        a NACK is lost without a word."""
        res.events.append(Undecryptable(nick, msg.msgid, reason))
        if self._reached_at(nick, peer):
            self._emit(nick, "NACK", {"v": WIRE_VERSION, "ref": msg.msgid}, res, to=msg.src,
                       urgent=True)

    def _reached_at(self, nick: str, peer: Peer) -> bool:
        """Whether sending to `nick` reaches `peer`'s master."""
        mapped = self.pinned(nick)
        return mapped is not None and mapped.master == peer.master

    # --- order challenges ---------------------------------------------------

    def challenge(self, nick: str, *, network: str, channel: str, sender_mask: str,
                  line: bytes) -> tuple[Challenge, Result]:
        """Send a CHAL for `line` to the master pinned to `nick`.
        `network` is the 005 NETWORK token; `line` the raw PRIVMSG text."""
        with self._lock:
            peer = self.pinned(nick)
            if peer is None:
                raise NotPinnedError(f"no key pinned to {nick!r}")
            ch = new_challenge(nick=nick, master=peer.master, network=network, channel=channel,
                               sender_mask=sender_mask, line=line, now=self._now())
            self._challenges.add(ch)
            return ch, self._send_inner(nick, ch.inner(), expires=ch.expires_at)

    def _on_ack(self, nick: str, peer: Peer, inner: dict, res: Result) -> None:
        ch, reason = self._challenges.check(str(inner.get("nonce")), peer.master, self._now())
        res.events.append(AckOk(nick, peer, ch) if ch else AckRejected(nick, peer, reason))

    # --- time --------------------------------------------------------------------

    def tick(self) -> Result:
        """Expire unanswered challenges and queued messages that waited too
        long for keys, send the KEYREQ of a re-key once the budget allows,
        forget old plaintexts, rotate the fallback key when it is due. Call
        about once a second."""
        with self._lock:
            res = Result()
            now = self._now()
            for ch in self._challenges.expire(now):
                res.events.append(ChallengeExpired(ch))
            for key in list(self._outq):
                self._live_queue(key, res)
            for key, nick in list(self._rekey_due.items()):
                if self.pinned(nick) is None:
                    del self._rekey_due[key]
                else:
                    self._maybe_keyreq(nick, res)
            self._trim_sent()
            if now - self._fallback["at"] >= FALLBACK_ROTATE:
                self._new_fallback_key()
                self._save()
            return res

    # --- identities and pins -------------------------------------------------

    def _master_peer(self, nick: str, ident: dict, master: str, cert: str,
                     res: Result) -> Peer | None:
        """The pinned peer a PKMSG's master names, under any nick. Otherwise
        None: ignored, never answered, and a KeyAlarm when `nick` is pinned
        to another master and the id block and certificate verify under the
        one presented. Junk next to a master key is anyone's to type, and an
        alarm for it would cry wolf."""
        peer = self._peers.get(master)
        if peer is not None:
            return peer
        pinned = self._pins.get(fold(nick))
        if pinned and id_ok(ident, master) and cert_ok(master, ident["ed25519"], cert):
            res.events.append(KeyAlarm(nick, pinned, master))
        res.events.append(Dropped(nick, "unpinned-key", "PKMSG"))
        return None

    def _book(self, master: str) -> Book:
        book = self._books.get(master)
        if book is None:
            book = self._books[master] = Book.empty(master)
        return book

    def _revoke(self, book: Book, revoked: set[str]) -> None:
        """A revoked device's sessions go, and nothing is encrypted to it
        again (trust rule 5)."""
        for ed in revoked:
            d = book.device(ed)
            if d is not None:
                self._sessions.pop(d.curve25519, None)
            self._rekeying.discard(ed)

    def _refusal(self, book: Book, ident: dict, *, cert: str | None,
                 proving: bool) -> str | None:
        """Why an id block's device may not be bound under `book`'s master
        (Book.refusal), or None. And v1's curve rules on top.

        An id block is public and replayable, and its signature only says the
        device key CLAIMS that curve, not that it holds it. So a curve is
        stored (_bind_device) only once a session exists. A session we opened
        on keys we asked for proves nothing, and neither does a message on it.
        Only a pre-key message the curve's holder built to us does:
        `proving` may take the curve from a device that only claimed it."""
        reason = book.refusal(ident, cert=cert)
        if reason is not None:
            return reason
        curve = ident["curve25519"]
        if curve == self._id_block["curve25519"]:
            # Else a pinned device could claim our curve, hand us our own
            # fallback key as its one-time key, and reflect our own messages
            # back to us as its own. (Our own key cannot sign another curve.)
            return "own-identity"
        owner = self._curve_owner(curve)
        if owner is not None and owner[1].ed25519 != ident["ed25519"] \
                and (owner[1].proven or not proving):
            # One curve under two devices would let one's messages be read
            # as the other's (sessions and MSG lookups go by curve).
            return "curve-already-bound"
        return None

    def _curve_owner(self, curve: str) -> tuple[Book, Device] | None:
        for book in self._books.values():
            d = book.bound(curve)
            if d is not None:
                return book, d
        return None

    def _bind_device(self, book: Book, ident: dict, *, proven: bool,
                     cert: str | None) -> Device:
        """Store the curve a session was opened on; `proven` when a pre-key
        message decrypted on it. A proof evicts another device's claim on
        that curve, sessions included (_refusal let it through only if
        unproven)."""
        curve = ident["curve25519"]
        owner = self._curve_owner(curve)
        if owner is not None and owner[1].ed25519 != ident["ed25519"]:
            owner[0].unbind(owner[1].ed25519)
            self._sessions.pop(curve, None)
        return book.bind(ident, proven=proven, cert=cert)

    def _heard(self, peer: Peer, book: Book, d: Device, nick: str) -> None:
        """A message from `d` decrypted: it gets the next first copy, and the
        nick hint follows its master. A hint names one master: any other
        master last heard from there is back at its configured nick."""
        book.heard(d.ed25519, self._now())
        for master, p in list(self._peers.items()):
            if master != peer.master and fold(p.nick) == fold(nick):
                self._peers[master] = replace(
                    p, nick=next(n for n, m in self._pins.items() if m == master))
        self._peers[peer.master] = replace(self._peers[peer.master], nick=nick)

    # --- crypto helpers ------------------------------------------------------

    def _own_blocks(self) -> None:
        """What we sign once: the id block, our list and our certificate."""
        self._device_key = self._account.ed25519_key.to_base64()
        self._master_key = self._master.ed25519_key.to_base64()
        self._did = did(self._device_key)
        self._id_block = id_block(self._account, self._master_key)
        self._own_block = sign_master(self._master, self._ver, [self._device_key])
        self._cert = sign_cert(self._master, self._device_key)

    def _sign(self, text: str) -> str:
        return self._account.sign(text.encode()).to_base64()

    def _new_fallback_key(self) -> None:
        self._account.generate_fallback_key()
        (fb,) = self._account.fallback_key.values()
        self._account.mark_keys_as_published()
        key = fb.to_base64()
        self._fallback = {"key": key, "sig": self._sign(OTK_SIG_PREFIX + key), "at": self._now()}

    def _drop_session(self, curve: str, session_id: str) -> None:
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
            "identity": {"master": self._master_key, "ed25519": self._device_key,
                         "curve25519": self._id_block["curve25519"]},
            "account": self._account.pickle(self._key),
            "master": self._master.pickle(self._key),
            "ver": self._ver,
            "fallback": self._fallback,
            "peers": {master: p.nick for master, p in self._peers.items()},
            "books": {master: b.to_doc() for master, b in self._books.items()},
            "sessions": {c: [s.pickle(self._key) for s in lst] for c, lst in self._sessions.items()},
            "seen_sessions": list(self._seen),
        })

    def _load(self, doc: dict) -> None:
        if doc.get("v") != STATE_VERSION:
            raise StateMismatchError(
                f"{self.state_path}: state version {doc.get('v')!r}, expected {STATE_VERSION}"
                " (wire v2 is a new identity: move the file away, and re-pin)")
        if doc.get("network") != self.network:
            raise StateMismatchError(
                f"{self.state_path} belongs to network {doc.get('network')!r}, not {self.network!r}")
        self._account = vz.Account.from_pickle(doc["account"], self._key)
        self._master = vz.Account.from_pickle(doc["master"], self._key)
        self._ver = doc["ver"]
        self._fallback = doc["fallback"]
        self._peers = {master: Peer(master, nick) for master, nick in doc["peers"].items()}
        self._books = {master: Book.from_doc(b) for master, b in doc["books"].items()}
        self._sessions = {c: [vz.Session.from_pickle(s, self._key) for s in lst]
                          for c, lst in doc["sessions"].items()}
        self._seen = OrderedDict((sid, None) for sid in doc["seen_sessions"])
