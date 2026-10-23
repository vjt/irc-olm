"""A user's devices under one master key (wire v2, grappa-irc#2430).

A user holds one master Ed25519 key per network, and the master signs the
list of the user's device keys: 1 to 4 of them, with a version `ver` that
only ever grows. Each device signs its master in its id block, so no other
master can list it. The pin is on the master. A device is trusted through
the list (KEYS, `t:list`), or through its certificate, which a pre-key
message carries instead of the list (wire v2 revision 2, grappa-irc#2430,
6346686730): the master's signature over the device's key and `N`, the
version of the first list that held it. The certificate and the id block
verify, the key was never revoked here, and the stored list is older than
`N`: a list at `N` or newer is the master's own word on the device, and an
unlisted device is one it no longer holds.

A `did` (device id) only addresses a line: nothing is trusted because of one.
It is computed from a key already checked, never taken from the wire.

`Book` is what a receiver keeps per master: the stored list (trust rule 3),
every key it ever listed, in a list it accepted or in the one a
certificate names once the stored list reaches it (so a revoked key is one
listed once and not now, rule 5), and the curve of each device a session
was bound to, with the version of its certificate if one was seen.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from enum import Enum

import vodozemac as vz

from .keys import SIG_LEN, b64, b64url, is_curve, is_key, sig_ok, unb64

MAX_DEVICES = 4              # on the wire: raising it is a new protocol version
VER_MAX = 2**31 - 1
LIST_SIG_PREFIX = "irc-e2e:v2:list:"
ID_SIG_PREFIX = "irc-e2e:v2:id:"
CERT_SIG_PREFIX = "irc-e2e:v2:dev:"
BIND_PREFIX = "irc-e2e:v2:bind:"


class InvalidBlock(ValueError):
    """A master block, or a KEYS payload, that breaks the wire's rules."""


def did(ed25519: str) -> str:
    """The first 8 bytes of SHA-256 over the raw key: 11 base64url characters
    (the amendment 6348464388), since grappa routes a did in a URL path."""
    return b64url(hashlib.sha256(unb64(ed25519)).digest()[:8])


def wire_int(value: object) -> int | None:
    """A `ver` or an `lv`: an integer value in 1..2^31-1, else None. A JSON
    number counts by its value, so 1.0 is 1; a bool is not a number here,
    although Python's bool is an int."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float):
        if not value.is_integer():          # NaN and the infinities included
            return None
        value = int(value)
    if isinstance(value, int) and 1 <= value <= VER_MAX:
        return value
    return None


def list_text(ver: int, devices: list[str] | tuple[str, ...]) -> str:
    return f"{LIST_SIG_PREFIX}{ver}:" + ",".join(devices)


def id_text(curve25519: str, master: str) -> str:
    return f"{ID_SIG_PREFIX}{curve25519}:{master}"


def cert_text(ver: int, ed25519: str) -> str:
    return f"{CERT_SIG_PREFIX}{ver}:{ed25519}"


@dataclass(frozen=True)
class Cert:
    """A device certificate: the version of the first list that held the
    device, and the master's signature over it and the device's key."""
    ver: int
    sig: str


def sign_cert(master: vz.Account, ver: int, ed25519: str) -> Cert:
    """The master's certificate for one of its devices, made once at pairing:
    `ver` is that of the list the pairing signs. Raises ValueError on a
    version the wire would refuse."""
    if type(ver) is not int or wire_int(ver) is None:
        raise ValueError("ver is an integer in 1..2^31-1")
    return Cert(ver, master.sign(cert_text(ver, ed25519).encode()).to_base64())


def cert_ok(master: str, ed25519: str, cert: Cert) -> bool:
    return sig_ok(master, cert_text(cert.ver, ed25519), cert.sig)


def binding(sender: str, recipient: str) -> str:
    """The fk/tk binding (`fb`) of an inner message sent in a pre-key body:
    16 bytes of SHA-256 over both device keys, sender first, 22 characters.
    128 bits cannot be found by search, so it binds as the two full keys did."""
    return b64(hashlib.sha256(f"{BIND_PREFIX}{sender}:{recipient}".encode()).digest()[:16])


@dataclass(frozen=True)
class DeviceList:
    """A master block whose signature verified."""
    master: str
    ver: int
    devices: tuple[str, ...]


def _check_devices(devices: object) -> None:
    if not isinstance(devices, list) or not 1 <= len(devices) <= MAX_DEVICES:
        raise InvalidBlock(f"a list holds 1 to {MAX_DEVICES} devices")
    if not all(is_key(k) for k in devices):
        raise InvalidBlock("a device key is not a key")
    if any(a >= b for a, b in zip(devices, devices[1:])):
        raise InvalidBlock("devices are not strictly ascending")
    if len({did(k) for k in devices}) != len(devices):
        raise InvalidBlock("two devices share a did")


def parse_master(block: object) -> DeviceList:
    """The list a master block carries, or InvalidBlock."""
    if not isinstance(block, dict):
        raise InvalidBlock("the master block is not an object")
    master, lst = block.get("ed25519"), block.get("list")
    if not is_key(master):
        raise InvalidBlock("the master is not a key")
    if not isinstance(lst, dict):
        raise InvalidBlock("the list is not an object")
    ver = wire_int(lst.get("ver"))
    if ver is None:
        raise InvalidBlock("ver is not an integer in range")
    devices = lst.get("devices")
    _check_devices(devices)
    if not sig_ok(master, list_text(ver, devices), block.get("sig")):
        raise InvalidBlock("the list signature does not verify")
    return DeviceList(master, ver, tuple(devices))


def parse_master_ref(block: object) -> tuple[str, Cert]:
    """A pre-key message's master block, `{"ed25519": M, "ver": N, "cert": C}`:
    the master and the sender's certificate, shaped but not yet verified (the
    caller holds the pin and the sender's key), or InvalidBlock."""
    if not isinstance(block, dict):
        raise InvalidBlock("the master block is not an object")
    master, cert = block.get("ed25519"), block.get("cert")
    if not is_key(master):
        raise InvalidBlock("the master is not a key")
    ver = wire_int(block.get("ver"))
    if ver is None:
        raise InvalidBlock("the certificate's ver is not an integer in range")
    if not isinstance(cert, str) or len(cert) != SIG_LEN:
        raise InvalidBlock("the certificate is not a signature")
    return master, Cert(ver, cert)


def sign_master(master: vz.Account, ver: int, devices: list[str]) -> dict:
    """The master block for our own list. Raises ValueError on a list the
    wire would refuse."""
    devices = sorted(devices)
    if type(ver) is not int or wire_int(ver) is None:
        raise ValueError("ver is an integer in 1..2^31-1")
    _check_devices(devices)
    return {"ed25519": master.ed25519_key.to_base64(),
            "list": {"ver": ver, "devices": devices},
            "sig": master.sign(list_text(ver, devices).encode()).to_base64()}


def id_block(device: vz.Account, master: str) -> dict:
    """A device's id block: its keys, and its signature over its curve and
    its master."""
    curve = device.curve25519_key.to_base64()
    return {"curve25519": curve, "ed25519": device.ed25519_key.to_base64(),
            "sig": device.sign(id_text(curve, master).encode()).to_base64()}


def id_ok(block: object, master: str) -> bool:
    """Whether an id block's device vouches for its curve under `master`."""
    if not isinstance(block, dict):
        return False
    ed, curve = block.get("ed25519"), block.get("curve25519")
    return is_key(ed) and is_curve(curve) and sig_ok(ed, id_text(curve, master), block.get("sig"))


def parse_keys(payload: dict) -> tuple[DeviceList, list[dict]]:
    """A KEYS payload's list and its entries, the first one per device key,
    or InvalidBlock. An entry is only shaped here: its signatures are the
    caller's to check, and an entry that fails them is skipped, not the
    KEYS."""
    entries = payload.get("devices")
    if not isinstance(entries, list) or len(entries) > MAX_DEVICES:
        raise InvalidBlock(f"KEYS hold at most {MAX_DEVICES} entries")
    seen: set[str] = set()
    first: list[dict] = []
    for e in entries:
        ident = e.get("id") if isinstance(e, dict) else None
        otk = e.get("otk") if isinstance(e, dict) else None
        if not (isinstance(ident, dict) and isinstance(otk, dict)
                and all(isinstance(ident.get(f), str) for f in ("curve25519", "ed25519", "sig"))
                and all(isinstance(otk.get(f), str) for f in ("key", "sig"))):
            raise InvalidBlock("a KEYS entry is malformed")
        if ident["ed25519"] not in seen:
            seen.add(ident["ed25519"])
            first.append(e)
    return parse_master(payload.get("master")), first


# --- the receiver's record of one master -------------------------------------

class Change(Enum):
    REPLACED = "replaced"    # a higher ver: the stored list is now this one
    SAME = "same"            # the same ver and keys
    CONFLICT = "conflict"    # the same ver, other keys: only the master made it; ignored
    STALE = "stale"          # a lower ver: ignored


@dataclass(frozen=True)
class Device:
    """A device whose id block verified under its master, listed or
    certified: the curve a session was bound to, whether a pre-key message
    proved it, the version of the certificate it was first bound on (None:
    it was bound listed), and when we last heard from it."""
    ed25519: str
    curve25519: str
    proven: bool
    cert_ver: int | None
    heard_at: float | None = None


class Book:
    def __init__(self, master: str, ver: int, listed: frozenset[str], ever: frozenset[str],
                 devices: dict[str, Device]):
        self.master = master
        self.ver = ver
        self._listed = listed
        self._ever = ever
        self._devices = devices

    @classmethod
    def first(cls, lst: DeviceList) -> "Book":
        keys = frozenset(lst.devices)
        return cls(lst.master, lst.ver, keys, keys, {})

    @classmethod
    def empty(cls, master: str) -> "Book":
        """A master whose list we have not seen yet: a pre-key message, which
        carries a certificate and no list, came first. `ver` 0 is below any
        list, so the first one replaces it."""
        return cls(master, 0, frozenset(), frozenset(), {})

    def apply(self, lst: DeviceList) -> tuple[Change, set[str]]:
        """Trust rule 3: the change, and the keys it revoked: the listed ones
        it drops, and the certified ones whose version it reaches without
        listing them."""
        if lst.master != self.master:
            raise ValueError("a list for another master")
        new = frozenset(lst.devices)
        if lst.ver < self.ver:
            return Change.STALE, set()
        if lst.ver == self.ver:
            return (Change.SAME if new == self._listed else Change.CONFLICT), set()
        before = {ed for ed in self._listed | self._devices.keys() if not self.revoked(ed)}
        # A certificate is its master's word that list N held the device, so
        # a list at N or newer has listed it as surely as one we saw.
        passed = {ed for ed, d in self._devices.items()
                  if d.cert_ver is not None and d.cert_ver <= lst.ver}
        self.ver, self._listed, self._ever = lst.ver, new, self._ever | new | passed
        return Change.REPLACED, {ed for ed in before if self.revoked(ed)}

    def listed(self, ed25519: str) -> bool:
        return ed25519 in self._listed

    def revoked(self, ed25519: str) -> bool:
        """Listed once and not now (rule 5): by a list we accepted, or by the
        one its certificate names, once the stored list has reached it."""
        return ed25519 in self._ever and ed25519 not in self._listed

    def refusal(self, ident: dict, *, cert: Cert | None) -> str | None:
        """Why a device may not be bound under this master, or None: its id
        block must verify under it, it must never have been revoked here, and
        it must be listed, or (a pre-key message's `cert`, the KEYS path has
        none) certified by `cert` for a version the stored list has not
        reached; with the curve already bound to it if any."""
        if not id_ok(ident, self.master):
            return "bad-identity-signature"
        ed, curve = ident["ed25519"], ident["curve25519"]
        if self.revoked(ed):
            return "revoked-device"
        if cert is not None and not cert_ok(self.master, ed, cert):
            return "bad-certificate"
        if not self.listed(ed):
            if cert is None:
                return "unlisted-device"
            if cert.ver <= self.ver:
                return "stale-certificate"
        cur = self._devices.get(ed)
        if cur is not None and cur.curve25519 != curve:
            return "identity-curve-mismatch"
        return None

    def bind(self, ident: dict, *, proven: bool, cert: Cert | None) -> Device:
        """Record the curve of a device `refusal` lets through, else
        ValueError with its reason. A proof, once recorded, stays, and so
        does the certificate the device was first bound on: a device bound
        listed has no use for one, since a list that drops it revokes it."""
        reason = self.refusal(ident, cert=cert)
        if reason is not None:
            raise ValueError(reason)
        ed, curve = ident["ed25519"], ident["curve25519"]
        cur = self._devices.get(ed)
        if cur is None:
            cur = Device(ed, curve, proven, cert.ver if cert is not None else None)
        else:
            cur = replace(cur, proven=cur.proven or proven)
        self._devices[ed] = cur
        return cur

    def unbind(self, ed25519: str) -> None:
        """Forget a device's curve: another key proved it holds it."""
        self._devices.pop(ed25519, None)

    def forget_devices(self) -> None:
        """Forget every curve, keeping the list, its version and what it
        revoked: the master is no longer pinned, and a re-pin must not roll
        its list back (trust rule 3)."""
        self._devices.clear()

    def _trusted(self, d: Device) -> bool:
        return not self.revoked(d.ed25519) and (d.cert_ver is not None or self.listed(d.ed25519))

    def device(self, ed25519: str) -> Device | None:
        return self._devices.get(ed25519)

    def wanted(self) -> frozenset[str]:
        """Every device a message to this master is for: the listed ones,
        with a curve or not yet, and the certified ones not revoked."""
        return self._listed | {d.ed25519 for d in self._devices.values() if self._trusted(d)}

    def bound(self, curve25519: str) -> Device | None:
        """The device this curve is bound to, trusted or not."""
        return next((d for d in self._devices.values() if d.curve25519 == curve25519), None)

    def heard(self, ed25519: str, at: float) -> None:
        cur = self._devices.get(ed25519)
        if cur is not None:
            self._devices[ed25519] = replace(cur, heard_at=at)

    def targets(self) -> list[Device]:
        """The trusted devices with a curve, the most recently heard first:
        the person typing gets the first copy. Never heard: in key order."""
        live = [d for d in self._devices.values() if self._trusted(d)]
        return sorted(live, key=lambda d: (d.heard_at is None, -(d.heard_at or 0.0), d.ed25519))

    def to_doc(self) -> dict:
        return {"master": self.master, "ver": self.ver,
                "listed": sorted(self._listed), "ever": sorted(self._ever),
                "devices": {ed: {"curve25519": d.curve25519, "proven": d.proven,
                                 "cert_ver": d.cert_ver, "heard_at": d.heard_at}
                            for ed, d in self._devices.items()}}

    @classmethod
    def from_doc(cls, doc: dict) -> "Book":
        return cls(doc["master"], doc["ver"], frozenset(doc["listed"]), frozenset(doc["ever"]),
                   {ed: Device(ed, d["curve25519"], d["proven"], d["cert_ver"], d["heard_at"])
                    for ed, d in doc["devices"].items()})
