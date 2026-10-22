"""A user's devices under one master key (wire v2, grappa-irc#2430).

A user holds one master Ed25519 key per network, and the master signs the
list of the user's device keys: 1 to 4 of them, with a version `ver` that
only ever grows. Each device signs its master in its id block, so no other
master can list it. The pin is on the master. A device is trusted through
the list (KEYS, `t:list`), or through its certificate, the master's
signature over its key, which a pre-key message carries instead of the list
(wire v2 revision 2, grappa-irc#2430, 6346686730): the certificate and the
id block verify and the key was never revoked here.

A `did` (device id) only addresses a line: nothing is trusted because of one.
It is computed from a key already checked, never taken from the wire.

`Book` is what a receiver keeps per master: the stored list (trust rule 3),
every key it ever listed (so a revoked key is one listed once and not now,
rule 5), and the curve of each device a session was bound to.
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


def cert_text(ed25519: str) -> str:
    return f"{CERT_SIG_PREFIX}{ed25519}"


def sign_cert(master: vz.Account, ed25519: str) -> str:
    """The master's certificate for one of its devices, made once at pairing."""
    return master.sign(cert_text(ed25519).encode()).to_base64()


def cert_ok(master: str, ed25519: str, cert: object) -> bool:
    return sig_ok(master, cert_text(ed25519), cert)


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


def parse_master_ref(block: object) -> tuple[str, str]:
    """A pre-key message's master block, `{"ed25519": M, "cert": C}`: the
    master and the sender's certificate, shaped but not yet verified (the
    caller holds the pin and the sender's key), or InvalidBlock."""
    if not isinstance(block, dict):
        raise InvalidBlock("the master block is not an object")
    master, cert = block.get("ed25519"), block.get("cert")
    if not is_key(master):
        raise InvalidBlock("the master is not a key")
    if not isinstance(cert, str) or len(cert) != SIG_LEN:
        raise InvalidBlock("the certificate is not a signature")
    return master, cert


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
    proved it, whether its master's certificate was seen, and when we last
    heard from it."""
    ed25519: str
    curve25519: str
    proven: bool
    certified: bool
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

    def apply(self, lst: DeviceList) -> tuple[Change, set[str]]:
        """Trust rule 3: the change, and the keys it revoked."""
        if lst.master != self.master:
            raise ValueError("a list for another master")
        new = frozenset(lst.devices)
        if lst.ver < self.ver:
            return Change.STALE, set()
        if lst.ver == self.ver:
            return (Change.SAME if new == self._listed else Change.CONFLICT), set()
        revoked = set(self._listed - new)
        self.ver, self._listed, self._ever = lst.ver, new, self._ever | new
        return Change.REPLACED, revoked

    def listed(self, ed25519: str) -> bool:
        return ed25519 in self._listed

    def revoked(self, ed25519: str) -> bool:
        return ed25519 in self._ever and ed25519 not in self._listed

    def bind(self, ident: dict, *, proven: bool, cert: str | None) -> Device:
        """Record the curve of a device whose id block verifies under this
        master and that is trusted: listed (`cert` None, the KEYS path), or
        certified by `cert` (a pre-key message's), and never revoked here.
        ValueError otherwise, and for a curve other than the one already
        bound. A proof, and a certificate, once recorded, stay."""
        if not id_ok(ident, self.master):
            raise ValueError("the id block does not verify under this master")
        ed, curve = ident["ed25519"], ident["curve25519"]
        if self.revoked(ed):
            raise ValueError("the device is revoked")
        if cert is not None and not cert_ok(self.master, ed, cert):
            raise ValueError("the certificate does not verify under this master")
        certified = cert is not None
        if not certified and not self.listed(ed):
            raise ValueError("the device is not listed")
        cur = self._devices.get(ed)
        if cur is None:
            cur = Device(ed, curve, proven, certified)
        elif cur.curve25519 != curve:
            raise ValueError("the device is bound to another curve")
        else:
            cur = replace(cur, proven=cur.proven or proven, certified=cur.certified or certified)
        self._devices[ed] = cur
        return cur

    def _trusted(self, d: Device) -> bool:
        return not self.revoked(d.ed25519) and (d.certified or self.listed(d.ed25519))

    def device(self, ed25519: str) -> Device | None:
        return self._devices.get(ed25519)

    def heard(self, ed25519: str, at: float) -> None:
        cur = self._devices.get(ed25519)
        if cur is not None:
            self._devices[ed25519] = replace(cur, heard_at=at)

    def targets(self) -> list[Device]:
        """The trusted devices with a curve, the most recently heard first:
        the person typing gets the first copy. Never heard: in key order."""
        live = [d for d in self._devices.values() if self._trusted(d)]
        return sorted(live, key=lambda d: (d.heard_at is None, -(d.heard_at or 0.0), d.ed25519))

    def device_for_curve(self, curve25519: str) -> Device | None:
        return next((d for d in self._devices.values()
                     if d.curve25519 == curve25519 and self._trusted(d)), None)

    def revoked_curve(self, curve25519: str) -> bool:
        return any(d.curve25519 == curve25519 and self.revoked(d.ed25519)
                   for d in self._devices.values())

    def to_doc(self) -> dict:
        return {"master": self.master, "ver": self.ver,
                "listed": sorted(self._listed), "ever": sorted(self._ever),
                "devices": {ed: {"curve25519": d.curve25519, "proven": d.proven,
                                 "certified": d.certified, "heard_at": d.heard_at}
                            for ed, d in self._devices.items()}}

    @classmethod
    def from_doc(cls, doc: dict) -> "Book":
        return cls(doc["master"], doc["ver"], frozenset(doc["listed"]), frozenset(doc["ever"]),
                   {ed: Device(ed, d["curve25519"], d["proven"], d["certified"], d["heard_at"])
                    for ed, d in doc["devices"].items()})
