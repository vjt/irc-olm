import pytest

from irc_olm import framing, store
from irc_olm.devices import MAX_DEVICES
from irc_olm.engine import Engine


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class Net:
    """In-memory IRC: delivers each engine's outbound lines to the target
    engine, as PRIVMSGs from the sender's nick, until the wire is quiet."""

    def __init__(self, tmp_path, clock):
        self.tmp_path = tmp_path
        self.clock = clock
        self.engines = {}
        self.events = {}
        self.wire = []          # every (sender, target, body) ever delivered
        self.drop = None        # predicate(sender, target, body) -> bool
        self.pins = {}          # nick -> its configured {peer nick: ed25519}
        self._keys = {}
        self.devices = {}       # nick -> the device engines of a multi-device user
        self.nick_of = {}       # a device's label ("alice.1") -> its nick ("alice")
        self.listed = {}        # nick -> device keys its master block lists
        self.no_keys = set()    # device keys grappa holds no one-time key for

    def add(self, nick, network="testnet"):
        key_path = self.tmp_path / f"{nick}.key"
        if not key_path.exists():
            store.generate_key_file(key_path)
        self.pins.setdefault(nick, {})
        e = Engine(self.tmp_path / f"{nick}.{network}.state.json", store.load_key(key_path),
                   network=network, nick=nick, ident=nick[:10], pins=self.pins[nick],
                   clock=self.clock)
        self.engines[nick] = e
        self.events.setdefault(nick, [])
        return e

    def restart(self, nick):
        return self.add(nick)

    def pin(self, a, b, key=None):
        """`a`'s operator pastes `b`'s key into `a`'s configuration."""
        self.pins[a][b] = key or self.engines[b].fingerprint
        for e in self.devices.get(a, [self.engines[a]]):
            e.set_pins(self.pins[a])

    def add_user(self, nick, n, ver=1):
        """`nick` as a cicchetto user with `n` devices under one master, all
        listed (the first four when `n` is more: a list holds four),
        labelled "nick.0" .. "nick.<n-1>". The Net plays the user's
        grappa: it answers a KEYREQ to the nick with every listed device, and
        hands each line to every device (each keeps its own `to` and body)."""
        devs = [self.add(f"{nick}.{i}") for i in range(n)]
        for i, d in enumerate(devs):
            d._master, d.nick = devs[0]._master, nick
            d._own_blocks()
            self.nick_of[f"{nick}.{i}"] = nick
        self.devices[nick], self.engines[nick] = devs, devs[0]
        self.pins[nick] = {}
        self.events.setdefault(nick, [])
        self.relist(nick, devs[:MAX_DEVICES], ver)
        return devs

    def relist(self, nick, keep, ver):
        """The user's master signs a new list holding the devices `keep`."""
        from irc_olm.devices import sign_master
        devs = self.devices[nick]
        block = sign_master(devs[0]._master, ver, [d.device_key for d in keep])
        for d in devs:
            d._ver, d._own_block = ver, block
        self.listed[nick] = {d.device_key for d in keep}

    def _grappa_keys(self, nick, asker, keyreq):
        """What the user's grappa answers a KEYREQ with: its master block and
        a one-time key for each listed device it holds one for."""
        from irc_olm.engine import OTK_SIG_PREFIX, Result
        entries = []
        for d in self.devices[nick]:
            if d.device_key not in self.listed[nick] or d.device_key in self.no_keys:
                continue
            d._account.generate_one_time_keys(1)
            (otk,) = d._account.one_time_keys.values()
            d._account.mark_keys_as_published()
            k = otk.to_base64()
            entries.append({"id": d.identity,
                            "otk": {"key": k, "fallback": False, "sig": d._sign(OTK_SIG_PREFIX + k)}})
        payload = {"v": 2, "master": self.devices[nick][0].master_block, "devices": entries}
        res = Result()
        for line in framing.fragment("KEYS", framing.encode_payload(payload), src=framing.ANY,
                                     dst=framing.parse(keyreq).src, own_mask=f"{nick}!g@h",
                                     target=asker):
            res.outbound.append((asker, line))
        return res

    def pair(self, a, b):
        self.pin(a, b)
        self.pin(b, a)

    def pump(self, sender, result):
        """Deliver `result` from `sender`; returns nothing, events pile up
        per receiving nick in self.events (the sender's own too)."""
        queue = [(sender, result)]
        for _ in range(1000):
            if not queue:
                return
            label, res = queue.pop(0)
            src = self.nick_of.get(label, label)
            self.events[label].extend(res.events)
            for target, body in res.outbound:
                self.wire.append((src, target, body))
                if self.drop and self.drop(src, target, body):
                    continue
                if target in self.devices:
                    if framing.parse(body).verb == "KEYREQ":
                        queue.append((target, self._grappa_keys(target, src, body)))
                        continue
                    for i, d in enumerate(self.devices[target]):
                        queue.append((f"{target}.{i}", d.receive(src, body)))
                elif target in self.engines:
                    queue.append((target, self.engines[target].receive(src, body)))
        raise AssertionError("wire never went quiet")

    def messages(self, sender=None):
        """Logical messages on the wire, fragments joined: [(src, verb, payload)]."""
        out, open_ = [], {}
        for src, _, body in self.wire:
            f = framing.parse(body)
            buf = open_.setdefault((src, f.msgid), [])
            buf.append(f.chunk)
            if len(buf) == f.total:
                del open_[(src, f.msgid)]
                if sender is None or src == sender:
                    out.append((src, f.verb, framing.decode_payload("".join(buf))))
        return out

    def did(self, nick):
        """`nick`'s device address, or a stranger's for a nick with no engine."""
        return self.engines[nick].did if nick in self.engines else "Str4nger-___"[:11]

    def inject(self, src, dst, verb, payload, *, frm=None, to=None):
        """Hand-built traffic: `payload` framed as `verb` from `src`, fed to
        `dst` only (nothing is pumped back). Returns the merged Result. The
        line's `from` and `to` follow the table unless given."""
        from irc_olm.engine import Result
        if frm is None:
            frm = framing.ANY if verb == "KEYS" else self.did(src)
        src = self.nick_of.get(src, src)
        if to is None:
            to = framing.ANY if verb == "KEYREQ" else self.did(dst)
        res = Result()
        for body in framing.fragment(verb, framing.encode_payload(payload), src=frm, dst=to,
                                     own_mask=f"{src}!x@h", target=dst):
            res.extend(self.engines[dst].receive(src, body))
        return res

    def captured(self, verb, sender=None):
        """Payloads of the logical `verb` messages on the wire, oldest first."""
        return [p for src, v, p in self.messages(sender) if v == verb]

    def take(self, nick, kind=None):
        evs, self.events[nick] = self.events[nick], []
        return [e for e in evs if kind is None or isinstance(e, kind)]


def pkmsg(sender, recipient, ct: bytes) -> dict:
    """A PKMSG payload from engine `sender` with one body for `recipient`."""
    from irc_olm.keys import b64
    return {"v": 2, "id": sender.identity, "master": sender.master_ref,
            "bodies": {recipient.did: b64(ct)}}


def msg(sender, recipient, ct: bytes) -> dict:
    """A MSG payload from engine `sender` with one body for `recipient`."""
    from irc_olm.keys import b64
    return {"v": 2, "ck": sender.identity["curve25519"], "bodies": {recipient.did: b64(ct)}}


def body(payload: dict, recipient) -> str:
    """`recipient`'s body in a PKMSG or MSG payload."""
    return payload["bodies"][recipient.did]


def keys_payload(net, src, dst):
    """The KEYS `src` answers `dst`'s KEYREQ with (rate limits apply)."""
    res = net.inject(dst, src, "KEYREQ", {"v": 2})
    return framing.decode_payload("".join(framing.parse(b).chunk for _, b in res.outbound))


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def net(tmp_path, clock):
    return Net(tmp_path, clock)
