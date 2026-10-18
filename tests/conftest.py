import itertools

import pytest

from irc_olm import framing, store
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
        self.engines[a].set_pins(self.pins[a])

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
            src, res = queue.pop(0)
            self.events[src].extend(res.events)
            for target, body in res.outbound:
                self.wire.append((src, target, body))
                if self.drop and self.drop(src, target, body):
                    continue
                if target in self.engines:
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

    def take(self, nick, kind=None):
        evs, self.events[nick] = self.events[nick], []
        return [e for e in evs if kind is None or isinstance(e, kind)]


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def net(tmp_path, clock):
    return Net(tmp_path, clock)
