# irc-olm

End-to-end encrypted IRC queries on top of [Olm](https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md),
through the [vodozemac](https://github.com/matrix-org/vodozemac) Python bindings.
The ircd and any bouncer only ever relay ciphertext.

The package is shared by vjt's IRC bots ([claude-ircbot](https://github.com/vjt/claude-ircbot)
and the ones after it). It speaks the same wire format as
[grappa](https://github.com/vjt/grappa-irc) and its web client cicchetto. The
protocol is specified in [grappa-irc#2430](https://github.com/vjt/grappa-irc/issues/2430);
the wire details are in w2's comment there, acked by both implementations.

**Status:** work in progress, not deployed.

No home-made cryptography: Olm and Ed25519 come from vodozemac. This package
does the IRC framing, the key exchange messages, session recovery, pinning and
order challenges.

SAS verification is not part of this release.

## Install

    pip install "irc-olm @ git+https://github.com/vjt/irc-olm@<sha>"

Python 3.10 or newer. It pulls `vodozemac==0.10.0`, which ships wheels for
Linux (glibc and musl) on x86_64 and aarch64, and for macOS, so no Rust
toolchain is needed.

## Keys and state

    python -m irc_olm keygen /home/bot/.config/irc-olm/azzurra.key

The key file holds 32 random bytes in base64. It is mode 600 and is written
only once (`keygen` refuses to overwrite). It encrypts every secret in the state
file. Keep it out of any repository, next to the bot's other secrets.
**Losing it means a new identity**, and every peer then sees a key alarm and has
to verify again.

There is one identity, and so one state file and one key, per network. The state
file is replaced atomically on every change, at mode 600. A state file or key
that group or others can read is refused, the way ssh refuses a private key.

## Wiring it into a bot

```python
from irc_olm import framing, store
from irc_olm.engine import Engine, Received, KeyAlarm, AckOk, ChallengeExpired
from irc_olm.pacing import PacedSender

engine = Engine("azzurra.state.json", store.load_key("azzurra.key"),
                network="azzurra", nick="vjt-claude", ident="claude")
pacer = PacedSender(lambda target, body: send_raw(f"PRIVMSG {target} :{body}"))

def dispatch(result):
    pacer.submit_all(result.outbound)
    for event in result.events:
        handle(event)                    # Received, KeyAlarm, AckOk, ...

# Inbound: every PRIVMSG body that framing.is_e2e() recognises goes here, and
# never anywhere else (not to the plaintext CTCP path, not to the logs).
if framing.is_e2e(body):
    dispatch(engine.receive(nick, body))

# Outbound:
dispatch(engine.send("vjt", {"t": "text", "body": "ciao"}))

# About once a second, to expire unanswered challenges:
dispatch(engine.tick())
```

When the server tells you your own mask (your JOIN echo, for one), call
`engine.set_own_mask("nick!user@host")`. Until then the chunk budget assumes
the longest mask bahamut allows.

Inner messages are JSON objects with a `t` field: `text`, `action`, `chal`,
`ack` and `sas.*`. `ack` is handled inside the engine. Everything else reaches
you as a `Received` event: act on the types you know and ignore the rest. **`Received.inner` is plaintext.** It is kept out
of `repr()`, but log lengths, never bodies.

## Security notes

- **Pins are on keys, never on nicks.** A key the nick is not pinned to raises
  `KeyAlarm`. Its messages arrive attributed to that new, unverified key, and
  nothing queued for the pinned identity is ever sent to it. Only `verify()`,
  a human decision, moves a pin.
- **Replays.** A pre-key message built on the fallback key can be replayed and
  would decrypt the old plaintext again. Seen session ids are persisted, and a
  replayed one is never decrypted.
- **Order challenges** (`Engine.challenge`) go only to a verified key. Each one
  is single use and expires after 15 s.
- **Threat model.** Whoever owns the bot's host owns its key and reads its side
  of every conversation. The second factor protects against impersonating the
  human, not against a compromised bot host.
- **Metadata** (who talks to whom, when, how much) is visible to the network.

## Pacing

bahamut (Azzurra) drops every CTCP to a client for 15 s once it has received
more than 4 in its 3 s window. That window is in integer seconds, and a steady
sender's count keeps accumulating while it lasts, so 3 lines per 3 s still trips
it. The default is **3 lines per 6 s per target**. `tests/flud_model.py` ports
bahamut's check, and the tests drive the default through it.

## Tests

    pip install -e '.[test]' && python -m pytest
