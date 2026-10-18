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
**Losing it means a new identity**, and every peer's operator has to paste the
new key in again.

## Pinned keys

A bot talks E2E only to the keys its operator pinned (vjt's ruling on
grappa-irc#2430). There is no trust-on-first-use and no SAS on a bot. The pins
file has one `<nick> <ed25519>` per line, and the key is the peer's Ed25519 key
exactly as it shows it (unpadded base64, 43 chars). An unknown key gets
silence: no KEYS, no NACK, no session. Rotation means re-pasting the key and
reloading (`Engine.set_pins`).

The bot only reads the pins file. **It must not be writable by the bot's own
Claude session**: the operator makes it root-owned in a root-owned directory,
or denies it in that session's permission rules. `pins_writable()` lets the
bot warn when it is not.

To print the bot's own key for pasting into the other side (cicchetto's
manual pin):

    python -m irc_olm identity --state azzurra.state.json

There is one identity, and so one state file and one key, per network. The state
file is replaced atomically on every change, at mode 600. A state file or key
that group or others can read is refused, the way ssh refuses a private key.

## Wiring it into a bot

```python
from irc_olm import framing, store
from irc_olm.pins import load_pins
from irc_olm.engine import Engine, Received, KeyAlarm, AckOk, ChallengeExpired
from irc_olm.pacing import PacedSender

engine = Engine("azzurra.state.json", store.load_key("azzurra.key"),
                network="azzurra", nick="vjt-claude", ident="claude",
                pins=load_pins("/etc/vjt-claude/e2e.pins"))
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

# About once a second: expires unanswered challenges, reports (SendFailed)
# messages that waited too long for keys, rotates the fallback key weekly.
dispatch(engine.tick())
```

When the server tells you your own mask (your JOIN echo, for one), call
`engine.set_own_mask("nick!user@host")`, and again after your own NICK change.
Until then the chunk budget assumes the longest mask bahamut allows.

A message that cannot be delivered is always a `SendFailed` event with a
reason (`unpinned-nick`, `unencodable`, `queue-full`, `keys-timeout`,
`key-mismatch`, `rekey-throttled`, ...) and the number of messages lost. There is no other
failure path.

Inner messages are JSON objects with a `t` field: `text`, `action`, `chal` and
`ack` (SAS messages only ever travel between two cicchettos). `ack` is handled
inside the engine. Everything else reaches
you as a `Received` event: act on the types you know and ignore the rest. **`Received.inner` is plaintext.** It is kept out
of `repr()`, but log lengths, never bodies.

## Security notes

- **Pins are on keys, never on nicks.** A pinned key is accepted under any
  nick. A different key on a pinned nick raises `KeyAlarm` for the log and is
  ignored. Nothing queued for a key is ever sent to another key, including
  one the operator pasted in its place.
- **Nothing moves before a session proves it.** An id block is public and
  replayable, and its signature only says the Ed25519 key claims that
  curve25519 key. A peer's curve is stored, and the nick it is reached at
  moves, only once a session exists: one opened on keys we asked for, or one
  whose first message decrypted. One curve belongs to one pinned key; a second
  key claiming it is refused. Keys are compared in vodozemac's one spelling.
- **Known limit (unknown key-share).** The inner message does not name the
  sender's and recipient's Ed25519 keys (Matrix puts both inside). The rules
  above close it except for one window: a pinned peer that captures another
  pinned peer's very first pre-key message off the network could get it
  attributed to itself. Closing that needs both keys in the inner payload, a
  wire change for both implementations.
- **Replays.** A pre-key message built on the fallback key can be replayed and
  would decrypt the old plaintext again. Seen session ids are persisted, and a
  replayed one is never decrypted. The fallback key also rotates weekly, and
  vodozemac forgets a fallback key two rotations later.
- **Recovery.** A NACK re-sends on a newer session when there is one, and
  otherwise opens a new one (at most one per peer per minute). Messages sent
  while keys are being asked for wait for the new session instead of going
  out on the session that just failed.
- **Order challenges** (`Engine.challenge`) go only to a pinned key. Each one
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

Each target queues at most 512 lines (about 17 minutes at that rate). A batch
that does not fit is refused whole and logged, since half a fragmented message
is worse than none. A `send` that raises is logged and the thread carries on.

## Tests

    pip install -e '.[test]' && python -m pytest
