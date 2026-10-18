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
import time

from irc_olm import framing, store
from irc_olm.pins import load_pins
from irc_olm.engine import Engine, Received, KeyAlarm, AckOk, ChallengeExpired
from irc_olm.pacing import FakeLag, Pacer, PacedSender

engine = Engine("azzurra.state.json", store.load_key("azzurra.key"),
                network="azzurra", nick="vjt-claude", ident="claude",
                pins=load_pins("/etc/vjt-claude/e2e.pins"))
lag = FakeLag()      # the server's flood bank for this connection
# The pacer charges the lines it releases: write them, do not charge them again.
pacer = PacedSender(lambda target, body: write_line(f"PRIVMSG {target} :{body}"),
                    Pacer(fakelag=lag))

def send_raw(line):  # every OTHER line: registration, PONG, chat
    lag.charge(line, time.monotonic())
    write_line(line)

def dispatch(result):
    # Lines leave in the order the engine produced them: call the engine and
    # dispatch its Result under one lock when several threads use it.
    refused = pacer.submit_all(result.outbound, result.urgent)
    engine.discard([msgid for _, msgid in refused])
    for nick, _ in refused:
        report_lost(nick)                # the pacer's queue for it was full
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

Every failure the engine can see is a `SendFailed` event with a reason
(`unpinned-nick`, `unencodable`, `too-long`, `queue-full`, `keys-timeout`,
`key-mismatch`, `rekey-throttled`, `resend-failed`, `repinned`,
`nack-from-another-nick`, ...) and the number of messages lost; `send()` never
raises. `challenge()` raises `NotPinnedError` for a nick without a pinned key:
ask `pinned()` first, under the same lock. IRC itself has no delivery receipt.
A line the server drops (no such nick, the receiver's CTCP flood limit) or that
a broken connection eats is lost without an event, like any IRC line. A
message the pacer refuses, its queue for that nick being full, comes back from
`submit_all` as `(nick, msgid)`: report it, and hand the msgids to
`engine.discard()`. What a peer receives and cannot decrypt, it NACKs, and the
message is sent once more. A message the global reassembly cap drops (see
Pacing) is a `Dropped` event with reason `reassembly:global-byte-cap` and the
nick it came from.

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
  curve25519 key. A peer's curve is stored only once a session exists, and the
  nick it is reached at moves only once a message decrypted. A curve learned
  from keys we asked for stays a claim, even once messages decrypt on that
  session; only a pre-key message the curve's holder built to us proves it,
  and takes it from a key that only claimed it. One curve belongs to one
  pinned key; a second key claiming a proven curve is refused, and nobody may
  claim ours. A nick hint names one
  key: the last one that spoke from it. Keys are compared in vodozemac's one
  spelling.
- **Known limit (unknown key-share).** The inner message does not name the
  sender's and recipient's Ed25519 keys (Matrix puts both inside). Two windows
  stay open, both needing a malicious pinned key. It can capture another
  pinned peer's very first pre-key message off the network and get it
  attributed to itself. Or, when that peer pins it too, it can claim the
  peer's curve, hand us the peer's one-time key and relay: the peer's messages
  on that session then decrypt as the relayer's until the peer opens a session
  of its own. Neither reads anything it could not read already. Check that a
  `Received` comes from the key pinned to its nick (claude-ircbot drops it
  otherwise). Closing both needs both keys in the inner payload, a wire change
  for both implementations.
- **Replays.** A pre-key message built on the fallback key can be replayed and
  would decrypt the old plaintext again. Seen session ids are persisted, and a
  replayed one is never decrypted. The fallback key also rotates weekly, and
  vodozemac forgets a fallback key two rotations later.
- **Recovery.** Every message that does not decrypt gets its own NACK, but
  only when its sender's nick is where the key it claims is reached: a pinned
  key's curve and id block are public, and a NACK to every nick that puts them
  on a line would answer nicks no pinned key ever used. A NACKed message is
  re-sent once, on a newer session when there is one, otherwise on a new one
  (at most one per peer per minute). Messages sent while keys are being asked
  for wait for the new session instead of going out on the session that just
  failed. A NACK from a nick the message was not sent to re-sends nothing (it
  is not authenticated) and is reported as a loss.
- **Order challenges** (`Engine.challenge`) go only to a pinned key. Each one
  is single use and expires after 15 s.
- **Threat model.** Whoever owns the bot's host owns its key and reads its side
  of every conversation. The second factor protects against impersonating the
  human, not against a compromised bot host.
- **Metadata** (who talks to whom, when, how much) is visible to the network.

## Pacing

Two limits, both from bahamut (Azzurra):

- **Per target, for the receiver.** bahamut drops every CTCP to a client for
  15 s once it has received more than 4 in its 3 s window. That window is in
  integer seconds, and a steady sender's count keeps accumulating while it
  lasts, so 3 lines per 3 s still trips it. The default is **3 lines per 6 s
  per target**. `tests/flud_model.py` ports bahamut's check.
- **Per connection, for the sender.** Every line costs its sender
  `2 + bytes/120` seconds of fake lag; the server parses a client's lines only
  while that bank is under 10 s, and more than 2560 unparsed bytes disconnect
  it ("Excess Flood"). A full E2E line costs 5 or 6 s, so the per-target window
  alone gets a long sender killed: at the 12th full line, measured on a
  testnet bahamut (grappa-irc#2430). `FakeLag` models the bank (the same
  arithmetic as grappa's), and a line is released only when the bank plus its
  cost stays at or under 10 s. The bank must see every line on the
  connection: the pacer charges its own, the application charges the rest
  (the application's own lines are charged, not held back, so a bot talking
  hard can still fill the bank itself). `tests/fakelag_model.py` ports the
  server side.

A long message is therefore slow: 64 full lines take over five minutes, and
receivers keep a partial message for 60 s after its LAST fragment (vjt's
ruling on grappa-irc#2430), buffering at most 512 KB across all senders. Past
that the sender holding the most loses its message furthest from completion
(on a tie, the sender whose latest message started last), reported as a
`Dropped` event.

Lines wait in three lanes (`pacing.Lane`):
- **URGENT**: what we originate and cannot wait, a KEYREQ and the messages
  carrying a challenge or an ACK (the engine lists their msgids in
  `Result.urgent`); a challenge expires in 15 s. They go first, oldest first,
  so one message's lines stay together. Nothing holds them back: no peer can
  make us originate more than a KEYREQ a minute.
- **REACTIVE**: what a peer draws from us, KEYS and NACK. Anyone holding a
  pinned nick can draw them (a KEYS for each KEYREQ, at most one per 15 s; a
  NACK for each junk line), so each target's go ahead of text only within 10 s
  of flood bank a minute (a KEYS and a NACK), taking turns by target; past it
  they wait behind the text. With n holders of pinned nicks flooding us, text
  keeps 60 - 10n s of bank a minute.
- **TEXT**: turns go to the target served longest ago, and a target's text
  keeps its order, so a short message never overtakes a long one sent before
  it. A target is its case-folded nick.

REACTIVE and TEXT lines never take the bank past 5 s (a full line, 6 s, goes
at an empty bank). The rest is kept for URGENT lines, at no cost in throughput
(the bank drains a second a second either way): behind a stream of text, a
challenge on an established session (two lines) leaves within 7 s, a first
challenge (a pre-key message, three lines) within 12 s, and flooders change
neither. The application's own lines are charged, not held back: a bot that
talks hard eats into the reserve too.

The queues are bounded. Each message is queued or refused whole (half a
fragmented message is worse than none), and `submit_all` returns the refused
ones:
- queued text, all targets together, may cost at most 480 s of flood bank (80
  to 96 full lines). With a third of the bank left to text (the rest to three
  flooders and the bot talking at a sixth of its bank) it leaves in 24
  minutes, and a NACK finds the plaintext: the engine keeps it 30 minutes, and
  at most 1200 messages, what the bank lets out in that time. A bot taking
  more of its bank for itself can outrun that; a late NACK is then a `Dropped`
  `unknown-nack-ref`;
- at most 32 text messages per target. An urgent message overtakes them, and
  the receiver's Olm skips a message key for each one overtaken; vodozemac
  keeps 40;
- at most 32 lines per target in each of the URGENT and REACTIVE lanes.

A `send` that raises is logged and the thread carries on.

## Tests

    pip install -e '.[test]' && python -m pytest
