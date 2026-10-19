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

def lost(nick, msgid, reason):   # on the pacer's thread, see below
    engine.discard([msgid])
    if reason == "send-failed":
        report_lost(nick)

# The pacer charges the lines it releases: write them, do not charge them again.
pacer = PacedSender(lambda target, body: write_line(f"PRIVMSG {target} :{body}"),
                    Pacer(fakelag=lag), on_lost=lost)

def send_raw(line):  # every OTHER line: registration, PONG, chat
    lag.charge(line, time.monotonic())
    write_line(line)

def dispatch(result):
    # Lines leave in the order the engine produced them: call the engine and
    # dispatch its Result under one lock when several threads use it.
    refused = pacer.submit_all(result.outbound, result.urgent)
    engine.discard([msgid for _, msgid in refused])
    for nick, msgid in refused:
        if msgid not in result.urgent:   # a refused CHAL ends as ChallengeExpired
            report_lost(nick)            # the pacer's queue for it was full
    for event in result.events:
        handle(event)                    # Received, KeyAlarm, AckOk, ...

# Inbound: every PRIVMSG body that framing.is_e2e() recognises goes here, and
# never anywhere else (not to the plaintext CTCP path, not to the logs).
if framing.is_e2e(body):
    dispatch(engine.receive(nick, body))

# Outbound. Ask the pacer first: a message it refuses was encrypted all the
# same, and the receiver skips its key when a CHAL overtakes the queue.
if pacer.room("vjt"):
    dispatch(engine.send("vjt", {"t": "text", "body": "ciao"}))
else:
    report_lost("vjt")

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
message the pacer refuses, its queues being full (see Pacing), comes back
from `submit_all` as `(nick, msgid)`: report it, and hand the msgids to
`engine.discard()`. Only messages that carried text come back: a refused
KEYREQ, KEYS or NACK is logged, and the protocol recovers from it or the
engine reports what it cost (a `keys-timeout`). What the pacer loses after
queueing it goes to `on_lost(nick, msgid, reason)`: `"late"`, a CHAL it could
no longer start in time to be answered (`ChallengeExpired` then reports the
order), and `"send-failed"`, a message one of whose lines your `send` raised
on (the rest of it is dropped: its receiver could never complete it). If the
pacer's thread dies, every call on it raises from then on. A message too long
for 64 fragments is a `SendFailed` `too-long`, and leaves the session as it
was. What a peer receives and cannot decrypt, it NACKs, and the
message is sent once more. A message the global reassembly cap drops (see
Pacing) is a `Dropped` event with reason `reassembly:global-byte-cap` and the
case-folded nick it came from.

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

Lines wait in three lanes (`pacing.Lane`), and are scheduled by message: once
an urgent or a text message's first line has left, no other message of its
lane starts before it ends, so one urgent and one text message are under way
at a time (KEYS and NACKs to different targets may interleave).
- **URGENT**: what we originate and cannot wait, a KEYREQ and the messages
  carrying a challenge or an ACK (the engine lists their msgids in
  `Result.urgent`). They go ahead of text within 36 s of flood bank a minute
  for the whole connection, whoever gives the orders: four orders, or a first
  contact and two (with a short own mask too). One human may take it all;
  a second human, and a first contact's KEYS going ahead of the orders
  (below), share a 9 s allowance on top.
  Peers draw these too, since the bot challenges every line a pinned human
  addresses to it, and humans chatting with it would otherwise take the whole
  bank. A challenge carries its deadline (the engine hands the pacer the
  seconds it has left), and starts only if its last line can leave 2 s before
  it, the ACK's way back: one that could not be answered any more is dropped
  unsent (`on_lost` `"late"`). The estimate counts the bank, not the
  target's window: a challenge reaching the pacer with under 8 s left just
  behind two NACKs to the same peer can finish up to 3 s late (70 of 2880
  such cases, measured), and then expires unanswered (`ChallengeExpired`).
- **REACTIVE**: what a peer draws from us, KEYS and NACK (a KEYS for each
  KEYREQ, at most one per 15 s; a NACK for each junk line). They go ahead of
  text within 18 s of bank per target per minute (five NACKs and a KEYS, the
  recovery after a lost session, or a KEYS and a retry's) and 22 s for all
  targets together. A KEYS or NACK under way whose last line left 20 s ago
  goes next after text under way past the floor and a first contact's KEYS
  that has waited (below), ahead of the orders, so its receiver gets the
  rest within the same 46 s as text.
- **TEXT**: no budget, and a floor instead: when text is queued and none has
  left for 20 s, a text message under way goes next after an order under
  way, since its receiver would drop it; a message not started yet goes after
  the orders, the first contacts' KEYS that have waited (below) and the rest
  of a KEYS or NACK under way past its own 20 s. The orders' budget and the
  allowance keep the first two to about 45 s of bank a minute, so its first
  line can wait about 70 s (69 measured), and text keeps 10 s a minute or
  more (measured below). A message under way therefore
  gets a line at least every 46 s
  (the floor, the rest of one order, the bank emptying for the text line and
  the target's window), inside the 60 s its receiver keeps it, whatever goes
  ahead of it.

A budget counts all of a message's lines, decided when its first one is due,
so ahead of text the orders never take more than 36 s in any minute (45 with
the allowance below) and the KEYS and NACKs of one target never more than 18.
Past its budget an urgent or reactive message waits behind the text, but it
still goes when no text line can (none queued, or the text target's window
full), since the bank would idle otherwise: with no text, or short text
lines, a minute can hold more (measured: 55 s of orders with one text target
of 2 s lines, 69 with no text, 26 s of one flooder's KEYS and NACKs with no
text). A target which drew nothing else from a lane in the last minute
(nothing sent, this one message queued) may still take the connection's
budget 9 s further, one message for all such targets together: an honest
peer behind flooders, a second human behind a chatty one. Such a target's
KEYS or NACK goes ahead of everyone else's not started yet at once. A first
contact's KEYS goes further: once it has waited 8 s (`FRESH_PATIENCE`), it
goes ahead of the orders queued after that instant and of text past the
floor, taking the reserve below if it needs it, and what of it goes ahead
is paid, once, from the orders' allowance, the one the second human takes.
A first contact is thus answered before its asker asks again (30 s); the
orders queued before keep their place, waiting on the bank or not (a
challenge arriving meanwhile has 15 s to be answered); and the orders keep
their own 36 s. Ahead of text past the floor, the orders, the second human
and the first contacts together never take more than 45 s a minute, and
while the orders are at their budget one of the second human and the first
contacts goes in a minute. A NACK never goes ahead of the orders: nobody
waits on it (its sender keeps the message 30 minutes), whereas a KEYS's
asker asks again at 30 s and drops what it queued at 60. A flooder held
back by the budget always has more queued. Turns go to
the target served longest ago, in every lane, so one
target's messages do not hold another's back. Within a target each lane keeps
its order, so a short message never overtakes a long one sent before it. A
target is its case-folded nick.

Measured (`irc-olm` PR 2, no application lines; each figure holds for the
shape named, not beyond it):
- 1, 2, 3, 6, 10 and 15 holders of pinned nicks flooding us at the most the
  engine answers (a NACK every 3 s, a KEYS every 15 s): text keeps 42, 39,
  38, 40, 39 and 38 s of bank a minute (35-46 with other NACK and KEYS
  rates), a challenge on an established session leaves within 3.95 s
  (5 + 4 s of lines) or 5.95 s (6 + 5) and a first one (three lines) within
  10.95 s, an honest peer's KEYS within 12 s (11.95 measured).
- Humans chatting with the bot, however many and however fast, and no
  flooders: with two streams of full text lines the orders never take more
  than 45 s in any minute, every challenge sent can still be answered (its
  last line leaves within 13 s), text keeps 14 to 48 s of bank a minute
  (24.7 with two text streams and 1-4 humans every 6-15 s), and an honest
  peer's KEYS leaves within 32 s (over 22 s in 55 of 144 random shapes,
  past the asker's 30 s in 3, which then asks again and keeps what it
  queued for 60 s); another human's order leaves within 7 s, or within
  13 s when it lands just behind the chatting human's challenge (two
  challenges at a 10 s bank). The second human and a first contact share
  the allowance: with one human addressing the bot every 15 s and a first
  contact in the same minute, a second human's 6 + 5 s challenge is dropped
  late in 446 of 810 shapes (8 of 30 with no first contact), and a second
  first contact within about 10 s of the first waits up to 38.5 s for its
  KEYS (past 30 s in 57 of 2500 random shapes).
- Fresh peers on top, each drawing one NACK every 75 s (up to 24 of them) or
  one KEYS every 61 s (up to 6), with one to four humans chatting: the orders
  keep their budget (34.6 s of bank a minute; one human every 15 s among 16
  such NACK peers has 2 of its 32 challenges dropped late), text keeps 10 to
  12 s a minute and is silent for up to 64 s, and a 10-line reply's first
  line can wait two minutes (98 to 124 s); it always completes. One to three
  first contacts' KEYS queued
  just before a challenge cost it nothing past the bounds below: every
  challenge with 15 s left is sent.
- Humans and flooders together leave text the floor and little more, 8.5 to
  11.2 s of bank a minute: a 10-line reply behind two streams of text
  completes in five to six minutes, its lines at most 32 s apart.
- Peers drawing one KEYS each just over a minute apart (each "fresh" every
  time) leave text 34-36 s. Eight of them draw 64 s of bank a minute against
  the 31 s the REACTIVE budget and the allowance let ahead of text, so their
  KEYS queue: an honest peer's KEYS among them waits up to 32 s, 39 s when
  two humans chat with the bot as well, 48 s when four to ten humans
  address it; its asker asks again and may see its queued messages fail
  (`keys-timeout`, reported). This is the known limit: about three first
  contacts a minute.
- One pinned nick using both lanes (addressing the bot every 4 to 15 s while
  drawing a NACK every 3 s and a KEYS every 15 s) takes up to 54 s in a
  minute (its two budgets allow 36 + 18), and leaves text 10.8 to 12.
- Multi-line messages under flood leave at most 23 s between fragments, and
  39 s in random mixes of orders, flooders and long replies. The second line
  of a KEYS under way leaves at most 33 s after its first behind chatting
  humans, 44 s in random mixes. A KEYS after six NACKs in the same minute
  still waits for the budget to recover, a minute late.

REACTIVE and TEXT lines never take the bank past 5 s (a full line, 6 s, goes
at an empty bank), except a KEYS or NACK going ahead of text past the floor:
a first contact's KEYS that has waited 8 s, and the rest of a KEYS or NACK
whose last line left 20 s ago.
The rest is kept for URGENT lines, at no cost in throughput (the bank drains
a second a second either way): behind a stream of text, a challenge on an
established session (two lines) leaves within 7 s, a first challenge (a
pre-key message, three lines) within 12 s, whatever flooders do (measured
4.9 to 6.9 s and 9.9 to 11.9 s). Both bounds assume no other urgent message
queued ahead, no text message under way that has waited 20 s (the floor), no
first contact's KEYS whose 8 s ran out before the challenge was queued, no
KEYS or NACK under way past its own 20 s, and no line of the application's
own in the last 10 s, each of which adds its cost; and the 15 s
of a challenge (14 to 15: it expires at a whole second) run from
`challenge()`, so on first contact they also cover the KEYREQ and the KEYS
coming back. The application's lines are charged, not held back. The reserve
also costs a KEYS's second line about 3 s on an idle connection.

The queues are bounded. Each message is queued or refused whole (half a
fragmented message is worse than none):
- queued text, all targets together, may cost at most 480 s of flood bank (80
  to 96 full lines). With a third of the bank left to text (the rest to three
  flooders and the bot talking at a tenth of its bank) it leaves in 20
  minutes, and a NACK finds the plaintext: the engine keeps it 30 minutes, and
  at most 1200 messages, what the bank lets out in that time. A bot taking
  more of its bank for itself can outrun that; a late NACK is then a `Dropped`
  `unknown-nack-ref`;
- at most 32 text messages per target, counting the Olm messages refused or
  dropped behind them while text is queued. An urgent message overtakes the
  queue, and the receiver's Olm skips a message key for each message
  overtaken and each refused one (it was encrypted all the same); vodozemac
  keeps 40. `room(nick)` says whether a one-line text message still fits
  (the per-target count, and a full line free in the shared backlog): ask it
  before `engine.send()`. A longer message can still be refused, and
  `submit_all` says so;
- at most 32 lines per target in each of the URGENT and REACTIVE lanes.

`Pacer.submit` takes whole messages, one after another: ValueError when one
cuts into another or the last line does not end one (fragment indexes are
not checked; `submit_all` passes the messages the engine built). A `send`
that raises is logged, the rest of its message dropped and reported, and the
thread carries on.

## Tests

    pip install -e '.[test]' && python -m pytest
