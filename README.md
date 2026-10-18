# irc-olm

End-to-end encrypted IRC queries on top of [Olm](https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md),
through the [vodozemac](https://github.com/matrix-org/vodozemac) Python bindings.
The ircd and any bouncer only ever relay ciphertext.

The package is shared by vjt's IRC bots ([claude-ircbot](https://github.com/vjt/claude-ircbot)
and the ones after it). It speaks the same wire format as
[grappa](https://github.com/vjt/grappa-irc) and its web client cicchetto. The
protocol is specified in [grappa-irc#2430](https://github.com/vjt/grappa-irc/issues/2430).

**Status:** work in progress, not deployed.

No home-made cryptography: Olm, Ed25519 and SAS all come from vodozemac. This
package only does the IRC framing, the key exchange messages, session recovery
and order challenges.
