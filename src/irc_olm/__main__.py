"""Command line: `python -m irc_olm keygen PATH` and `identity --state PATH`."""

from __future__ import annotations

import argparse
import sys

from . import store


def _keygen(args) -> int:
    try:
        store.generate_key_file(args.path)
    except FileExistsError:
        print(f"{args.path} exists: refusing to overwrite a key (it IS the identity)",
              file=sys.stderr)
        return 1
    print(f"wrote {args.path} (mode 600). Keep it out of any repository.")
    return 0


def _identity(args) -> int:
    doc = store.StateFile(args.state).load()
    if doc is None:
        print(f"{args.state}: no such state file (the bot creates it on first start)",
              file=sys.stderr)
        return 1
    # The key to paste into the peer's configuration (cicchetto's manual pin).
    print(doc["identity"]["ed25519"])
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m irc_olm")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="write a new pickle key (mode 600)")
    k.add_argument("path")
    k.set_defaults(func=_keygen)
    i = sub.add_parser("identity", help="print this identity's Ed25519 key, to paste into peers")
    i.add_argument("--state", required=True)
    i.set_defaults(func=_identity)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
