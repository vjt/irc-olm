"""A port of bahamut's per-client flood bank and Excess Flood, for pacing tests.

azzurra/bahamut (the tree vendored in grappa-irc): every line (every command
flagged 1 in msgtab: PRIVMSG, NOTICE, NICK, JOIN, MODE, PING, PONG, ...) adds
`2 + params/120` seconds to the client's `since` (src/parse.c:236; `params` is
the line after the command word, CRLF excluded); a read sets
`since = max(since, now)` (src/s_bsd.c:1758); the client's recvQ is parsed only
while `since - now < 10` (src/s_bsd.c:1657); more than CLIENT_FLOOD = 2560
unparsed bytes after a read disconnects a non-oper (src/s_bsd.c:1795,
include/config.h:587). Time is the server's integer time().
"""

CEILING, CLIENT_FLOOD = 10, 2560


class ServerModel:
    def __init__(self):
        self.since = None
        self.recvq: list[str] = []
        self.killed_at = None
        self.parsed: list[tuple[int, str]] = []
        self.max_backlog = 0

    def arrive(self, line: str, now: int) -> None:
        """One line from the client reaches the server at integer second `now`."""
        if self.killed_at is not None:
            return
        self.since = now if self.since is None else max(self.since, now)
        self.recvq.append(line)
        if sum(len(x.encode()) + 2 for x in self.recvq) > CLIENT_FLOOD:
            self.killed_at = now
            return
        self.drain(now)

    def drain(self, now: int) -> None:
        while self.recvq and self.since - now < CEILING:
            line = self.recvq.pop(0)
            params = line.partition(" ")[2]
            self.since += 2 + len(params.encode()) // 120
            self.parsed.append((now, line))
        self.max_backlog = max(self.max_backlog, len(self.recvq))
