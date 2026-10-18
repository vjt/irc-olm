"""A port of bahamut's CTCP flood protection, for pacing tests.

azzurra/bahamut src/s_user.c check_for_flud() with include/config.h's
FLUD_NUM 4, FLUD_TIME 3, FLUD_BLOCK 15. One recipient, any number of
senders. Time is the server's integer time().
"""

FLUD_NUM, FLUD_TIME, FLUD_BLOCK = 4, 3, 15


class FludModel:
    def __init__(self):
        self.fluders = {}          # sender -> [count, first_msg, last_msg]
        self.fludblock = -10**9
        self.trips = 0

    def ctcp(self, sender, now):
        """One CTCP PRIVMSG reaching the recipient at integer second `now`.
        Returns True when the server drops it."""
        blocking = self.fludblock > now - FLUD_BLOCK
        if not blocking:
            for s, e in list(self.fluders.items()):
                if e[2] < now - FLUD_TIME:
                    del self.fluders[s]
        count = 0
        found = False
        for s, e in self.fluders.items():
            if s == sender:
                e[2] = now
                e[0] += 1
                found = True
            count += 1 if e[1] < now - FLUD_TIME else e[0]
        if not found:
            self.fluders[sender] = [1, now, now]
            count += 1
        if not blocking and count > FLUD_NUM:
            blocking = True
            self.trips += 1
        if blocking:
            self.fludblock = now
        return blocking
