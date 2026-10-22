"""A legal `from` / `to` for each verb, for tests that build lines by hand
(framing.ADDRESSES is the table they follow)."""

DID_ME = "AbCdEfGh-_0"
DID_PEER = "_Uw_z3-OAsk"


def addr(verb: str) -> dict:
    if verb == "KEYREQ":
        return {"src": DID_ME, "dst": "*"}
    if verb == "KEYS":
        return {"src": "*", "dst": DID_PEER}
    return {"src": DID_ME, "dst": DID_PEER}
