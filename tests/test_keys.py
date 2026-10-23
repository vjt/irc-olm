import pytest
import vodozemac as vz

from irc_olm.keys import is_curve, is_key, sig_ok

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def stray(key):
    """The same 32 bytes, spelled with the last character's unused bit set."""
    return key[:-1] + ALPHABET[ALPHABET.index(key[-1]) ^ 1]


@pytest.mark.parametrize("check,key", [
    (is_key, lambda: vz.Account().ed25519_key.to_base64()),
    (is_curve, lambda: vz.Account().curve25519_key.to_base64()),
])
def test_a_key_passes_only_in_its_one_spelling(check, key):
    k = key()
    assert check(k)
    assert not check(k + "=")               # vodozemac parses it; the wire does not
    assert not check(stray(k))
    assert not check(k[:-1])
    assert not check(k + "A")
    assert not check("A" * 44)              # 33 bytes: vodozemac would panic on an Ed25519
    assert not check("!" * 43)
    assert not check(None)
    assert not check(42)


def test_an_ed25519_key_is_not_a_curve_and_back():
    a = vz.Account()
    # Both are 32 bytes in base64; only vodozemac's parse tells them apart,
    # and only sometimes. What matters is that neither check crashes.
    for k in (a.ed25519_key.to_base64(), a.curve25519_key.to_base64()):
        assert isinstance(is_key(k), bool) and isinstance(is_curve(k), bool)


def test_sig_ok_takes_a_signature_of_86_characters_only():
    a = vz.Account()
    ed = a.ed25519_key.to_base64()
    sig = a.sign(b"text").to_base64()
    assert len(sig) == 86
    assert sig_ok(ed, "text", sig)
    assert not sig_ok(ed, "text", sig + "==")   # vodozemac decodes it
    assert not sig_ok(ed, "other", sig)
    assert not sig_ok(vz.Account().ed25519_key.to_base64(), "text", sig)
    assert not sig_ok(ed, "text", None)
    assert not sig_ok("A" * 44, "text", sig)
