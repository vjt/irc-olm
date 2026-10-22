"""A user's devices under one master key (wire v2, grappa-irc#2430)."""

import math

import pytest
import vodozemac as vz

from irc_olm import devices
from irc_olm.devices import (MAX_DEVICES, Book, Change, DeviceList, InvalidBlock, binding,
                             cert_ok, cert_text, did, id_block, id_ok, list_text, parse_keys,
                             parse_master, parse_master_ref, sign_cert, sign_master, wire_int)

# RFC 8032, 7.1, tests 1 and 2: public keys anyone can check the dids of.
RFC_KEY_1 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo"
RFC_KEY_2 = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw"


def keys(n):
    """n device keys in wire order."""
    return sorted(vz.Account().ed25519_key.to_base64() for _ in range(n))


@pytest.fixture
def master():
    return vz.Account()


def m_key(account):
    return account.ed25519_key.to_base64()


def resign(master, block):
    """`block` with its signature redone by `master` over what it now says."""
    lst = block["list"]
    text = devices.LIST_SIG_PREFIX + f"{lst['ver']}:" + ",".join(lst["devices"])
    return {**block, "sig": master.sign(text.encode()).to_base64()}


# --- did ------------------------------------------------------------------

# The vectors of the base64url amendment (grappa-irc#2430, 6348464388): grappa
# and cicchetto pin the same two, so the three implementations agree on bytes.
VECTOR_2 = "7l01yXGoarYtEU3nwHF01/CIo8/r8U0lJ01TnULT9IY"   # raw = sha256("irc-e2e did vector 70")


def test_did_is_the_first_8_bytes_of_sha256_over_the_raw_key():
    assert did(RFC_KEY_1) == "If4x36FUomE"
    assert did(RFC_KEY_2) == "OfcT0KZEJT8"


def test_did_is_base64url_so_it_can_sit_in_a_url_path():
    assert did(VECTOR_2) == "_Uw_z3-OAsk"            # its standard form, /Uw/z3+OAsk, splits a path


def test_did_is_11_characters_of_unpadded_base64url():
    for k in keys(20):
        d = did(k)
        assert len(d) == 11
        assert set(d) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


# --- encodings ------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (1, 1), (2, 2), (2**31 - 1, 2**31 - 1),
    (1.0, 1),            # a JSON number: its value is what counts
    (7.0, 7),
])
def test_wire_int_accepts_integral_values_in_range(value, expected):
    got = wire_int(value)
    assert got == expected and type(got) is int


@pytest.mark.parametrize("value", [
    0, -1, 2**31, 1.5, True, False, "1", None, [1], {"v": 1},
    math.nan, math.inf, -math.inf, 2.0**31,
])
def test_wire_int_refuses_everything_else(value):
    assert wire_int(value) is None


# --- the master block -----------------------------------------------------

def test_list_text_is_the_signed_string():
    assert list_text(12, [RFC_KEY_2, RFC_KEY_1]) == (
        "irc-e2e:v2:list:12:" + RFC_KEY_2 + "," + RFC_KEY_1)


def test_a_signed_block_parses(master):
    devs = keys(3)
    block = sign_master(master, 5, devs)
    assert block["ed25519"] == m_key(master)
    assert block["list"] == {"ver": 5, "devices": devs}
    assert parse_master(block) == DeviceList(m_key(master), 5, tuple(devs))


def test_sign_master_sorts_the_devices(master):
    devs = keys(3)
    block = sign_master(master, 1, list(reversed(devs)))
    assert block["list"]["devices"] == devs


@pytest.mark.parametrize("n", [0, MAX_DEVICES + 1])
def test_sign_master_refuses_a_list_outside_1_to_4(master, n):
    with pytest.raises(ValueError):
        sign_master(master, 1, keys(n))


def test_sign_master_refuses_a_duplicate(master):
    (k,) = keys(1)
    with pytest.raises(ValueError):
        sign_master(master, 1, [k, k])


@pytest.mark.parametrize("ver", [0, 2**31, True])
def test_sign_master_refuses_a_version_out_of_range(master, ver):
    with pytest.raises(ValueError):
        sign_master(master, ver, keys(1))


def test_the_cap_is_4():
    assert MAX_DEVICES == 4


def test_four_devices_parse_five_do_not(master):
    devs = keys(5)
    assert parse_master(sign_master(master, 1, devs[:4])).devices == tuple(devs[:4])
    five = resign(master, {"ed25519": m_key(master), "list": {"ver": 1, "devices": devs}})
    with pytest.raises(InvalidBlock):
        parse_master(five)


def test_an_empty_list_does_not_parse(master):
    empty = resign(master, {"ed25519": m_key(master), "list": {"ver": 1, "devices": []}})
    with pytest.raises(InvalidBlock):
        parse_master(empty)


def test_an_unsorted_list_does_not_parse(master):
    devs = keys(2)
    block = resign(master, {"ed25519": m_key(master),
                            "list": {"ver": 1, "devices": list(reversed(devs))}})
    with pytest.raises(InvalidBlock):
        parse_master(block)


def test_a_duplicate_device_does_not_parse(master):
    (k,) = keys(1)
    block = resign(master, {"ed25519": m_key(master), "list": {"ver": 1, "devices": [k, k]}})
    with pytest.raises(InvalidBlock):
        parse_master(block)


def test_two_devices_with_one_did_do_not_parse(master, monkeypatch):
    devs = keys(2)
    block = sign_master(master, 1, devs)
    monkeypatch.setattr(devices, "did", lambda key: "AAAAAAAAAAA")
    with pytest.raises(InvalidBlock):
        parse_master(block)


def test_a_non_canonical_device_key_does_not_parse(master):
    devs = keys(2)
    block = resign(master, {"ed25519": m_key(master),
                            "list": {"ver": 1, "devices": [devs[0] + "=", devs[1]]}})
    with pytest.raises(InvalidBlock):
        parse_master(block)


def test_a_non_canonical_master_key_does_not_parse(master):
    block = sign_master(master, 1, keys(1))
    with pytest.raises(InvalidBlock):
        parse_master({**block, "ed25519": block["ed25519"] + "="})


def test_a_block_signed_by_another_key_does_not_parse(master):
    block = sign_master(vz.Account(), 1, keys(1))
    with pytest.raises(InvalidBlock):
        parse_master({**block, "ed25519": m_key(master)})


def test_a_raised_version_does_not_verify(master):
    block = sign_master(master, 1, keys(1))
    with pytest.raises(InvalidBlock):
        parse_master({**block, "list": {**block["list"], "ver": 2}})


def test_a_swapped_device_does_not_verify(master):
    devs = keys(3)
    block = sign_master(master, 1, devs[:2])
    with pytest.raises(InvalidBlock):
        parse_master({**block, "list": {**block["list"], "devices": sorted([devs[0], devs[2]])}})


def test_a_version_of_1_0_counts_as_1(master):
    block = sign_master(master, 1, keys(1))
    assert parse_master({**block, "list": {**block["list"], "ver": 1.0}}).ver == 1


@pytest.mark.parametrize("ver", [True, "1", 0, 2**31, 1.5, None])
def test_a_version_that_is_not_an_integer_in_range_does_not_parse(master, ver):
    block = resign(master, {"ed25519": m_key(master), "list": {"ver": ver, "devices": keys(1)}})
    with pytest.raises(InvalidBlock):
        parse_master(block)


@pytest.mark.parametrize("mangle", [
    lambda b: None,
    lambda b: [],
    lambda b: {k: v for k, v in b.items() if k != "sig"},
    lambda b: {k: v for k, v in b.items() if k != "list"},
    lambda b: {k: v for k, v in b.items() if k != "ed25519"},
    lambda b: {**b, "list": None},
    lambda b: {**b, "list": {"ver": 1}},
    lambda b: {**b, "list": {**b["list"], "devices": b["list"]["devices"][0]}},
    lambda b: {**b, "list": {**b["list"], "devices": [7]}},
    lambda b: {**b, "sig": 7},
    lambda b: {**b, "sig": b["sig"][:-1]},
    lambda b: {**b, "sig": "!" * 86},
])
def test_a_malformed_block_does_not_parse(master, mangle):
    with pytest.raises(InvalidBlock):
        parse_master(mangle(sign_master(master, 1, keys(1))))


def test_a_padded_signature_does_not_verify(master):
    # vodozemac decodes it; the wire spells a signature in 86 characters
    block = sign_master(master, 1, keys(1))
    with pytest.raises(InvalidBlock):
        parse_master({**block, "sig": block["sig"] + "=="})


def test_unknown_fields_are_ignored(master):
    block = sign_master(master, 1, keys(1))
    block["extra"] = 1
    block["list"]["extra"] = [1]
    assert parse_master(block).ver == 1


# --- the id block ---------------------------------------------------------

def test_an_id_block_vouches_for_its_master(master):
    device = vz.Account()
    block = id_block(device, m_key(master))
    assert block["ed25519"] == device.ed25519_key.to_base64()
    assert block["curve25519"] == device.curve25519_key.to_base64()
    assert id_ok(block, m_key(master))


def test_an_id_block_does_not_vouch_for_another_master(master):
    # Change 3: Mallory's master listing Alice's device gets nowhere, since
    # Alice's device signed her own master and nobody else's.
    block = id_block(vz.Account(), m_key(master))
    assert not id_ok(block, m_key(vz.Account()))


def test_a_v1_id_signature_does_not_count(master):
    device = vz.Account()
    curve = device.curve25519_key.to_base64()
    v1 = {"curve25519": curve, "ed25519": device.ed25519_key.to_base64(),
          "sig": device.sign(("irc-e2e:v1:id:" + curve).encode()).to_base64()}
    assert not id_ok(v1, m_key(master))


def test_an_id_block_with_another_curve_does_not_verify(master):
    block = id_block(vz.Account(), m_key(master))
    other = vz.Account().curve25519_key.to_base64()
    assert not id_ok({**block, "curve25519": other}, m_key(master))


@pytest.mark.parametrize("mangle", [
    lambda b: None,
    lambda b: {k: v for k, v in b.items() if k != "sig"},
    lambda b: {**b, "ed25519": b["ed25519"] + "="},
    lambda b: {**b, "curve25519": b["curve25519"] + "="},
    lambda b: {**b, "curve25519": 7},
    lambda b: {**b, "sig": "!" * 86},
])
def test_a_malformed_id_block_does_not_verify(master, mangle):
    assert not id_ok(mangle(id_block(vz.Account(), m_key(master))), m_key(master))


# --- the device certificate and the PKMSG's master block --------------------

def test_cert_text_is_the_signed_string():
    assert cert_text(RFC_KEY_1) == "irc-e2e:v2:dev:" + RFC_KEY_1


def test_a_cert_verifies_under_its_master_for_its_device(master):
    dev = vz.Account()
    c = sign_cert(master, ed(dev))
    assert cert_ok(m_key(master), ed(dev), c)
    assert not cert_ok(m_key(vz.Account()), ed(dev), c)         # another master
    assert not cert_ok(m_key(master), ed(vz.Account()), c)      # another device
    assert not cert_ok(m_key(master), ed(dev), c + "A")
    assert not cert_ok(m_key(master), ed(dev), None)


def test_a_list_signature_is_not_a_cert(master):
    dev = vz.Account()
    block = sign_master(master, 1, [ed(dev)])
    assert not cert_ok(m_key(master), ed(dev), block["sig"])


def test_the_pkmsg_master_block_parses_into_its_key_and_cert(master):
    dev = vz.Account()
    c = sign_cert(master, ed(dev))
    assert parse_master_ref({"ed25519": m_key(master), "cert": c, "x": 1}) == (m_key(master), c)


@pytest.mark.parametrize("mangle", [
    lambda b: None,
    lambda b: [],
    lambda b: {**b, "ed25519": b["ed25519"] + "="},
    lambda b: {k: v for k, v in b.items() if k != "cert"},
    lambda b: {**b, "cert": 7},
    lambda b: {**b, "cert": b["cert"][:-1]},
])
def test_a_malformed_pkmsg_master_block_does_not_parse(master, mangle):
    block = {"ed25519": m_key(master), "cert": sign_cert(master, ed(vz.Account()))}
    with pytest.raises(InvalidBlock):
        parse_master_ref(mangle(block))


# --- the fk/tk binding ------------------------------------------------------

def test_the_binding_is_16_bytes_of_sha256_over_both_keys_in_order():
    assert binding(RFC_KEY_1, RFC_KEY_2) == "l+TpsPRwYcy6cwpxK79anQ"
    assert binding(RFC_KEY_2, RFC_KEY_1) == "V94U/7K/o6CVvEgCpfxUhQ"   # sender first


# --- KEYS v2 --------------------------------------------------------------

def keys_payload(master, accounts, ver=1, listed=None):
    m = m_key(master)
    listed = listed if listed is not None else [a.ed25519_key.to_base64() for a in accounts]
    entries = []
    for a in accounts:
        a.generate_one_time_keys(1)
        (otk,) = a.one_time_keys.values()
        a.mark_keys_as_published()
        o = otk.to_base64()
        entries.append({"id": id_block(a, m),
                        "otk": {"key": o, "fallback": False,
                                "sig": a.sign(("irc-e2e:v1:otk:" + o).encode()).to_base64()}})
    return {"v": 2, "master": sign_master(master, ver, listed), "devices": entries}


def test_keys_parse_into_the_list_and_its_entries(master):
    accounts = [vz.Account(), vz.Account()]
    payload = keys_payload(master, accounts)
    lst, entries = parse_keys(payload)
    assert lst == parse_master(payload["master"])
    assert entries == payload["devices"]


def test_keys_with_4_entries_parse(master):
    accounts = [vz.Account() for _ in range(4)]
    assert len(parse_keys(keys_payload(master, accounts))[1]) == 4


def test_keys_with_more_than_4_entries_do_not_parse(master):
    accounts = [vz.Account() for _ in range(4)]
    payload = keys_payload(master, accounts)
    payload["devices"].append(payload["devices"][0])
    with pytest.raises(InvalidBlock):
        parse_keys(payload)


def test_keys_keep_the_first_entry_per_device_key(master):
    a, b = vz.Account(), vz.Account()
    first = keys_payload(master, [a, b])
    again = keys_payload(master, [a])["devices"][0]
    _, entries = parse_keys({**first, "devices": first["devices"] + [again]})
    assert entries == first["devices"]


def test_keys_with_no_entry_parse(master):
    # A listed device grappa has no key left for is simply not reachable now.
    payload = keys_payload(master, [], listed=keys(1))
    assert parse_keys(payload)[1] == []


def test_keys_with_an_invalid_master_block_do_not_parse(master):
    payload = keys_payload(master, [vz.Account()])
    payload["master"]["list"]["ver"] = 2
    with pytest.raises(InvalidBlock):
        parse_keys(payload)


@pytest.mark.parametrize("mangle", [
    lambda p: {k: v for k, v in p.items() if k != "devices"},
    lambda p: {k: v for k, v in p.items() if k != "master"},
    lambda p: {**p, "devices": {}},
    lambda p: {**p, "devices": [None]},
    lambda p: {**p, "devices": [{"id": p["devices"][0]["id"]}]},
    lambda p: {**p, "devices": [{"otk": p["devices"][0]["otk"]}]},
    lambda p: {**p, "devices": [{**p["devices"][0], "id": []}]},
    lambda p: {**p, "devices": [{**p["devices"][0], "otk": {"key": 7}}]},
    lambda p: {**p, "devices": [{**p["devices"][0],
                                 "id": {**p["devices"][0]["id"], "ed25519": 7}}]},
])
def test_malformed_keys_do_not_parse(master, mangle):
    with pytest.raises(InvalidBlock):
        parse_keys(mangle(keys_payload(master, [vz.Account()])))


# --- the stored list (trust rule 3) and revocation (rule 5) ----------------

def lst(master, ver, devs):
    return parse_master(sign_master(master, ver, devs))


def test_a_new_book_holds_its_first_list(master):
    devs = keys(2)
    book = Book.first(lst(master, 3, devs))
    assert book.master == m_key(master)
    assert book.ver == 3
    assert all(book.listed(k) for k in devs)
    assert not any(book.revoked(k) for k in devs)


def test_a_higher_version_replaces_the_list_and_revokes_what_it_drops(master):
    a, b, c = keys(3)
    book = Book.first(lst(master, 1, [a, b]))
    change, revoked = book.apply(lst(master, 2, [a, c]))
    assert change is Change.REPLACED and revoked == {b}
    assert book.ver == 2
    assert book.listed(a) and book.listed(c) and not book.listed(b)
    assert book.revoked(b) and not book.revoked(a) and not book.revoked(c)


def test_a_key_added_later_and_dropped_is_revoked(master):
    a, b = keys(2)
    book = Book.first(lst(master, 1, [a]))
    book.apply(lst(master, 2, [a, b]))
    assert book.apply(lst(master, 3, [a])) == (Change.REPLACED, {b})
    assert book.revoked(b)


def test_the_same_version_and_keys_change_nothing(master):
    a, b = keys(2)
    book = Book.first(lst(master, 2, [a, b]))
    assert book.apply(lst(master, 2, [a, b])) == (Change.SAME, set())


def test_the_same_version_with_other_keys_is_ignored(master):
    a, b, c = keys(3)
    book = Book.first(lst(master, 2, [a, b]))
    assert book.apply(lst(master, 2, [a, c])) == (Change.CONFLICT, set())
    assert book.listed(b) and not book.listed(c) and not book.revoked(b)


def test_a_lower_version_is_stale(master):
    a, b = keys(2)
    book = Book.first(lst(master, 5, [a]))
    assert book.apply(lst(master, 4, [a, b])) == (Change.STALE, set())
    assert book.ver == 5 and not book.listed(b)


def test_a_device_listed_again_is_no_longer_revoked(master):
    a, b = keys(2)
    book = Book.first(lst(master, 1, [a, b]))
    book.apply(lst(master, 2, [a]))
    change, revoked = book.apply(lst(master, 3, [a, b]))
    assert change is Change.REPLACED and revoked == set()
    assert book.listed(b) and not book.revoked(b)


def test_a_key_never_listed_is_neither_listed_nor_revoked(master):
    a, stranger = keys(2)
    book = Book.first(lst(master, 1, [a]))
    assert not book.listed(stranger) and not book.revoked(stranger)


def test_a_book_takes_only_its_own_masters_lists(master):
    book = Book.first(lst(master, 1, keys(1)))
    with pytest.raises(ValueError):
        book.apply(lst(vz.Account(), 2, keys(1)))


# --- devices under a master and the fan-out -------------------------------

def bound(master, n, ver=1):
    """A book whose n listed devices all have a curve."""
    accounts = [vz.Account() for _ in range(n)]
    eds = [a.ed25519_key.to_base64() for a in accounts]
    book = Book.first(lst(master, ver, eds))
    for a in accounts:
        book.bind(id_block(a, m_key(master)), proven=False, cert=None)
    return book, accounts


def ed(account):
    return account.ed25519_key.to_base64()


def curve(account):
    return account.curve25519_key.to_base64()


def test_targets_are_the_listed_devices_with_a_curve(master):
    a, b, c = vz.Account(), vz.Account(), vz.Account()
    book = Book.first(lst(master, 1, sorted([ed(a), ed(b), ed(c)])))
    book.bind(id_block(a, m_key(master)), proven=False, cert=None)
    book.bind(id_block(c, m_key(master)), proven=True, cert=None)
    assert {d.ed25519 for d in book.targets()} == {ed(a), ed(c)}


def test_targets_go_to_the_most_recently_heard_device_first(master):
    book, (a, b, c, d) = bound(master, 4)
    book.heard(ed(c), 100.0)
    book.heard(ed(a), 200.0)
    order = [x.ed25519 for x in book.targets()]
    assert order[:2] == [ed(a), ed(c)]
    assert order[2:] == sorted([ed(b), ed(d)])      # never heard: in key order


def test_a_revoked_device_is_no_target_and_its_curve_is_remembered(master):
    book, (a, b) = bound(master, 2)
    book.apply(lst(master, 2, [ed(a)]))
    assert [x.ed25519 for x in book.targets()] == [ed(a)]
    assert book.revoked_curve(curve(b))
    assert not book.revoked_curve(curve(a))
    assert book.device_for_curve(curve(b)) is None


def test_device_for_curve_finds_only_listed_devices(master):
    book, (a,) = bound(master, 1)
    assert book.device_for_curve(curve(a)).ed25519 == ed(a)
    assert book.device_for_curve(curve(vz.Account())) is None


def test_bind_takes_an_unlisted_device_its_master_certified(master):
    book, (a,) = bound(master, 1)
    b = vz.Account()                           # paired after the list we hold
    d = book.bind(id_block(b, m_key(master)), proven=True, cert=sign_cert(master, ed(b)))
    assert d.certified and not book.listed(ed(b))
    assert {x.ed25519 for x in book.targets()} == {ed(a), ed(b)}
    assert book.device_for_curve(curve(b)).ed25519 == ed(b)


def test_bind_refuses_a_cert_that_does_not_verify(master):
    book, _ = bound(master, 1)
    b = vz.Account()
    with pytest.raises(ValueError):
        book.bind(id_block(b, m_key(master)), proven=True, cert=sign_cert(vz.Account(), ed(b)))
    assert book.device(ed(b)) is None


def test_a_revoked_device_is_not_trusted_on_its_cert(master):
    book, (a, b) = bound(master, 2)
    book.apply(lst(master, 2, [ed(a)]))
    with pytest.raises(ValueError):
        book.bind(id_block(b, m_key(master)), proven=True, cert=sign_cert(master, ed(b)))
    assert ed(b) not in {x.ed25519 for x in book.targets()}


def test_a_certified_device_dropped_by_a_later_list_is_revoked(master):
    book, (a,) = bound(master, 1)
    b = vz.Account()
    book.bind(id_block(b, m_key(master)), proven=True, cert=sign_cert(master, ed(b)))
    book.apply(lst(master, 2, sorted([ed(a), ed(b)])))
    book.apply(lst(master, 3, [ed(a)]))
    assert book.revoked(ed(b))
    assert [x.ed25519 for x in book.targets()] == [ed(a)]


def test_bind_takes_only_a_listed_device(master):
    book, _ = bound(master, 1)
    with pytest.raises(ValueError):
        book.bind(id_block(vz.Account(), m_key(master)), proven=False, cert=None)


def test_bind_takes_only_an_id_block_signed_for_its_master(master):
    a = vz.Account()
    book = Book.first(lst(master, 1, [ed(a)]))
    with pytest.raises(ValueError):
        book.bind(id_block(a, m_key(vz.Account())), proven=False, cert=None)
    with pytest.raises(ValueError):
        book.bind({**id_block(a, m_key(master)), "curve25519": curve(vz.Account())},
                  proven=False, cert=None)
    assert book.targets() == []


def test_bind_keeps_the_first_curve_and_records_a_proof(master):
    book, (a,) = bound(master, 1)
    # a's own key signing a second curve for itself: the first one stays
    other = vz.Account().curve25519_key.to_base64()
    forged = {"curve25519": other, "ed25519": ed(a),
              "sig": a.sign(("irc-e2e:v2:id:" + other + ":" + m_key(master)).encode()).to_base64()}
    with pytest.raises(ValueError):
        book.bind(forged, proven=True, cert=None)
    book.bind(id_block(a, m_key(master)), proven=True, cert=None)
    assert book.device(ed(a)).proven
    assert book.device(ed(a)).curve25519 == curve(a)


def test_a_proof_is_never_taken_back(master):
    book, (a,) = bound(master, 1)
    book.bind(id_block(a, m_key(master)), proven=True, cert=None)
    book.bind(id_block(a, m_key(master)), proven=False, cert=None)
    assert book.device(ed(a)).proven


def test_heard_on_an_unbound_device_is_ignored(master):
    book, (a,) = bound(master, 1)
    book.heard(ed(vz.Account()), 5.0)
    assert book.targets()[0].heard_at is None


def test_a_book_survives_a_round_trip(master):
    book, (a, b, c) = bound(master, 3)
    book.heard(ed(b), 42.0)
    book.bind(id_block(a, m_key(master)), proven=True, cert=None)
    book.apply(lst(master, 2, sorted([ed(a), ed(b)])))
    again = Book.from_doc(book.to_doc())
    assert again.master == book.master and again.ver == 2
    assert [d for d in again.targets()] == [d for d in book.targets()]
    assert again.revoked(ed(c)) and again.revoked_curve(curve(c))
    assert again.device(ed(a)).proven
    d = vz.Account()
    book.bind(id_block(d, m_key(master)), proven=True, cert=sign_cert(master, ed(d)))
    assert Book.from_doc(book.to_doc()).device(ed(d)).certified
