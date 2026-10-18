import base64
import os
import stat

import pytest

from irc_olm import store


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


# --- key file ------------------------------------------------------------

def test_generate_key_writes_32_random_bytes_mode_600(tmp_path):
    p = tmp_path / "olm.key"
    store.generate_key_file(p)
    assert mode(p) == 0o600
    key = store.load_key(p)
    assert len(key) == 32
    assert base64.b64decode(p.read_text().strip()) == key
    q = tmp_path / "other.key"
    store.generate_key_file(q)
    assert store.load_key(q) != key


def test_generate_key_never_overwrites(tmp_path):
    p = tmp_path / "olm.key"
    store.generate_key_file(p)
    before = p.read_bytes()
    with pytest.raises(FileExistsError):
        store.generate_key_file(p)
    assert p.read_bytes() == before


def test_generate_key_ignores_a_permissive_umask(tmp_path):
    old = os.umask(0)
    try:
        store.generate_key_file(tmp_path / "k")
    finally:
        os.umask(old)
    assert mode(tmp_path / "k") == 0o600


@pytest.mark.parametrize("perm", [0o640, 0o604, 0o644])
def test_load_key_refuses_group_or_world_access(tmp_path, perm):
    p = tmp_path / "olm.key"
    store.generate_key_file(p)
    os.chmod(p, perm)
    with pytest.raises(store.InsecureFileError):
        store.load_key(p)


@pytest.mark.parametrize("content", ["", "not base64!", base64.b64encode(b"short").decode()])
def test_load_key_refuses_a_malformed_key(tmp_path, content):
    p = tmp_path / "olm.key"
    p.write_text(content)
    os.chmod(p, 0o600)
    with pytest.raises(store.KeyFileError):
        store.load_key(p)


# --- state file ----------------------------------------------------------

def test_missing_state_loads_as_none(tmp_path):
    assert store.StateFile(tmp_path / "s.json").load() is None


def test_state_round_trips_with_mode_600(tmp_path):
    s = store.StateFile(tmp_path / "s.json")
    s.save({"v": 1, "x": "ü"})
    assert mode(tmp_path / "s.json") == 0o600
    assert s.load() == {"v": 1, "x": "ü"}


def test_save_replaces_atomically_and_leaves_no_temp_files(tmp_path):
    s = store.StateFile(tmp_path / "s.json")
    for i in range(5):
        s.save({"v": 1, "i": i})
    assert s.load() == {"v": 1, "i": 4}
    assert sorted(os.listdir(tmp_path)) == ["s.json"]


def test_a_failed_save_keeps_the_previous_state(tmp_path):
    s = store.StateFile(tmp_path / "s.json")
    s.save({"v": 1, "ok": True})
    with pytest.raises(TypeError):
        s.save({"v": 1, "bad": object()})
    assert s.load() == {"v": 1, "ok": True}
    assert sorted(os.listdir(tmp_path)) == ["s.json"]


def test_load_refuses_a_world_readable_state(tmp_path):
    s = store.StateFile(tmp_path / "s.json")
    s.save({"v": 1})
    os.chmod(tmp_path / "s.json", 0o644)
    with pytest.raises(store.InsecureFileError):
        s.load()


def test_state_round_trips_a_lone_surrogate_whatever_the_locale(tmp_path):
    # A caller decoding IRC with surrogateescape can hand us such a nick.
    f = store.StateFile(tmp_path / "s.json")
    f.save({"nick": "vjt\udcff", "x": "é"})
    assert f.load() == {"nick": "vjt\udcff", "x": "é"}
    assert (tmp_path / "s.json").read_bytes().isascii()
