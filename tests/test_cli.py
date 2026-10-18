from irc_olm import store
from irc_olm.__main__ import main


def test_keygen_writes_a_key_and_never_overwrites(tmp_path):
    assert main(["keygen", str(tmp_path / "k")]) == 0
    key = store.load_key(tmp_path / "k")
    assert len(key) == 32
    assert main(["keygen", str(tmp_path / "k")]) == 1
    assert store.load_key(tmp_path / "k") == key


def test_identity_prints_the_key_to_paste(tmp_path, capsys, net):
    bot = net.add("bot")
    assert main(["identity", "--state", str(bot.state_path)]) == 0
    assert capsys.readouterr().out.strip() == bot.fingerprint
    assert main(["identity", "--state", str(tmp_path / "missing.json")]) == 1
