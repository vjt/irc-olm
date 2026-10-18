import os

import pytest

from irc_olm.pins import PinsError, load_pins, parse_pins, pins_writable

KEY = "Y3E1/yaaT7cNiOsD0+Xlzctrb2YJM/WU7oUdRYuJ2GE"


def test_parse_pins_reads_nick_key_lines_and_skips_comments():
    assert parse_pins(f"# vjt's cicchetto\n\nvjt {KEY}\n") == {"vjt": KEY}


@pytest.mark.parametrize("text", [
    f"vjt {KEY} extra",
    "vjt",
    f"vjt {KEY}=",                    # padded
    f"vjt {KEY[:-1]}",                # short
    f"vjt {KEY[:-1]}*",               # not base64
    f"vjt {KEY}\nVJT {KEY}",          # pinned twice (ascii fold)
])
def test_parse_pins_refuses_malformed_lines(text):
    with pytest.raises(PinsError):
        parse_pins(text)


def test_load_and_writability(tmp_path):
    p = tmp_path / "pins"
    p.write_text(f"vjt {KEY}\n")
    assert load_pins(p) == {"vjt": KEY}
    assert pins_writable(p)          # ours, in a directory we own: the warning case
