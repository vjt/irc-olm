import irc_olm


def test_version_matches_pyproject():
    import pathlib
    import re

    text = (pathlib.Path(__file__).parent.parent / "pyproject.toml").read_text()
    assert re.search(r'^version = "([^"]+)"', text, re.M).group(1) == irc_olm.__version__
