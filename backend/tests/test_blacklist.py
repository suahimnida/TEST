import json

import pytest

from app.services import blacklist


@pytest.fixture
def fake_blacklist(tmp_path, monkeypatch):
    (tmp_path / "urls.json").write_text(
        json.dumps(["evil.com/login", "Phish.KR/a/b"]), encoding="utf-8"
    )
    (tmp_path / "hosts.json").write_text(
        json.dumps(["evil.com", "phish.kr", "1.2.3.4:8080", "5.6.7.8"]), encoding="utf-8"
    )
    monkeypatch.setenv("BLACKLIST_DIR", str(tmp_path))
    blacklist.load_blacklist.cache_clear()
    yield
    blacklist.load_blacklist.cache_clear()


@pytest.mark.parametrize(
    "url, match_type",
    [
        ("evil.com/login", "exact"),
        ("https://evil.com/login", "exact"),
        ("http://EVIL.com/login/", "exact"),
        ("http://phish.kr/a/b", "exact"),
        ("https://evil.com/other", "host"),
        ("http://1.2.3.4:8080/x", "host"),
        ("http://5.6.7.8:9999/x", "host"),
        ("https://example.com", "none"),
        ("https://notevil.com/login", "none"),
    ],
)
def test_check_blacklist(fake_blacklist, url, match_type):
    result = blacklist.check_blacklist(url)
    assert result.match_type == match_type
    assert result.matched == (match_type != "none")
    assert result.source == "KISA 2024"


def test_real_files_load():
    blacklist.load_blacklist.cache_clear()
    urls, hosts = blacklist.load_blacklist()
    assert len(urls) > 0 and len(hosts) > 0
