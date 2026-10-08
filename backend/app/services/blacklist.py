"""KISA 피싱사이트 블랙리스트 조회.

데이터 담당이 제공하는 urls.json / hosts.json(문자열 배열)을 그대로 읽어 조회만 한다.
파일 위치는 BLACKLIST_DIR 환경변수로 바꿀 수 있다 (기본: 프로젝트 루트).
"""

import json
import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from app.schemas import BlacklistResult

SOURCE = "KISA 2024"
_DEFAULT_DIR = Path(__file__).resolve().parents[2] / "resources" / "blacklist"


def _data_dir() -> Path:
    return Path(os.environ.get("BLACKLIST_DIR") or _DEFAULT_DIR)


@lru_cache(maxsize=1)
def load_blacklist() -> tuple[frozenset[str], frozenset[str]]:
    """(urls, hosts) 집합을 반환. 첫 호출 시 1회만 파일을 읽는다."""
    d = _data_dir()
    with open(d / "urls.json", encoding="utf-8") as f:
        urls = frozenset(_normalize_url(u) for u in json.load(f))
    with open(d / "hosts.json", encoding="utf-8") as f:
        hosts = frozenset(h.strip().lower() for h in json.load(f))
    return urls, hosts


def _normalize_url(url: str) -> str:
    """스킴과 끝의 '/'를 떼고 호스트만 소문자로 바꾼다 (urls.json 항목과 같은 형태)."""
    url = url.strip()
    if "://" in url:
        url = url.split("://", 1)[1]
    host, sep, rest = url.partition("/")
    return (host.lower() + sep + rest).rstrip("/")


def _extract_host(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    return urlsplit(url).netloc.lower()


def check_blacklist(url: str) -> BlacklistResult:
    urls, hosts = load_blacklist()

    if _normalize_url(url) in urls:
        return BlacklistResult(matched=True, match_type="exact", source=SOURCE)

    host = _extract_host(url)
    if host in hosts or host.split(":", 1)[0] in hosts:
        return BlacklistResult(matched=True, match_type="host", source=SOURCE)

    return BlacklistResult(matched=False, match_type="none", source=SOURCE)
