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
    d = _data_dir()
    with open(d / "urls.json", encoding="utf-8") as f:
        urls = frozenset(_normalize_url(u) for u in json.load(f))
    with open(d / "hosts.json", encoding="utf-8") as f:
        hosts = frozenset(h.strip().lower() for h in json.load(f))
    return urls, hosts


def _normalize_url(url: str) -> str:
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
