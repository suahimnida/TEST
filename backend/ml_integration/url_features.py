import math
import re
from collections import Counter
from urllib.parse import urlsplit

import numpy as np

SUSPICIOUS_KEYWORDS = (
    "login", "verify", "secure", "account", "update", "confirm", "banking", "signin",
    "webscr", "password", "auth", "wallet", "bonus", "unlock", "suspend", "billing",
)
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "bitly.com", "cutt.ly", "rebrand.ly", "shorturl.at", "me2.do", "han.gl", "url.kr", "vo.la",
}
TWO_LEVEL_SUFFIXES = {
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr", "ms.kr", "hs.kr", "es.kr",
    "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.au", "com.cn", "com.br", "co.in", "com.tw", "com.hk", "com.sg", "com.tr", "com.mx",
}
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_SCHEME = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://")


def split_url(raw: str) -> dict:
    raw = str(raw).strip()
    m = _SCHEME.match(raw)
    scheme = m.group(1) if m else ""
    try:
        parts = urlsplit(raw if m else "//" + raw)
        netloc = parts.netloc
        path, query = parts.path, parts.query
    except ValueError:
        netloc, path, query = raw[len(m.group(0)):] if m else raw, "", ""
    host = netloc.rsplit("@", 1)[-1]
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif ":" in host:
        host = host.split(":", 1)[0]
    return {"raw": raw, "scheme": scheme, "netloc": netloc, "host": host, "path": path, "query": query}


def strip_www(host: str) -> str:
    return host[4:] if host.lower().startswith("www.") else host


def registered_domain(host: str) -> str:
    h = host.lower().strip(".")
    if _IPV4.match(h):
        return h
    labels = h.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# ---- n-gram 입력 (텍스트) ----


def text_raw(urls) -> list:
    return [split_url(u)["raw"] for u in urls]


def text_normalized(urls) -> list:
    out = []
    for u in urls:
        p = split_url(u)
        rest = p["path"] + ("?" + p["query"] if p["query"] else "")
        out.append(strip_www(p["netloc"]) + rest)
    return out


def text_host(urls) -> list:
    return [strip_www(split_url(u)["host"]) for u in urls]


def text_path(urls) -> list:
    out = []
    for u in urls:
        p = split_url(u)
        out.append(p["path"] + ("?" + p["query"] if p["query"] else ""))
    return out


# ---- 구조 특징 (숫자) ----

STRUCT_NAMES = [
    "host_len", "host_labels_extra", "host_digit_ratio", "host_hyphens", "is_ip", "has_punycode",
    "is_shortener", "host_keywords", "path_len", "path_depth", "path_keywords", "query_len",
    "query_params", "has_at", "has_double_slash_in_path", "path_has_file_ext",
]
ENTROPY_HOST = ["host_entropy"]
ENTROPY_ALL = ["host_entropy", "path_entropy", "url_entropy"]


def _struct_row(u: str) -> list:
    p = split_url(u)
    host = strip_www(p["host"]).lower()
    reg = registered_domain(host)
    path, query = p["path"], p["query"]
    lower_path = (path + "?" + query).lower()
    digits = sum(ch.isdigit() for ch in host)
    return [
        len(host),
        max(len(host.split(".")) - len(reg.split(".")), 0),
        digits / len(host) if host else 0.0,
        host.count("-"),
        int(bool(_IPV4.match(host))),
        int("xn--" in host),
        int(reg in SHORTENERS or host in SHORTENERS),
        sum(k in host for k in SUSPICIOUS_KEYWORDS),
        len(path),
        path.count("/") - (1 if path.startswith("/") else 0),
        sum(k in lower_path for k in SUSPICIOUS_KEYWORDS),
        len(query),
        query.count("&") + (1 if query else 0),
        int("@" in p["netloc"] or "@" in path),
        int("//" in path),
        int(bool(re.search(r"\.(php|html?|aspx?|jsp|cgi|exe|zip|apk)$", path.lower()))),
    ]


def struct_features(urls) -> np.ndarray:
    return np.array([_struct_row(u) for u in urls], dtype=float)


def entropy_host(urls) -> np.ndarray:
    return np.array([[entropy(strip_www(split_url(u)["host"]).lower())] for u in urls])


def entropy_all(urls) -> np.ndarray:
    rows = []
    for u in urls:
        p = split_url(u)
        host = strip_www(p["host"]).lower()
        rows.append([entropy(host), entropy(p["path"] + p["query"]), entropy(host + p["path"] + p["query"])])
    return np.array(rows)


def calibrate(raw: float, suspicious: float, phishing: float) -> float:
    if raw < suspicious:
        return 30 * raw / suspicious
    if raw < phishing:
        return 30 + 30 * (raw - suspicious) / (phishing - suspicious)
    return 60 + 40 * (raw - phishing) / (100 - phishing) if phishing < 100 else 100.0
