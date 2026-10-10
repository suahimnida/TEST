import re
import sys
from pathlib import Path

_ML_DIR = Path(__file__).resolve().parents[2] / "ml_integration"
if str(_ML_DIR) not in sys.path:
    sys.path.append(str(_ML_DIR))

from preprocess import SUSPICIOUS_KEYWORDS, extract_features, safe_urlparse

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", 
    "top", "xyz", "site", "link", "club", "shop", "fun", "online", "live", "work", "cloud",
}

_TWO_LEVEL_SUFFIXES = {
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr", "ms.kr", "hs.kr", "es.kr",
    "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.au", "com.cn", "com.br", "co.in", "com.tw", "com.hk", "com.sg",
}

OFFICIAL_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me"},
    "naver": {"naver.com", "naver.net", "navercorp.com"},
    "kakao": {"kakao.com", "kakaocorp.com", "kakaobank.com", "kakaopay.com", "kakaomobility.com"},
    "coupang": {"coupang.com"},
    "google": {"google.com", "google.co.kr", "google.co.jp", "google.co.uk"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "amazon": {"amazon.com", "amazon.co.jp", "amazon.co.uk", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
}

_SHORT_REASON = {
    "suspicious": "의심 근거가 발견되었습니다.",
    "normal": "의심되는 특징이 발견되지 않았습니다.",
}


def _registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _result(reasons: list[str], notes: list[str]) -> dict:
    status = "suspicious" if reasons else "normal"
    return {"status": status, "reasons": reasons, "notes": notes or [_SHORT_REASON[status]]}


# 해킹당한 정상 사이트에 피싱 페이지를 숨길 때 자주 쓰는 폴더
CMS_DIRS = ("/wp-content/", "/wp-includes/", "/wp-admin/", "/administrator/", "/sites/default/files/",
            "/.well-known/", "/cgi-bin/")
# 워드프레스 관리 화면은 정상 사이트에도 로그인 단어가 있으므로 다른 브랜드 이름만 근거로 본다
ADMIN_DIRS = ("/wp-admin/", "/administrator/")
CREDENTIAL_WORDS = ("login", "signin", "sign-in", "logon", "verify", "verification", "account", "secure",
                    "update", "confirm", "password", "banking", "webscr", "wallet", "recovery", "unlock")
_EMBEDDED_DOMAIN = re.compile(r"/(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|co\.kr|kr|me|io))(?=[/?#]|$)")


def _path_patterns(path: str, registered: str) -> list[str]:
    reasons = []
    lower = path.lower()
    tokens = set(re.split(r"[^a-z0-9]+", lower))  # 'accounting'이 'account'로 잡히지 않도록 단어 단위로 비교
    brands = [b for b, official in OFFICIAL_DOMAINS.items() if b in tokens and registered not in official]
    words = [w for w in CREDENTIAL_WORDS if w in tokens]

    for cms in CMS_DIRS:
        if cms not in lower:
            continue
        after = set(re.split(r"[^a-z0-9]+", lower.split(cms, 1)[1]))
        if cms not in ADMIN_DIRS and any(w in after for w in CREDENTIAL_WORDS):
            found = [w for w in CREDENTIAL_WORDS if w in after][:3]
            reasons.append(
                f"사이트 관리용 폴더({cms.strip('/')}) 아래에 로그인·인증 경로({', '.join(found)})가 있습니다. "
                "해킹당한 정상 사이트에 피싱 페이지를 숨기는 전형적인 형태입니다."
            )
        elif brands:
            reasons.append(f"사이트 관리용 폴더({cms.strip('/')}) 아래에 다른 브랜드 이름('{brands[0]}')이 있습니다.")
        break

    if brands and words and not reasons:
        reasons.append(f"경로에 '{brands[0]}' 브랜드 이름과 로그인·인증 단어({words[0]})가 함께 있지만 공식 도메인이 아닙니다.")

    for embedded in _EMBEDDED_DOMAIN.findall(lower):
        if _registered_domain(embedded) != registered and any(_registered_domain(embedded) in o for o in OFFICIAL_DOMAINS.values()):
            reasons.append(f"경로 안에 다른 공식 도메인({embedded})이 들어 있어 진짜 주소처럼 보이게 합니다.")
            break
    return reasons


def _analyze_url(url: str, host: str, feats: dict, registered: str, official: bool) -> dict:
    reasons, notes = [], []
    if feats["is_ip_domain"]:
        reasons.append(f"도메인 이름 대신 IP 주소({host})를 사용합니다.")
    if feats["count_at"]:
        reasons.append("URL에 '@'가 있어, 앞부분과 다른 주소로 이동할 수 있습니다.")
    if feats["has_punycode"]:
        reasons.append("퓨니코드(xn--) 도메인으로, 비슷하게 생긴 문자로 정상 사이트를 흉내 낼 수 있습니다.")
    if feats["is_shortener"]:
        reasons.append("단축 URL이라 실제로 이동할 주소가 가려져 있습니다.")

    host_keywords = [] if official else [kw for kw in SUSPICIOUS_KEYWORDS if kw in host]
    if len(host_keywords) >= 2:
        reasons.append(f"도메인에 의심 키워드 {len(host_keywords)}개({', '.join(host_keywords)})가 들어 있습니다.")
    elif host_keywords:
        notes.append(f"도메인에 의심 키워드 '{host_keywords[0]}'가 들어 있습니다.")

    dash = registered.replace("xn--", "").count("-")
    if dash >= 3:
        reasons.append(f"도메인 이름({registered})에 하이픈(-)이 {dash}개 있어 여러 단어를 이어 붙인 형태입니다.")
    elif dash == 2:
        notes.append(f"도메인 이름({registered})에 하이픈(-)이 2개 있습니다.")

    if not official:
        parsed = safe_urlparse(url)
        reasons += _path_patterns(parsed.path + ("?" + parsed.query if parsed.query else ""), registered)

    notes.append(f"URL 길이 {feats['url_length']}자, 경로 길이 {feats['path_length']}자")
    return _result(reasons, notes)


def _analyze_url_stats(host: str, feats: dict) -> dict:
    reasons, notes = [], []
    host_digits = sum(c.isdigit() for c in host)
    host_digit_ratio = host_digits / len(host) if host else 0.0

    if feats["host_entropy"] >= 4.2:
        reasons.append(f"도메인 문자 엔트로피가 {feats['host_entropy']}로 높아, 무작위로 만든 이름일 수 있습니다.")
    if feats["host_length"] >= 40:
        reasons.append(f"도메인 길이가 {feats['host_length']}자로 매우 깁니다.")
    if not feats["is_ip_domain"] and not feats["has_punycode"] and host_digit_ratio >= 0.2:
        reasons.append(f"도메인의 {host_digit_ratio:.0%}가 숫자입니다.")

    notes.append(
        f"도메인 길이 {feats['host_length']}자, 도메인 엔트로피 {feats['host_entropy']}, "
        f"URL 엔트로피 {feats['url_entropy']}"
    )
    grams = [feats[k] for k in ("top_3gram_1", "top_3gram_2", "top_3gram_3") if feats.get(k)]
    if grams:
        notes.append(f"자주 나온 3글자 조합: {', '.join(grams)}")
    return _result(reasons, notes)


def _analyze_domain(url: str, host: str, feats: dict, registered: str) -> dict:
    reasons, notes = [], []
    if feats["is_ip_domain"]:
        return {
            "status": "suspicious",
            "reasons": ["도메인 이름 없이 IP 주소로 접속하는 사이트입니다."],
            "notes": [],
        }

    tld = registered.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"'.{tld}'는 피싱 사이트에 자주 쓰이는 최상위 도메인입니다.")

    tokens = set(re.split(r"[.\-]", host.rsplit(".", 1)[0]))
    for brand, officials in OFFICIAL_DOMAINS.items():
        if brand in tokens and registered not in officials:
            reasons.append(
                f"'{brand}' 브랜드명을 쓰지만 공식 도메인({', '.join(sorted(officials))})이 아닙니다."
            )

    sub_labels = host[: -len(registered)].rstrip(".").split(".") if host != registered else []
    sub_labels = [s for s in sub_labels if s and s != "www"]
    if len(sub_labels) >= 3:
        reasons.append(f"서브도메인이 {len(sub_labels)}단계로 깊습니다 ({'.'.join(sub_labels)}).")

    if url.strip().lower().startswith("http://"):
        notes.append("HTTPS가 아닌 HTTP 주소입니다. 입력한 정보가 암호화되지 않을 수 있습니다.")
    notes.append(f"등록 도메인: {registered}")
    notes.append("인증서 기록은 평판 신호에서 확인합니다. 리디렉션은 사이트에 접속해야 알 수 있어 확인하지 않았습니다.")
    return _result(reasons, notes)


def analyze(url: str) -> dict:
    feats = extract_features(url)
    host = (safe_urlparse(url).hostname or "").lower().strip(".")
    registered = host if feats["is_ip_domain"] else _registered_domain(host)
    official = any(registered in o for o in OFFICIAL_DOMAINS.values())

    # 페이지 내용(HTML·이미지)은 사이트에 접속해야 알 수 있어 분석하지 않는다. 그런 항목을 "분석되지 않음"으로
    # 늘 보여 주면 분석하는 것처럼 보이므로 아예 보내지 않고, 결과 화면 맨 위의 분석 범위 안내에서 밝힌다
    return {
        "url": _analyze_url(url, host, feats, registered, official),
        "url_stats": _analyze_url_stats(host, feats),
        "domain": _analyze_domain(url, host, feats, registered),
    }
