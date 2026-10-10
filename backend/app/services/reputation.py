import ipaddress
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx

from app.services.allowlist import _is_user_content
from url_features import registered_domain, split_url

logger = logging.getLogger(__name__)
# 평판 조회 한 번에 요청 로그가 여러 줄 찍혀 배포 로그가 지저분해진다 (Claude·OpenAI 호출은 httpx2라 영향 없음)
logging.getLogger("httpx").setLevel(logging.WARNING)

TIMEOUT = 4.0  # 각 조회의 시간 제한 (초)
CACHE_SECONDS = 24 * 3600
NEW_DOMAIN_DAYS = 30  # 이보다 최근에 등록·발급되면 의심 근거
YOUNG_DOMAIN_DAYS = 365

RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
CRT_SH = "https://crt.sh/"
DOH = "https://cloudflare-dns.com/dns-query"

_cache: dict = {}
_cache_lock = threading.Lock()
_bootstrap: dict = {}


def enabled() -> bool:
    return os.environ.get("REPUTATION_ENABLED", "1") != "0"


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, follow_redirects=True, headers={"User-Agent": "phishing-url-checker/1.0"})


def _parse_date(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _days_since(dt: datetime) -> int:
    return max((datetime.now(timezone.utc) - dt).days, 0)


# ---------------------------------------------------------------------------
# 도메인 등록일 (RDAP)
# ---------------------------------------------------------------------------


def _rdap_base(tld: str, client) -> str | None:
    if "services" not in _bootstrap:
        data = client.get(RDAP_BOOTSTRAP).json()
        _bootstrap["services"] = {t: urls[0] for tlds, urls in data["services"] for t in tlds}
    return _bootstrap["services"].get(tld)


def rdap_lookup(domain: str, client) -> dict:
    tld = domain.rsplit(".", 1)[-1]
    base = _rdap_base(tld, client)
    if not base:
        return {"status": "unsupported", "note": f"'.{tld}'은(는) RDAP 조회를 지원하지 않아 등록일을 확인하지 못했습니다."}
    resp = client.get(base.rstrip("/") + "/domain/" + domain)
    if resp.status_code == 404:
        return {"status": "not_found"}
    resp.raise_for_status()
    events = {e.get("eventAction"): _parse_date(e.get("eventDate")) for e in resp.json().get("events", [])}
    created = events.get("registration")
    if not created:
        return {"status": "unknown"}
    return {"status": "ok", "created": created.date().isoformat(), "age_days": _days_since(created)}


# ---------------------------------------------------------------------------
# 인증서 첫 발급일 (CT 로그)
# ---------------------------------------------------------------------------


def ct_lookup(domain: str, client) -> dict:
    resp = client.get(CRT_SH, params={"q": domain, "output": "json"})
    resp.raise_for_status()
    certs = resp.json() if resp.text.strip() else []
    dates = [d for d in (_parse_date(c.get("not_before")) for c in certs) if d]
    if not dates:
        return {"status": "none"}
    first = min(dates)
    issuers = {c.get("issuer_name", "") for c in certs}
    return {"status": "ok", "first_issued": first.date().isoformat(), "age_days": _days_since(first),
            "count": len(certs), "lets_encrypt_only": all("Let's Encrypt" in i for i in issuers if i)}


# ---------------------------------------------------------------------------
# 호스팅 정보 (DNS → ASN)
# ---------------------------------------------------------------------------


def _doh(name: str, rtype: str, client) -> dict:
    resp = client.get(DOH, params={"name": name, "type": rtype}, headers={"accept": "application/dns-json"})
    resp.raise_for_status()
    return resp.json()


def hosting_lookup(host: str, client) -> dict:
    try:
        ip = str(ipaddress.ip_address(host))
    except ValueError:
        answer = _doh(host, "A", client)
        if answer.get("Status") == 3:  # NXDOMAIN
            return {"status": "nxdomain"}
        ips = [a["data"] for a in answer.get("Answer", []) if a.get("type") == 1]
        if not ips:
            return {"status": "no_address"}
        ip = ips[0]
    if ipaddress.ip_address(ip).version != 4:
        return {"status": "ok", "ip": ip}

    reversed_ip = ".".join(reversed(ip.split(".")))
    origin = _doh(f"{reversed_ip}.origin.asn.cymru.com", "TXT", client)
    txt = [a["data"].strip('"') for a in origin.get("Answer", []) if a.get("type") == 16]
    if not txt:
        return {"status": "ok", "ip": ip}
    asn, _, country = [p.strip() for p in txt[0].split("|")][:3]
    asn = asn.split()[0]
    name_txt = _doh(f"AS{asn}.asn.cymru.com", "TXT", client)
    names = [a["data"].strip('"') for a in name_txt.get("Answer", []) if a.get("type") == 16]
    as_name = names[0].split("|")[-1].strip() if names else ""
    return {"status": "ok", "ip": ip, "asn": f"AS{asn}", "as_name": as_name, "country": country}


# ---------------------------------------------------------------------------
# 조회 묶음과 근거 문장
# ---------------------------------------------------------------------------


def _safe(fn, *args) -> dict:
    try:
        return fn(*args)
    except Exception as error:  # 외부 서비스 장애는 "확인 불가"로 처리하고 분석은 계속한다
        logger.info("평판 조회 실패 %s: %s", fn.__name__, type(error).__name__)
        return {"status": "error"}


def lookup(url: str) -> dict:
    host = split_url(url)["host"].lower().strip(".")
    if not host:
        return {}
    domain = registered_domain(host)
    platform = _is_user_content(host)
    key = (host, domain)
    with _cache_lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < CACHE_SECONDS:
            return hit[1]

    is_ip = host.replace(".", "").isdigit()
    with _client() as client, ThreadPoolExecutor(max_workers=3) as pool:
        rdap = pool.submit(_safe, rdap_lookup, domain, client) if not (platform or is_ip) else None
        ct = pool.submit(_safe, ct_lookup, domain, client) if not (platform or is_ip) else None
        hosting = pool.submit(_safe, hosting_lookup, host, client)
        result = {
            "domain": domain,
            "platform": platform,
            "rdap": rdap.result() if rdap else {"status": "skipped"},
            "ct": ct.result() if ct else {"status": "skipped"},
            "hosting": hosting.result(),
        }
    with _cache_lock:
        _cache[key] = (time.time(), result)
    return result


def to_detection(info: dict) -> dict | None:
    if not info:
        return None
    reasons, notes = [], []
    rdap, ct, hosting = info["rdap"], info["ct"], info["hosting"]

    if info["platform"]:
        notes.append("누구나 하위 주소를 만들 수 있는 서비스라 도메인 등록일과 인증서는 판단 근거로 쓰지 않았습니다.")

    if rdap["status"] == "ok":
        days = rdap["age_days"]
        if days <= NEW_DOMAIN_DAYS:
            reasons.append(f"도메인이 {days}일 전({rdap['created']})에 등록됐습니다. 새로 만든 도메인은 피싱에 자주 쓰입니다.")
        elif days <= YOUNG_DOMAIN_DAYS:
            notes.append(f"도메인 등록일: {rdap['created']} ({days}일 전, 1년 이내)")
        else:
            notes.append(f"도메인 등록일: {rdap['created']} (약 {days // 365}년 전)")
    elif rdap["status"] == "not_found":
        notes.append("등록 정보가 없습니다. 만료됐거나 등록되지 않은 도메인일 수 있습니다.")
    elif rdap["status"] == "unsupported":
        notes.append(rdap["note"])
    elif rdap["status"] != "skipped":
        notes.append("도메인 등록일을 확인하지 못했습니다.")

    if ct["status"] == "ok":
        if ct["age_days"] <= NEW_DOMAIN_DAYS:
            reasons.append(f"이 도메인의 첫 인증서가 {ct['age_days']}일 전({ct['first_issued']})에 발급됐습니다.")
        else:
            notes.append(f"첫 인증서 발급일: {ct['first_issued']} (인증서 기록 {ct['count']}건)")
    elif ct["status"] == "none":
        notes.append("인증서 투명성 로그에 인증서 기록이 없습니다. HTTPS를 쓰지 않는 사이트일 수 있습니다.")
    elif ct["status"] != "skipped":
        notes.append("인증서 기록을 확인하지 못했습니다.")

    if hosting["status"] == "nxdomain":
        reasons.append("DNS에 도메인이 존재하지 않습니다. 이미 차단됐거나 만료된 피싱 도메인에서 자주 나타납니다.")
    elif hosting["status"] == "ok":
        where = f"{hosting.get('asn', '')} {hosting.get('as_name', '')}".strip()
        notes.append(f"호스팅: {where or '확인 불가'} (IP {hosting['ip']}{', ' + hosting['country'] if hosting.get('country') else ''})")
    elif hosting["status"] == "no_address":
        notes.append("DNS에 IP 주소가 없습니다.")
    else:
        notes.append("호스팅 정보를 확인하지 못했습니다.")

    checked = [x for x in (rdap, ct, hosting) if x["status"] not in ("error", "skipped")]
    status = "suspicious" if reasons else ("normal" if checked else "not_analyzed")
    notes.append("평판 신호는 참고 근거이며 최종 점수에는 반영하지 않습니다.")
    return {"status": status, "reasons": reasons, "notes": notes}
