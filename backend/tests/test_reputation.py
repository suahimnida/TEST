import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import reputation

NOW = datetime.now(timezone.utc)
DOMAINS = {  # 도메인: (등록일, 첫 인증서 발급일, DNS 상태)
    "fresh-login.xyz": (NOW - timedelta(days=5), NOW - timedelta(days=3), "ok"),
    "naver.com": (datetime(1997, 9, 12, tzinfo=timezone.utc), datetime(2014, 1, 1, tzinfo=timezone.utc), "ok"),
    "gone-phish.top": (None, None, "nxdomain"),
}


class FakeInternet:
    def __init__(self, down=False):
        self.down = down
        self.urls = []

    def __call__(self, request):
        url = str(request.url)
        self.urls.append(url)
        if self.down:
            return httpx.Response(503)
        host, path, q = request.url.host, request.url.path, dict(request.url.params)
        if host == "data.iana.org":
            return httpx.Response(200, json={"services": [[["com", "xyz", "top"], ["https://rdap.example/"]]]})
        if host == "rdap.example":
            domain = path.rsplit("/", 1)[-1]
            created = DOMAINS.get(domain, (None,))[0]
            if not created:
                return httpx.Response(404)
            return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": created.isoformat()}]})
        if host == "crt.sh":
            first = DOMAINS.get(q["q"], (None, None))[1]
            certs = [{"issuer_name": "C=US, O=Let's Encrypt, CN=R11", "not_before": first.strftime("%Y-%m-%dT%H:%M:%S")}] if first else []
            return httpx.Response(200, text=json.dumps(certs))
        if host == "cloudflare-dns.com":
            name, rtype = q["name"], q["type"]
            if rtype == "A":
                state = DOMAINS.get(".".join(name.split(".")[-2:]), (None, None, "ok"))[2]
                if state == "nxdomain":
                    return httpx.Response(200, json={"Status": 3})
                return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 1, "data": "104.16.1.1"}]})
            if name.endswith("origin.asn.cymru.com"):
                return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 16, "data": '"13335 | 104.16.0.0/12 | US | arin | 2014-03-28"'}]})
            if name.endswith("asn.cymru.com"):
                return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 16, "data": '"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"'}]})
        return httpx.Response(404)


@pytest.fixture
def internet(monkeypatch):
    fake = FakeInternet()
    monkeypatch.setattr(reputation, "_client", lambda: httpx.Client(transport=httpx.MockTransport(fake), timeout=2))
    monkeypatch.setattr(reputation, "_cache", {})
    monkeypatch.setattr(reputation, "_bootstrap", {})
    return fake


def test_new_domain_and_new_certificate_are_reasons(internet):
    det = reputation.to_detection(reputation.lookup("https://fresh-login.xyz/verify?id=1"))
    assert det["status"] == "suspicious"
    assert any("5일 전" in r for r in det["reasons"]) and any("인증서" in r for r in det["reasons"])
    assert any("AS13335 CLOUDFLARENET" in n for n in det["notes"])


def test_old_domain_is_normal(internet):
    det = reputation.to_detection(reputation.lookup("https://www.naver.com"))
    assert det["status"] == "normal" and not det["reasons"]
    assert any("1997-09-12" in n for n in det["notes"])


def test_nxdomain_is_a_reason(internet):
    det = reputation.to_detection(reputation.lookup("http://gone-phish.top/login"))
    assert any("존재하지 않습니다" in r for r in det["reasons"])


def test_only_domain_names_leave_the_server(internet):
    reputation.lookup("https://fresh-login.xyz/account/secret-token?user=hong@example.com")
    sent = " ".join(internet.urls)
    assert "secret-token" not in sent and "hong" not in sent and "account" not in sent


def test_results_are_cached(internet):
    reputation.lookup("https://fresh-login.xyz/a")
    first = len(internet.urls)
    reputation.lookup("https://fresh-login.xyz/b")
    assert len(internet.urls) == first


def test_outage_does_not_break_analysis(monkeypatch):
    fake = FakeInternet(down=True)
    monkeypatch.setattr(reputation, "_client", lambda: httpx.Client(transport=httpx.MockTransport(fake), timeout=2))
    monkeypatch.setattr(reputation, "_cache", {})
    monkeypatch.setattr(reputation, "_bootstrap", {})
    det = reputation.to_detection(reputation.lookup("https://fresh-login.xyz"))
    assert det["status"] == "not_analyzed" and not det["reasons"]


def test_platform_subdomain_skips_registration_and_certificate(internet):
    info = reputation.lookup("https://someone.github.io/login")
    assert info["rdap"]["status"] == "skipped" and info["ct"]["status"] == "skipped"
    assert not any("rdap.example" in u or "crt.sh" in u for u in internet.urls)


def test_reputation_is_shown_but_does_not_change_score(internet, monkeypatch):
    client = TestClient(app)
    headers = {"X-Client-Id": str(uuid.uuid4())}
    url = "https://fresh-login.xyz/verify"
    monkeypatch.setenv("REPUTATION_ENABLED", "0")
    without = client.post("/api/v1/analyses", json={"url": url}, headers=headers).json()
    monkeypatch.setenv("REPUTATION_ENABLED", "1")
    with_rep = client.post("/api/v1/analyses", json={"url": url}, headers=headers).json()
    assert without["detections"]["reputation"] is None
    assert with_rep["detections"]["reputation"]["status"] == "suspicious"
    assert with_rep["risk_score"] == without["risk_score"]
