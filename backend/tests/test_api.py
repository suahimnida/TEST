import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.schemas import BlacklistResult, ModelResult
from app.services import blacklist, model, rag

client = TestClient(app)


def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_create_analysis_returns_stub(monkeypatch):
    monkeypatch.setattr(model, "predict", lambda url: ModelResult(status="not_ready"))

    res = client.post("/api/v1/analyses", json={"url": "https://example.com"})
    assert res.status_code == 200
    body = res.json()
    assert body["id"]
    assert body["status"] == "completed"
    assert body["url"] == "https://example.com"
    for key in ["verdict", "confidence", "risk_score", "risk_level"]:
        assert body[key] is None
    assert set(body["detections"]) == {"url", "url_stats", "domain", "html", "image", "reputation"}
    assert body["detections"]["reputation"] is None  # 테스트에서는 외부 조회를 끈다
    assert body["detections"]["url"]["status"] == "normal"
    assert body["detections"]["html"]["status"] == "not_analyzed"
    assert body["ai_analysis"] == {"summary": None, "reasons": []}
    assert body["extracted_features"] == {}
    assert body["similar_cases"] == []
    assert body["blacklist"] == {"matched": False, "match_type": "none", "source": "KISA 2024"}
    assert body["rag"] == {"matched": False, "source": [], "evidence": None}
    assert body["model"] == {"status": "not_ready", "risk_score": None, "label": None}


def test_create_analysis_fills_model_field(monkeypatch):
    fake = ModelResult(status="ready", risk_score=83.2, label="phishing")
    monkeypatch.setattr(model, "predict", lambda url: fake)

    body = client.post("/api/v1/analyses", json={"url": "http://evil.tk/x"}).json()
    assert body["model"] == {"status": "ready", "risk_score": 83.2, "label": "phishing"}
    assert body["verdict"] == "phishing"
    assert body["risk_score"] == 83.2
    assert body["risk_level"] == "warning"


def test_blacklist_match_skips_rag_and_model(monkeypatch):
    def must_not_run(url):
        raise AssertionError("블랙리스트 매치 시 실행되면 안 됨")

    monkeypatch.setattr(
        blacklist,
        "check_blacklist",
        lambda url: BlacklistResult(matched=True, match_type="host", source="KISA 2024"),
    )
    monkeypatch.setattr(rag, "explain", must_not_run)
    monkeypatch.setattr(model, "predict", must_not_run)

    body = client.post("/api/v1/analyses", json={"url": "http://evil.tk/x"}).json()
    assert body["verdict"] == "phishing"
    assert body["risk_score"] == 100.0
    assert body["risk_level"] == "danger"
    assert body["model"]["status"] == "not_ready"


def test_create_analysis_fills_rag_fields(monkeypatch):
    fake = rag.RagResult(
        verdict="phishing",
        confidence=0.9,
        summary="근거 요약",
        features={"url_length": 20},
        similar_cases=[{"url": "http://evil.tk", "label": 1, "similarity": 0.91}],
        reference={"matched": True, "source": ["KISA 가이드"], "evidence": "문서 근거"},
    )
    monkeypatch.setattr(rag, "explain", lambda url: fake)

    body = client.post("/api/v1/analyses", json={"url": "http://evil.tk/x"}).json()
    assert body["ai_analysis"] == {"summary": "근거 요약", "reasons": []}
    assert body["extracted_features"] == {"url_length": 20}
    assert body["similar_cases"] == [{"url": "http://evil.tk", "label": 1, "similarity": 0.91}]
    assert body["rag"] == {"matched": True, "source": ["KISA 가이드"], "evidence": "문서 근거"}


def test_create_analysis_rejects_blank_url():
    res = client.post("/api/v1/analyses", json={"url": "   "})
    assert res.status_code == 422


def new_client_headers() -> dict:
    client_id = client.post("/api/v1/clients").json()["client_id"]
    return {"X-Client-Id": client_id}


def analyze(url: str, headers: dict | None = None, is_public: bool = False) -> dict:
    res = client.post("/api/v1/analyses", json={"url": url, "is_public": is_public}, headers=headers)
    assert res.status_code == 200
    return res.json()


def test_create_client_issues_new_uuid():
    first = client.post("/api/v1/clients").json()["client_id"]
    second = client.post("/api/v1/clients").json()["client_id"]
    assert uuid.UUID(first) and first != second


def test_create_analysis_is_private_by_default():
    assert analyze("https://example.com")["is_public"] is False
    assert analyze("https://example.com", is_public=True)["is_public"] is True


def test_create_analysis_rejects_invalid_client_id():
    res = client.post(
        "/api/v1/analyses", json={"url": "https://example.com"}, headers={"X-Client-Id": "abc"}
    )
    assert res.status_code == 422


def test_owner_can_read_private_result():
    headers = new_client_headers()
    created = analyze("https://example.com", headers)

    res = client.get(f"/api/v1/analyses/{created['id']}", headers=headers)
    assert res.status_code == 200
    assert res.json() == created


def test_others_cannot_read_private_result():
    created = analyze("https://example.com", new_client_headers())

    assert client.get(f"/api/v1/analyses/{created['id']}").status_code == 404
    other = new_client_headers()
    assert client.get(f"/api/v1/analyses/{created['id']}", headers=other).status_code == 404


def test_anyone_can_read_public_result():
    created = analyze("https://example.com", new_client_headers(), is_public=True)

    res = client.get(f"/api/v1/analyses/{created['id']}")
    assert res.status_code == 200
    assert res.json() == created


def test_read_analysis_unknown_id_returns_404():
    res = client.get("/api/v1/analyses/does-not-exist")
    assert res.status_code == 404


def test_list_mine_returns_only_my_records_newest_first():
    mine, other = new_client_headers(), new_client_headers()
    for url in ["https://a.com", "https://b.com", "https://c.com"]:
        analyze(url, mine)
    analyze("https://other.com", other)

    res = client.get("/api/v1/analyses", params={"scope": "mine"}, headers=mine)
    assert res.status_code == 200
    items = res.json()["items"]
    assert [item["url"] for item in items] == ["https://c.com", "https://b.com", "https://a.com"]
    assert set(items[0]) == {"id", "url", "verdict", "created_at"}


def test_list_mine_requires_client_id():
    res = client.get("/api/v1/analyses", params={"scope": "mine"})
    assert res.status_code == 400


def test_list_public_returns_only_public_records():
    headers = new_client_headers()
    analyze("https://private.com", headers)
    analyze("https://public.com", headers, is_public=True)

    res = client.get("/api/v1/analyses", params={"scope": "public"})
    assert [item["url"] for item in res.json()["items"]] == ["https://public.com"]


def test_list_requires_scope():
    assert client.get("/api/v1/analyses").status_code == 422


def test_list_analyses_respects_limit():
    headers = new_client_headers()
    for url in ["https://a.com", "https://b.com", "https://c.com"]:
        analyze(url, headers)

    res = client.get("/api/v1/analyses", params={"scope": "mine", "limit": 2}, headers=headers)
    assert [item["url"] for item in res.json()["items"]] == ["https://c.com", "https://b.com"]


def test_list_analyses_empty():
    res = client.get("/api/v1/analyses", params={"scope": "public"})
    assert res.json() == {"items": []}


def test_cors_allows_vite_dev_server():
    res = client.options(
        "/api/v1/analyses",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert res.status_code == 200
    assert res.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_rejects_unknown_origin():
    res = client.get("/health", headers={"Origin": "http://evil.com"})
    assert "access-control-allow-origin" not in res.headers


def test_list_analyses_rejects_invalid_limit():
    for limit in [0, 101]:
        res = client.get("/api/v1/analyses", params={"scope": "public", "limit": limit})
        assert res.status_code == 422
