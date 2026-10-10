import joblib
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas import AnalysisResponse
from app.services import followup, report

import url_explain as ue
from model_integration import MODEL_DIR

client = TestClient(app)
PHISHING = "http://m.login.secure.naver-account-verify-center.xyz/update?id=1029"


@pytest.fixture(scope="module")
def model():
    return joblib.load(f"{MODEL_DIR}/url_model_v2.joblib")


@pytest.mark.parametrize("url", [PHISHING, "naver.com", "https://github.com/a/b", "HTTPS://PaypaI-login.ex.XYZ/A?b=1"])
def test_contributions_add_up_to_model_score(model, url):
    e = ue.explain_model(model, url)
    assert e["probability"] == pytest.approx(model.predict_proba([url])[0, 1], abs=1e-4)
    total = e["intercept"] + sum(p["contribution"] for p in e["parts"])
    assert total == pytest.approx(e["logit"], abs=0.02)
    assert len(e["char_scores"]) == len(e["url"])


def test_url_segments_cover_original_text():
    raw = "HTTPS://user@www.a.b.Example.co.kr:8080/Path/x?q=1"
    parts = ue.segment_url(raw)
    assert "".join(raw[a:b] for _, a, b in parts) == raw
    names = [n for n, _, _ in parts]
    assert names == ["scheme", "사용자 정보", "www", "하위 도메인", "도메인 이름", "최상위 도메인", "포트", "경로", "쿼리"]


def test_phishing_parts_point_at_suspicious_text(model):
    e = ue.explain_model(model, PHISHING)
    by_part = {p["part"]: p for p in e["parts"]}
    assert by_part["하위 도메인"]["text"] == "m.login.secure."
    assert by_part["하위 도메인"]["contribution"] > 0
    assert e["top_risky"] and all(g["contribution"] > 0 for g in e["top_risky"])


def test_reference_positions():
    ref = {r["key"]: r for r in ue.reference(PHISHING)}
    assert ref["host_length"]["value"] == 46 and ref["host_length"]["outside_normal"]
    assert 0 <= ref["url_length"]["normal_percentile"] <= 100
    assert ue.percentile(10**6, [0.0] * 101) == 100.0


def test_api_returns_explanation_and_report_uses_it():
    body = client.post("/api/v1/analyses", json={"url": PHISHING}).json()
    exp = body["explanation"]
    assert exp["model"]["parts"] and exp["reference"]
    rep = report.generate_report(AnalysisResponse(**body), followup.research(AnalysisResponse(**body)))
    sources = [e.source for e in rep.evidence]
    assert "ML 모델 · 부분별 기여" in sources and "정상 데이터 대비" in sources


def test_blacklisted_url_has_no_model_explanation():
    url = "http://154.92.182.159/download/download.php?udid=1734568657532"
    body = client.post("/api/v1/analyses", json={"url": url}).json()
    assert body["blacklist"]["matched"] and body["explanation"]["model"] is None
