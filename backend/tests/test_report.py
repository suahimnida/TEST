"""후속 조치 조사(첫번째 키)와 리포트 작성(두번째 키) 테스트."""

import io
import uuid

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from app import main
from app.main import app
from app.schemas import AnalysisResponse, SimilarCase
from app.services import followup, report, report_pdf
from app.services.followup import FollowupLLM
from app.services.report import ReportLLM

client = TestClient(app)
PHISHING_URL = "http://m.login.secure.naver-account-verify-center.xyz/update?id=1029"


def analyze(url, client_id=None, is_public=False):
    client_id = client_id or str(uuid.uuid4())
    body = client.post(
        "/api/v1/analyses", json={"url": url, "is_public": is_public}, headers={"X-Client-Id": client_id}
    ).json()
    return body, client_id


class FakeLLM:
    """OpenAIJsonClient 대신 정해진 답(또는 예외)을 돌려준다. 받은 프롬프트는 prompts에 쌓인다."""

    def __init__(self, model, reply=None, error=None):
        self.model = model
        self.reply = reply
        self.error = error
        self.prompts = []

    def ask(self, system, user, schema):
        self.prompts.append(user)
        if self.error:
            raise self.error
        return schema.model_validate(self.reply)


FOLLOWUP_REPLY = {
    "research_summary": "네이버 계정 정보를 노리는 피싱으로 보입니다.",
    "priority_action_ids": ["do_not_visit", "change_password"],
    "action_notes": [{"id": "change_password", "note": "네이버 비밀번호를 먼저 바꾸세요."}],
}
REPORT_REPLY = {"summary": "네이버를 사칭한 피싱 URL입니다.", "risk_assessment": "공식 도메인이 아닙니다."}


@pytest.fixture
def analysis():
    """테스트에서는 RAG가 꺼져 있어 유사 사례를 직접 넣는다."""
    body, _ = analyze(PHISHING_URL)
    result = AnalysisResponse(**body)
    result.similar_cases = [
        SimilarCase(url="https://tp2.wordpress.example.fr/citizens-bank/login/", label=1, similarity=0.44),
        SimilarCase(url="https://www.example-shop.com", label=0, similarity=0.31),
    ]
    return result


def all_actions(result):
    return [a for g in result.action_groups for a in g.actions]


# ---- 후속 조치 조사 (첫번째 키) ----


def test_followup_uses_detections_similar_cases_and_ai_analysis(analysis):
    analysis.ai_analysis.summary = "AI 분석: 네이버 로그인 화면을 흉내 냅니다."
    llm = FakeLLM("followup-model", FOLLOWUP_REPLY)
    result = followup.research(analysis, client=llm)

    prompt = llm.prompts[0]
    assert "탐지 결과" in prompt and "'naver' 브랜드명" in prompt  # 탐지 근거
    assert "유사 사례" in prompt and analysis.similar_cases[0].url in prompt
    assert "AI 분석: 네이버 로그인 화면을 흉내 냅니다." in prompt
    assert "118" not in prompt and "1332" not in prompt  # 연락처는 넘기지 않는다

    assert result.generated_by == "followup-model"
    assert result.priority_action_ids == ["do_not_visit", "change_password"]
    assert result.action_notes == {"change_password": "네이버 비밀번호를 먼저 바꾸세요."}


def test_followup_drops_actions_not_shown_for_verdict():
    body, _ = analyze("https://www.google.com")  # 정상 판정: 예방 조치만
    reply = {**FOLLOWUP_REPLY, "priority_action_ids": ["stop_payment", "verify_official"], "action_notes": []}
    result = followup.research(AnalysisResponse(**body), client=FakeLLM("m", reply))
    assert result.priority_action_ids == ["verify_official"]


def test_followup_falls_back_to_template(analysis):
    result = followup.research(analysis, client=FakeLLM("m", error=RuntimeError("서버 오류")))
    assert result.generated_by == "template"
    assert result.priority_action_ids == ["do_not_visit", "report_site", "change_password"]
    assert followup.research(analysis, client=None).generated_by == "template"


def test_unknown_action_id_is_rejected_by_schema():
    with pytest.raises(Exception):
        FollowupLLM.model_validate({**FOLLOWUP_REPLY, "priority_action_ids": ["made_up_action"]})


# ---- 리포트 작성 (두번째 키) ----


def test_report_combines_everything(analysis):
    analysis.ai_analysis.summary = "AI 분석 설명입니다."
    research = followup.research(analysis, client=FakeLLM("followup-model", FOLLOWUP_REPLY))
    llm = FakeLLM("report-model", REPORT_REPLY)
    result = report.generate_report(analysis, research, client=llm)

    # 리포트 LLM은 후속 조치 조사 결과까지 받는다
    assert "네이버 계정 정보를 노리는 피싱" in llm.prompts[0]
    assert "AI 분석 설명입니다." in llm.prompts[0]

    assert result.generated_by == "report-model" and result.followup_by == "followup-model"
    assert result.summary == REPORT_REPLY["summary"]
    assert result.ai_analysis == "AI 분석 설명입니다."
    assert result.similar_cases == analysis.similar_cases
    assert result.followup_summary == FOLLOWUP_REPLY["research_summary"]
    assert [a.id for a in all_actions(result) if a.priority] == ["do_not_visit", "change_password"]
    assert [c.phone for c in result.contacts if c.phone] == ["118", "112", "1332"]


def test_report_template_without_llm(analysis):
    research = followup.research(analysis, client=None)
    result = report.generate_report(analysis, research, client=None)
    assert result.generated_by == "template" and result.followup_by == "template"
    assert len(result.action_groups) == 6
    sources = [e.source for e in result.evidence]
    assert "KISA 블랙리스트" in sources and "ML 모델" in sources and "유사 사례" in sources


def test_report_falls_back_when_llm_fails(analysis):
    research = followup.research(analysis, client=FakeLLM("followup-model", FOLLOWUP_REPLY))
    result = report.generate_report(analysis, research, client=FakeLLM("m", {"summary": " ", "risk_assessment": "x"}))
    assert result.generated_by == "template"
    assert result.followup_by == "followup-model"  # 조사 결과는 그대로 쓴다


def test_report_schema_has_only_narrative_fields():
    assert set(ReportLLM.model_fields) == {"summary", "risk_assessment"}


# ---- API ----


@pytest.fixture
def fake_llms(monkeypatch):
    """API 엔드포인트가 가짜 LLM 두 개를 쓰게 한다."""
    f, r = FakeLLM("followup-model", FOLLOWUP_REPLY), FakeLLM("report-model", REPORT_REPLY)
    monkeypatch.setattr(main, "_followup_client", lambda: f)
    monkeypatch.setattr(main, "_report_client", lambda: r)
    return f, r


def test_report_endpoint_runs_followup_then_report(fake_llms):
    f, r = fake_llms
    body, cid = analyze(PHISHING_URL)
    res = client.post(f"/api/v1/analyses/{body['id']}/report", headers={"X-Client-Id": cid}).json()
    assert len(f.prompts) == 1 and len(r.prompts) == 1
    assert res["followup_by"] == "followup-model" and res["generated_by"] == "report-model"


def test_report_endpoint_caches_and_regenerates(fake_llms):
    f, r = fake_llms
    body, cid = analyze(PHISHING_URL)
    headers = {"X-Client-Id": cid}
    first = client.post(f"/api/v1/analyses/{body['id']}/report", headers=headers).json()
    again = client.post(f"/api/v1/analyses/{body['id']}/report", headers=headers).json()
    assert first["created_at"] == again["created_at"] and len(f.prompts) == 1  # LLM 다시 안 부름
    client.post(f"/api/v1/analyses/{body['id']}/report?regenerate=true", headers=headers)
    assert len(f.prompts) == 2 and len(r.prompts) == 2


def test_report_respects_privacy():
    body, _ = analyze(PHISHING_URL)
    other = {"X-Client-Id": str(uuid.uuid4())}
    assert client.post(f"/api/v1/analyses/{body['id']}/report", headers=other).status_code == 404
    assert client.get(f"/api/v1/analyses/{body['id']}/report.pdf", headers=other).status_code == 404
    assert client.post("/api/v1/analyses/no-such-id/report").status_code == 404


def test_public_analysis_report_is_available_to_others():
    body, _ = analyze(PHISHING_URL, is_public=True)
    assert client.post(f"/api/v1/analyses/{body['id']}/report").status_code == 200


def test_pdf_contains_all_sections(fake_llms):
    body, cid = analyze(PHISHING_URL)
    res = client.get(f"/api/v1/analyses/{body['id']}/report.pdf", headers={"X-Client-Id": cid})
    assert res.status_code == 200 and res.headers["content-type"] == "application/pdf"
    assert "attachment" in res.headers["content-disposition"]
    text = "".join(page.extract_text() for page in PdfReader(io.BytesIO(res.content)).pages)
    for section in ("1. 요약", "2. 판정 근거", "3. 유사 사례", "4. AI 분석 설명", "5. 위험 분석",
                    "6. 후속 조치", "7. 신고·상담 기관", "8. 분석의 한계"):
        assert section in text, section
    assert "report-model" in text and "followup-model" in text
    assert FOLLOWUP_REPLY["research_summary"] in text


def test_pdf_escapes_markup_in_url(analysis):
    analysis.url = "http://evil.tk/?a=<b>&c=</para>"
    research = followup.research(analysis, client=None)
    pdf = report_pdf.render_report_pdf(report.generate_report(analysis, research, client=None))
    assert pdf.startswith(b"%PDF")
