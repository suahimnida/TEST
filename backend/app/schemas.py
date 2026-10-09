"""API 요청/응답 스키마. 프론트와 공유하는 계약이므로 필드 변경 시 프론트에 공지할 것."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AnalysisRequest(BaseModel):
    url: str = Field(..., examples=["https://example.com"])
    is_public: bool = False  # 공개 목록에 올릴지. 분석 후에는 바꿀 수 없다

    @field_validator("url")
    @classmethod
    def url_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url이 비어 있습니다.")
        return v


class BlacklistResult(BaseModel):
    matched: bool
    match_type: Literal["none", "exact", "host"]
    source: str


class RagReference(BaseModel):
    """RAG가 참고한 보안 문서(KISA/OWASP 등)와 근거. 블랙리스트 조회 결과와는 별개다.
    값의 형태는 codes/ml_integration/risk_judge.py의 RagResult 기준. 내용은 RAG 담당이 채운다."""

    matched: bool = False
    source: list[str] = []  # 참고한 문서 출처 목록
    evidence: str | None = None  # 근거 요약


class ModelResult(BaseModel):
    """값의 형태는 ML 담당 코드(codes/ml_integration/model_integration.py) 기준."""

    status: Literal["ready", "not_ready"]
    risk_score: float | None = None  # 0~100 (피싱 확률 x 100)
    label: Literal["phishing", "normal"] | None = None


class SimilarCase(BaseModel):
    url: str
    label: int  # 1 = 피싱, 0 = 정상
    similarity: float


class Detections(BaseModel):
    """탐지 항목별 결과 (app/services/detections.py).

    각 값은 {"status": "suspicious" | "normal" | "not_analyzed", "reasons": [...], "notes": [...]}.
    탐지 중 오류가 나면 null.
    """

    url: dict | None = None
    url_stats: dict | None = None
    domain: dict | None = None
    html: dict | None = None
    image: dict | None = None


class AiAnalysis(BaseModel):
    summary: str | None = None
    reasons: list[str] = []


class AnalysisResponse(BaseModel):
    id: str
    status: Literal["completed", "failed"]
    url: str
    is_public: bool = False
    # 최종 판정: codes/ml_integration/risk_judge.py 기준 값. 판정 로직 연결 전까지 null
    verdict: Literal["phishing", "suspicious", "normal"] | None = None
    confidence: float | None = None
    risk_score: float | None = None  # 0~100
    # safe: 30 미만 / caution: 30 이상 60 미만 / warning: 60 이상 85 미만 / danger: 85 이상
    risk_level: Literal["safe", "caution", "warning", "danger"] | None = None
    detections: Detections = Detections()
    ai_analysis: AiAnalysis = AiAnalysis()
    extracted_features: dict = {}
    similar_cases: list[SimilarCase] = []
    # 프론트 구조에서 자리가 아직 정해지지 않은 값 (합의 후 이동)
    blacklist: BlacklistResult  # KISA 블랙리스트 조회
    rag: RagReference = RagReference()  # RAG 문서 검색
    model: ModelResult  # ML 모델


class AnalysisSummary(BaseModel):
    """목록용 요약. 브라우저 ID(client_id)는 절대 넣지 않는다."""

    id: str
    url: str
    verdict: Literal["phishing", "suspicious", "normal"] | None = None
    created_at: str


class AnalysisListResponse(BaseModel):
    items: list[AnalysisSummary]


class ClientResponse(BaseModel):
    client_id: str


class HealthResponse(BaseModel):
    status: str


# ---------------------------------------------------------------------------
# 분석 리포트
#
# 후속 조치 조사 (app/services/followup.py, 첫번째 OpenAI 키)
#     탐지 결과·유사 사례·AI 분석 설명으로 예상 피해를 추론하고 우선 조치를 고른다.
# 리포트 작성 (app/services/report.py, 두번째 OpenAI 키)
#     위 결과를 모두 받아 요약과 위험 분석을 쓴다.
# 사실(점수, 판정, 기관 연락처, 조치 단계)은 두 LLM 모두 바꾸지 못하고 서버가 채운다.
# ---------------------------------------------------------------------------


class FollowupResult(BaseModel):
    research_summary: str  # 예상 피해 유형과 대응 방향
    priority_action_ids: list[str]
    action_notes: dict[str, str]  # 조치 id → 이 URL에서 필요한 이유
    generated_by: str  # 조사한 모델 이름, 또는 "template"


class ReportEvidence(BaseModel):
    """판정 근거 한 줄. used_in_verdict가 True인 근거만 최종 점수 계산에 쓰였다."""

    source: str  # "KISA 블랙리스트", "ML 모델", "탐지 결과", "유사 사례", "AI 분석"
    finding: str
    used_in_verdict: bool


class ReportAction(BaseModel):
    id: str
    title: str
    steps: list[str]
    priority: bool = False  # 이 URL에 특히 필요한 조치로 선택됨
    note: str | None = None  # LLM이 이 URL 상황에 맞춰 덧붙인 설명


class ReportActionGroup(BaseModel):
    """상황별 조치 묶음. 사용자가 어디까지 진행했는지는 서버가 알 수 없으므로 상황별로 안내한다."""

    situation: str  # "링크만 받았거나 아직 접속하지 않은 경우" 등
    actions: list[ReportAction]


class ReportContact(BaseModel):
    name: str
    phone: str | None = None
    url: str | None = None
    purpose: str


class ReportResponse(BaseModel):
    analysis_id: str
    created_at: str
    generated_by: str  # 리포트를 작성한 모델 이름(두번째 키), 또는 "template"
    followup_by: str  # 후속 조치를 조사한 모델 이름(첫번째 키), 또는 "template"
    url: str
    verdict: Literal["phishing", "suspicious", "normal"] | None = None
    risk_score: float | None = None
    risk_level: Literal["safe", "caution", "warning", "danger"] | None = None
    confidence: float | None = None
    analyzed_at: str | None = None
    summary: str
    risk_assessment: str
    evidence: list[ReportEvidence]
    similar_cases: list[SimilarCase] = []
    ai_analysis: str | None = None  # 분석 결과 화면의 AI 분석 설명 (RAG)
    followup_summary: str  # 후속 조치 조사 결과
    action_groups: list[ReportActionGroup]
    contacts: list[ReportContact]
    limitations: list[str]
    references: list[str]
