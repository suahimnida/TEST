import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AnalysisRequest(BaseModel):
    url: str = Field(..., examples=["https://example.com"])
    is_public: bool = False
    # 분석 요청자 확인용. 화면에서는 필수로 받는다 (app/services/owner.py)
    owner_name: str | None = Field(None, max_length=30)
    owner_secret: str | None = None

    @field_validator("url")
    @classmethod
    def url_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url이 비어 있습니다.")
        return v

    @field_validator("owner_name")
    @classmethod
    def name_not_blank(cls, v: str | None) -> str | None:
        if v is not None and not v.strip():
            raise ValueError("성명이 비어 있습니다.")
        return v.strip() if v else v

    @field_validator("owner_secret")
    @classmethod
    def secret_format(cls, v: str | None) -> str | None:
        if v is not None and not re.fullmatch(r"[A-Za-z0-9]{8,12}", v):
            raise ValueError("사용자 식별 암호는 영문 대소문자와 숫자 8~12자리여야 합니다.")
        return v


class OwnerCheckRequest(BaseModel):
    name: str
    secret: str


class DeleteAnalysisRequest(BaseModel):
    name: str
    secret: str
    confirm_text: str


class BlacklistResult(BaseModel):
    matched: bool
    match_type: Literal["none", "exact", "host"]
    source: str


class RagReference(BaseModel):

    matched: bool = False
    source: list[str] = [] 
    evidence: str | None = None 


class ModelResult(BaseModel):

    status: Literal["ready", "not_ready"]
    risk_score: float | None = None 
    label: Literal["phishing", "normal"] | None = None


class SimilarCase(BaseModel):
    url: str
    label: int 
    similarity: float


class Detections(BaseModel):

    url: dict | None = None
    url_stats: dict | None = None
    domain: dict | None = None
    reputation: dict | None = None  # 평판 신호 (참고 근거, 점수 미반영)


class AiAnalysis(BaseModel):
    """출처가 있는 설명. 문장 끝의 [E1]은 evidence, [G1]은 guides의 항목을 가리킨다."""

    summary: str | None = None
    reasons: list[str] = []
    written_by: str | None = None  # 설명을 쓴 모델 이름, 또는 "template"
    evidence: list[dict] = []  # ML·탐지 근거 (app/services/guides.py build_evidence)
    guides: list[dict] = []  # RAG로 찾은 공식 기관 대응 가이드


class AllowlistResult(BaseModel):
    """공식 도메인 허용 목록 일치 여부. 일치하면 ML 점수만으로 피싱 판정을 내리지 않는다."""

    matched: bool = False
    domain: str | None = None


class AnalysisResponse(BaseModel):
    id: str
    status: Literal["completed", "failed"]
    url: str
    # 요청한 사람에 따라 달라지는 값 (저장하지 않는다)
    #   viewer: owner(내 결과) / public(남의 공개 결과) / shared(공유 링크로 연 결과)
    #   share_token: 공유 링크 토큰. 본인에게만 보낸다
    viewer: Literal["owner", "public", "shared"] | None = None
    share_token: str | None = None
    owner_name: str | None = None  # 가린 성명 (예: 김**). 공개 결과에서 보여 준다
    is_public: bool = False
    verdict: Literal["phishing", "suspicious", "normal"] | None = None
    confidence: float | None = None
    risk_score: float | None = None 
    risk_level: Literal["safe", "caution", "warning", "danger"] | None = None
    detections: Detections = Detections()
    ai_analysis: AiAnalysis = AiAnalysis()
    extracted_features: dict = {}
    similar_cases: list[SimilarCase] = []
    blacklist: BlacklistResult
    allowlist: AllowlistResult = AllowlistResult()
    # 판단 근거 수치: ML 모델 기여도와 정상 데이터 대비 위치 (app/services/explain.py)
    explanation: dict | None = None 
    rag: RagReference = RagReference() 
    model: ModelResult 


class AnalysisSummary(BaseModel):

    id: str
    url: str
    verdict: Literal["phishing", "suspicious", "normal"] | None = None
    created_at: str
    owner_name: str | None = None  # 가린 성명 (예: 김**)


class AnalysisListResponse(BaseModel):
    items: list[AnalysisSummary]


class ClientResponse(BaseModel):
    client_id: str


class HealthResponse(BaseModel):
    status: str

class FollowupResult(BaseModel):
    research_summary: str 
    priority_action_ids: list[str]
    action_notes: dict[str, str]
    generated_by: str 


class ReportEvidence(BaseModel):

    source: str 
    finding: str
    used_in_verdict: bool


class ReportAction(BaseModel):
    id: str
    title: str
    steps: list[str]
    priority: bool = False
    note: str | None = None
    source: str | None = None  # 이 조치를 안내하는 공식 기관 (resources/guides/guides.json)
    source_url: str | None = None


class ReportActionGroup(BaseModel):

    situation: str 
    actions: list[ReportAction]


class ReportContact(BaseModel):
    name: str
    phone: str | None = None
    url: str | None = None
    purpose: str


class ReportResponse(BaseModel):
    analysis_id: str
    created_at: str
    generated_by: str 
    followup_by: str 
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
    ai_analysis: str | None = None  # 출처 번호([E1], [G1])가 붙은 설명
    ai_evidence: list[dict] = []  # [E] 번호가 가리키는 근거
    ai_guides: list[dict] = []  # [G] 번호가 가리키는 공식 기관 대응 가이드
    followup_summary: str  
    action_groups: list[ReportActionGroup]
    contacts: list[ReportContact]
    limitations: list[str]
    references: list[str]



class VisibilityRequest(BaseModel):
    is_public: bool


class ShareResponse(BaseModel):
    token: str | None = None  # 없으면 공유 링크가 없는 상태
