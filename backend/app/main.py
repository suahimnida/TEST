"""피싱 URL 분석 API 서버.

실행 (backend/ 폴더에서):
    uvicorn app.main:app --reload
"""

import logging
from concurrent.futures import ThreadPoolExecutor
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware

# backend/.env의 값을 환경변수로 읽어온다 (이미 설정된 환경변수가 우선)
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

# RAG 로드 여부와 실패 원인이 서버 로그에 보이도록 앱 로그를 INFO 수준으로 출력한다
logging.basicConfig(level=logging.INFO, format="%(levelname)s:     [%(name)s] %(message)s")
logger = logging.getLogger(__name__)

from app import db  # noqa: E402
from app.schemas import (
    AiAnalysis,
    AnalysisListResponse,
    AnalysisRequest,
    AnalysisResponse,
    ClientResponse,
    Detections,
    HealthResponse,
    ModelResult,
    RagReference,
    ReportResponse,
    ShareResponse,
    VisibilityRequest,
)
from app.services import (
    allowlist,
    blacklist,
    explain,
    guides,
    reputation,
    detections,
    followup,
    model,
    rag,
    report,
    report_pdf,
    verdict,
)
from app.services.llm_openai import OpenAIJsonClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 첫 요청이 느려지지 않도록 서버 시작 시 블랙리스트를 미리 로드
    blacklist.load_blacklist()
    # DB 연결 정보가 잘못되면 여기서 서버 시작을 멈춘다. Render는 시작에 실패한 배포를
    # 적용하지 않고 이전 배포를 계속 서비스하므로, 기록이 엉뚱한 곳에 쌓이지 않는다
    try:
        db.init_db()
    except Exception:
        logger.exception("DB 연결 실패: %s", db.describe())
        raise
    logger.info("분석 기록 저장소: %s", db.describe())
    # RAG 준비 중 오류(패키지 누락, 임베딩 모델 다운로드 실패 등)가 나도 서버는 뜨고,
    # 블랙리스트 + ML 판정은 그대로 동작하도록 여기서 막는다
    try:
        rag.load_rag()
    except Exception:
        logger.exception("RAG 로드 실패: RAG 없이 서버를 실행합니다")
    yield


app = FastAPI(title="피싱 URL 분석 API", version="0.1.0", lifespan=lifespan)

# 프론트 개발 서버(Vite)에서 오는 요청을 허용. 쉼표로 여러 주소 지정 가능
app.add_middleware(
    CORSMiddleware,
    allow_origins=(os.environ.get("CORS_ORIGINS") or "http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(status="ok")


def _client_key(client_id: uuid.UUID | None) -> str | None:
    """헤더의 브라우저 ID를 DB에 저장하는 형태(소문자 UUID 문자열)로 바꾼다."""
    return str(client_id) if client_id else None


@app.post("/api/v1/clients", response_model=ClientResponse)
def create_client():
    """브라우저 ID 발급. 프론트는 로컬스토리지에 저장해두고 X-Client-Id 헤더로 보낸다."""
    return ClientResponse(client_id=str(uuid.uuid4()))


# 평판 신호(외부 조회)를 RAG·ML과 동시에 실행하기 위한 작업자
_background = ThreadPoolExecutor(max_workers=4)


@app.post("/api/v1/analyses", response_model=AnalysisResponse)
def create_analysis(request: AnalysisRequest, x_client_id: uuid.UUID | None = Header(None)):
    blacklist_result = blacklist.check_blacklist(request.url)
    allowlist_result = allowlist.check(request.url)
    reputation_job = _background.submit(reputation.lookup, request.url) if reputation.enabled() else None
    # 블랙리스트에 있으면 피싱으로 확정되므로 RAG/ML은 돌리지 않는다 (팀 합의)
    if blacklist_result.matched:
        rag_result = rag.RagResult()
        model_result = ModelResult(status="not_ready")
    else:
        rag_result = rag.similar(request.url)
        model_result = model.predict(request.url)

    # URL 문자열 기반 탐지 결과. 실패해도 나머지 분석 결과는 그대로 반환한다
    try:
        detection_result = Detections(**detections.analyze(request.url))
    except Exception:
        logger.exception("탐지 결과 생성 실패: %s", request.url)
        detection_result = Detections()
    if reputation_job is not None:
        try:
            detection_result.reputation = reputation.to_detection(reputation_job.result(timeout=10))
        except Exception:
            logger.exception("평판 신호 조회 실패: %s", request.url)

    decided = verdict.decide(blacklist_result, model_result, allowlist_result)
    explanation = explain.build(request.url, model_used=model_result.status == "ready")

    # ① ML 근거 → ② RAG 대응 가이드 검색 → ③ LLM이 둘을 합쳐 출처가 있는 설명 작성
    evidence = guides.build_evidence(
        verdict=decided["verdict"], risk_score=decided["risk_score"], blacklist=blacklist_result,
        allowlist=allowlist_result, model=model_result, explanation=explanation,
        detections=detection_result, similar_cases=rag_result.similar_cases,
    )
    found = guides.retrieve(guides.evidence_tags(request.url, decided["verdict"], evidence), evidence)
    # 블랙리스트로 확정된 URL은 LLM을 부르지 않는다 (팀 합의: 블랙리스트면 RAG·ML 생략)
    written = None if blacklist_result.matched else rag.compose(evidence, found)
    ai_analysis = AiAnalysis(
        summary=written or guides.template_explanation(decided["verdict"], evidence, found),
        written_by=rag.CLAUDE_MODEL if written else "template",
        evidence=evidence,
        guides=found,
    )

    result = AnalysisResponse(
        id=str(uuid.uuid4()),
        status="completed",
        url=request.url,
        is_public=request.is_public,
        **decided,
        detections=detection_result,
        ai_analysis=ai_analysis,
        extracted_features=rag_result.features,
        similar_cases=rag_result.similar_cases,
        blacklist=blacklist_result,
        allowlist=allowlist_result,
        explanation=explanation,
        rag=RagReference(
            matched=bool(found),
            source=[f"{g['title']} ({g['source']})" for g in found],
        ),
        model=model_result,
    )
    # 저장에 실패해도(예: DB 일시 장애) 분석 결과는 사용자에게 돌려준다
    try:
        db.save_analysis(result, _client_key(x_client_id))
    except Exception:
        logger.exception("분석 기록 저장 실패: %s", request.url)
    result.viewer = "owner"
    return result


@app.get("/api/v1/analyses", response_model=AnalysisListResponse)
def list_analyses(
    scope: Literal["mine", "public"],
    limit: int = Query(20, ge=1, le=100),
    x_client_id: uuid.UUID | None = Header(None),
):
    """scope=mine: 이 브라우저의 기록 / scope=public: 공개된 기록."""
    if scope == "public":
        return AnalysisListResponse(items=db.list_analyses(limit))
    if x_client_id is None:
        raise HTTPException(status_code=400, detail="X-Client-Id 헤더가 필요합니다.")
    return AnalysisListResponse(items=db.list_analyses(limit, _client_key(x_client_id)))


@app.get("/api/v1/analyses/{analysis_id}", response_model=AnalysisResponse)
def read_analysis(analysis_id: str, x_client_id: uuid.UUID | None = Header(None)):
    # 비공개 결과는 만든 브라우저에서만 보인다. 남의 비공개 결과도 "없음"으로 응답한다
    record = db.get_analysis_access(analysis_id, _client_key(x_client_id))
    if record is None:
        raise HTTPException(status_code=404, detail="분석 결과를 찾을 수 없습니다.")
    result, _, owner = record
    return _for_viewer(result, "owner" if owner else "public")


def _for_viewer(result: AnalysisResponse, viewer: str) -> AnalysisResponse:
    result.viewer = viewer
    # 공유 링크 토큰은 본인에게만 보낸다
    result.share_token = db.get_share_token(result.id) if viewer == "owner" else None
    return result


def _require_owner(analysis_id: str, x_client_id) -> str:
    client_key = _client_key(x_client_id)
    if not db.is_owner(analysis_id, client_key):
        # 남의 결과인지 없는 결과인지 구분되지 않도록 같은 응답을 쓴다
        raise HTTPException(status_code=404, detail="분석 결과를 찾을 수 없습니다.")
    return client_key


@app.patch("/api/v1/analyses/{analysis_id}/visibility", response_model=AnalysisResponse)
def change_visibility(analysis_id: str, request: VisibilityRequest, x_client_id: uuid.UUID | None = Header(None)):
    """본인 결과의 공개 여부를 바꾼다."""
    result = db.set_visibility(analysis_id, _client_key(x_client_id), request.is_public)
    if result is None:
        raise HTTPException(status_code=404, detail="분석 결과를 찾을 수 없습니다.")
    return _for_viewer(result, "owner")


@app.post("/api/v1/analyses/{analysis_id}/share", response_model=ShareResponse)
def create_share_link(analysis_id: str, x_client_id: uuid.UUID | None = Header(None)):
    """'링크가 있는 사람은 볼 수 있음'. 본인 결과에만 만들 수 있고, 이미 있으면 같은 링크를 돌려준다."""
    _require_owner(analysis_id, x_client_id)
    return ShareResponse(token=db.create_share(analysis_id))


@app.delete("/api/v1/analyses/{analysis_id}/share", response_model=ShareResponse)
def delete_share_link(analysis_id: str, x_client_id: uuid.UUID | None = Header(None)):
    """공유 중지. 이미 보낸 링크는 바로 열리지 않는다."""
    _require_owner(analysis_id, x_client_id)
    db.delete_share(analysis_id)
    return ShareResponse(token=None)


@app.get("/api/v1/shared/{token}", response_model=AnalysisResponse)
def read_shared(token: str):
    """공유 링크로 연 결과 (읽기 전용). 공개 여부와 관계없이 링크가 살아 있으면 보인다."""
    record = db.get_shared(token)
    if record is None:
        raise HTTPException(status_code=404, detail="공유가 중지됐거나 없는 링크입니다.")
    return _for_viewer(record[0], "shared")


# ---------------------------------------------------------------------------
# 분석 리포트
# ---------------------------------------------------------------------------

# OpenAI 클라이언트는 처음 쓸 때 한 번만 만든다. 키나 모델이 없으면 None (템플릿으로 대신).
_llm_clients: dict = {}


def _followup_client():
    """첫번째 OpenAI 키: 후속 조치 조사"""
    if "followup" not in _llm_clients:
        _llm_clients["followup"] = OpenAIJsonClient.from_env(
            "FOLLOWUP", "후속 조치 조사", followup.DEFAULT_FOLLOWUP_MODEL
        )
    return _llm_clients["followup"]


def _report_client():
    """두번째 OpenAI 키: 리포트 작성"""
    if "report" not in _llm_clients:
        _llm_clients["report"] = OpenAIJsonClient.from_env(
            "REPORT", "리포트 작성", report.DEFAULT_REPORT_MODEL
        )
    return _llm_clients["report"]


def _load_report(analysis_id: str, client_key: str | None, share: str | None = None) -> ReportResponse:
    """분석 1건당 리포트는 한 번만 만든다. 이미 있으면 저장된 리포트를 돌려준다 (LLM을 다시 부르지 않음).
    공유 링크로 연 사람도 그 결과의 리포트는 볼 수 있다."""
    record = db.get_analysis_record(analysis_id, client_key)
    if record is None and share:
        shared = db.get_shared(share)
        if shared is not None and shared[0].id == analysis_id:
            record = shared
    if record is None:
        raise HTTPException(status_code=404, detail="분석 결과를 찾을 수 없습니다.")
    analysis, analyzed_at = record

    cached = db.get_report(analysis_id)
    if cached is not None:
        return cached

    # 1) 첫번째 키로 후속 조치 조사 → 2) 두번째 키로 리포트 작성
    research = followup.research(analysis, client=_followup_client())
    result = report.generate_report(
        analysis, research, client=_report_client(), analyzed_at=analyzed_at
    )
    # 저장에 실패해도 만든 리포트는 돌려준다 (다음에 다시 만들면 된다)
    try:
        db.save_report(result)
    except Exception:
        logger.exception("리포트 저장 실패: %s", analysis_id)
    return result


@app.post("/api/v1/analyses/{analysis_id}/report", response_model=ReportResponse)
def create_report(
    analysis_id: str,
    share: str | None = Query(None, description="공유 링크 토큰"),
    x_client_id: uuid.UUID | None = Header(None),
):
    """분석 결과로 리포트를 만든다. 이미 만든 리포트가 있으면 그대로 돌려준다 (다시 생성 기능 없음)."""
    return _load_report(analysis_id, _client_key(x_client_id), share)


@app.get("/api/v1/analyses/{analysis_id}/report.pdf")
def download_report_pdf(
    analysis_id: str,
    share: str | None = Query(None, description="공유 링크 토큰"),
    x_client_id: uuid.UUID | None = Header(None),
):
    """리포트 PDF. 리포트가 아직 없으면 먼저 만든다."""
    result = _load_report(analysis_id, _client_key(x_client_id), share)
    pdf = report_pdf.render_report_pdf(result)
    filename = f"phishing-report-{analysis_id[:8]}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

