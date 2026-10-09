import logging
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

logging.basicConfig(level=logging.INFO, format="%(levelname)s:     [%(name)s] %(message)s")
logger = logging.getLogger(__name__)

from app import db 
from app.schemas import (
    AiAnalysis,
    AnalysisListResponse,
    AnalysisRequest,
    AnalysisResponse,
    ClientResponse,
    Detections,
    HealthResponse,
    ModelResult,
    ReportResponse,
)
from app.services import (
    blacklist,
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
    blacklist.load_blacklist()
    try:
        db.init_db()
    except Exception:
        logger.exception("DB 연결 실패: %s", db.describe())
        raise
    logger.info("분석 기록 저장소: %s", db.describe())
    try:
        rag.load_rag()
    except Exception:
        logger.exception("RAG 로드 실패: RAG 없이 서버를 실행합니다")
    yield


app = FastAPI(title="피싱 URL 분석 API", version="0.1.0", lifespan=lifespan)

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
    return str(client_id) if client_id else None


@app.post("/api/v1/clients", response_model=ClientResponse)
def create_client():
    return ClientResponse(client_id=str(uuid.uuid4()))


@app.post("/api/v1/analyses", response_model=AnalysisResponse)
def create_analysis(request: AnalysisRequest, x_client_id: uuid.UUID | None = Header(None)):
    blacklist_result = blacklist.check_blacklist(request.url)
    if blacklist_result.matched:
        rag_result = rag.RagResult()
        model_result = ModelResult(status="not_ready")
    else:
        rag_result = rag.explain(request.url)
        model_result = model.predict(request.url)

    try:
        detection_result = Detections(**detections.analyze(request.url))
    except Exception:
        logger.exception("탐지 결과 생성 실패: %s", request.url)
        detection_result = Detections()

    result = AnalysisResponse(
        id=str(uuid.uuid4()),
        status="completed",
        url=request.url,
        is_public=request.is_public,
        **verdict.decide(blacklist_result, model_result),
        detections=detection_result,
        ai_analysis=AiAnalysis(summary=rag_result.summary),
        extracted_features=rag_result.features,
        similar_cases=rag_result.similar_cases,
        blacklist=blacklist_result,
        rag=rag_result.reference,
        model=model_result,
    )
    try:
        db.save_analysis(result, _client_key(x_client_id))
    except Exception:
        logger.exception("분석 기록 저장 실패: %s", request.url)
    return result


@app.get("/api/v1/analyses", response_model=AnalysisListResponse)
def list_analyses(
    scope: Literal["mine", "public"],
    limit: int = Query(20, ge=1, le=100),
    x_client_id: uuid.UUID | None = Header(None),
):
    if scope == "public":
        return AnalysisListResponse(items=db.list_analyses(limit))
    if x_client_id is None:
        raise HTTPException(status_code=400, detail="X-Client-Id 헤더가 필요합니다.")
    return AnalysisListResponse(items=db.list_analyses(limit, _client_key(x_client_id)))


@app.get("/api/v1/analyses/{analysis_id}", response_model=AnalysisResponse)
def read_analysis(analysis_id: str, x_client_id: uuid.UUID | None = Header(None)):
    result = db.get_analysis(analysis_id, _client_key(x_client_id))
    if result is None:
        raise HTTPException(status_code=404, detail="분석 결과를 찾을 수 없습니다.")
    return result

_llm_clients: dict = {}


def _followup_client():
    if "followup" not in _llm_clients:
        _llm_clients["followup"] = OpenAIJsonClient.from_env(
            "FOLLOWUP", "후속 조치 조사", followup.DEFAULT_FOLLOWUP_MODEL
        )
    return _llm_clients["followup"]


def _report_client():
    if "report" not in _llm_clients:
        _llm_clients["report"] = OpenAIJsonClient.from_env(
            "REPORT", "리포트 작성", report.DEFAULT_REPORT_MODEL
        )
    return _llm_clients["report"]


def _load_report(analysis_id: str, client_key: str | None, regenerate: bool) -> ReportResponse:
    record = db.get_analysis_record(analysis_id, client_key)
    if record is None:
        raise HTTPException(status_code=404, detail="분석 결과를 찾을 수 없습니다.")
    analysis, analyzed_at = record

    if not regenerate:
        cached = db.get_report(analysis_id)
        if cached is not None:
            return cached

    research = followup.research(analysis, client=_followup_client())
    result = report.generate_report(
        analysis, research, client=_report_client(), analyzed_at=analyzed_at
    )

    try:
        db.save_report(result)
    except Exception:
        logger.exception("리포트 저장 실패: %s", analysis_id)
    return result


@app.post("/api/v1/analyses/{analysis_id}/report", response_model=ReportResponse)
def create_report(
    analysis_id: str,
    regenerate: bool = Query(False, description="true면 저장된 리포트를 무시하고 새로 만든다"),
    x_client_id: uuid.UUID | None = Header(None),
):
    return _load_report(analysis_id, _client_key(x_client_id), regenerate)


@app.get("/api/v1/analyses/{analysis_id}/report.pdf")
def download_report_pdf(analysis_id: str, x_client_id: uuid.UUID | None = Header(None)):
    result = _load_report(analysis_id, _client_key(x_client_id), regenerate=False)
    pdf = report_pdf.render_report_pdf(result)
    filename = f"phishing-report-{analysis_id[:8]}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

