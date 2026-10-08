"""
피싱 URL 분석 프로젝트 - 최종 판정 규칙 (verdict / confidence / risk_score / risk_level)

팀 합의 내용 (10/02 논의 기준):
1) 블랙리스트(KISA) 매치 시 -> RAG/ML 돌리지 않고 즉시 phishing 확정
2) 매치 안 되면 -> RAG 점수 + ML 점수를 가중평균하여 risk_score 산출
   - ML 모델 연동 전까지는 ML 가중치 0으로 두고 RAG 단독 운용
3) risk_level은 risk_score(0~100) 구간으로 분류
   - 0-30   : safe (안전)
   - 30-60  : caution (주의)
   - 60-85  : warning (경고)
   - 85-100 : danger (위험)

model: {status, risk_score, label} 응답 필드를 만들기 위한 ML 쪽 결과 포맷도
이 모듈에서 함께 정의합니다 (백엔드 응답 구조 그대로).

작성자: 성주 (AI 개발자)
"""

from dataclasses import dataclass, field
from typing import Optional

# RAG/ML 가중치 (합이 1.0이 되어야 함)
# ML 모델 연동 전에는 RAG_WEIGHT=1.0, ML_WEIGHT=0.0 으로 시작하고,
# 모델 성능이 검증되면 팀 논의 후 조정합니다.
RAG_WEIGHT = 1.0
ML_WEIGHT = 0.0

RISK_LEVEL_BANDS = [
    (0, 30, "safe"),
    (30, 60, "caution"),
    (60, 85, "warning"),
    (85, 101, "danger"),  # 101로 둬서 100도 포함
]


@dataclass
class BlacklistResult:
    matched: bool
    match_type: Optional[str] = None  # "url" | "domain" | None
    source: Optional[str] = None      # "KISA" 등


@dataclass
class RagResult:
    matched: bool = False
    source: list = field(default_factory=list)   # 참고한 문서 출처 목록
    evidence: Optional[str] = None                # 근거 요약


@dataclass
class ModelResult:
    status: str = "not_ready"  # "ready" | "not_ready"
    risk_score: Optional[float] = None  # 0~100, 모델 미연동 시 None
    label: Optional[str] = None         # "phishing" | "normal", 모델 미연동 시 None


def risk_level_from_score(score: float) -> str:
    for low, high, level in RISK_LEVEL_BANDS:
        if low <= score < high:
            return level
    return "danger"


def judge(
    blacklist: BlacklistResult,
    rag: RagResult,
    rag_score: float,
    model: ModelResult = ModelResult(),
) -> dict:
    """
    최종 verdict/confidence/risk_score/risk_level을 계산.

    rag_score: RAG 쪽에서 산출한 0~100 위험 점수 (문자열 패턴/특징 기반 1차·2차 판정 결과).
    model.risk_score: ML 모델이 아직 없으면 None -> ML_WEIGHT가 0이므로 영향 없음.
    """
    # 1) 블랙리스트 매치 시 즉시 확정 (RAG/ML 결과 무시)
    if blacklist.matched:
        return {
            "verdict": "phishing",
            "confidence": 1.0,
            "risk_score": 100.0,
            "risk_level": "danger",
            "reason": f"blacklist_match:{blacklist.match_type}",
        }

    # 2) 블랙리스트 미매치 -> RAG + ML 가중평균
    ml_score = model.risk_score if model.status == "ready" and model.risk_score is not None else 0.0
    effective_rag_weight = RAG_WEIGHT if model.status != "ready" else RAG_WEIGHT
    effective_ml_weight = ML_WEIGHT if model.status == "ready" else 0.0

    # ML이 아직 없으면 RAG 100%로 재정규화
    total_weight = effective_rag_weight + effective_ml_weight
    if total_weight == 0:
        total_weight = 1.0

    risk_score = (rag_score * effective_rag_weight + ml_score * effective_ml_weight) / total_weight
    risk_score = round(min(max(risk_score, 0.0), 100.0), 2)

    verdict = "phishing" if risk_score >= 60 else ("suspicious" if risk_score >= 30 else "normal")
    confidence = round(abs(risk_score - 50) / 50, 2)  # 50(애매)에서 멀수록 확신도 높음

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level_from_score(risk_score),
        "reason": "rag_ml_weighted_score" if model.status == "ready" else "rag_only_score",
    }


if __name__ == "__main__":
    # 간단 동작 확인
    print(judge(BlacklistResult(matched=True, match_type="domain", source="KISA"), RagResult(), rag_score=0))
    print(judge(BlacklistResult(matched=False), RagResult(matched=True, source=["KISA_db"]), rag_score=72))
    print(judge(BlacklistResult(matched=False), RagResult(), rag_score=12))
