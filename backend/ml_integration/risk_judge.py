from dataclasses import dataclass, field
from typing import Optional

RAG_WEIGHT = 1.0
ML_WEIGHT = 0.0

RISK_LEVEL_BANDS = [
    (0, 30, "safe"),
    (30, 60, "caution"),
    (60, 85, "warning"),
    (85, 101, "danger"),  
]


@dataclass
class BlacklistResult:
    matched: bool
    match_type: Optional[str] = None 
    source: Optional[str] = None     


@dataclass
class RagResult:
    matched: bool = False
    source: list = field(default_factory=list)  
    evidence: Optional[str] = None               


@dataclass
class ModelResult:
    status: str = "not_ready"  
    risk_score: Optional[float] = None 
    label: Optional[str] = None   


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
    if blacklist.matched:
        return {
            "verdict": "phishing",
            "confidence": 1.0,
            "risk_score": 100.0,
            "risk_level": "danger",
            "reason": f"blacklist_match:{blacklist.match_type}",
        }

    ml_score = model.risk_score if model.status == "ready" and model.risk_score is not None else 0.0
    effective_rag_weight = RAG_WEIGHT if model.status != "ready" else RAG_WEIGHT
    effective_ml_weight = ML_WEIGHT if model.status == "ready" else 0.0

    total_weight = effective_rag_weight + effective_ml_weight
    if total_weight == 0:
        total_weight = 1.0

    risk_score = (rag_score * effective_rag_weight + ml_score * effective_ml_weight) / total_weight
    risk_score = round(min(max(risk_score, 0.0), 100.0), 2)

    verdict = "phishing" if risk_score >= 60 else ("suspicious" if risk_score >= 30 else "normal")
    confidence = round(abs(risk_score - 50) / 50, 2) 

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level_from_score(risk_score),
        "reason": "rag_ml_weighted_score" if model.status == "ready" else "rag_only_score",
    }


if __name__ == "__main__":
    print(judge(BlacklistResult(matched=True, match_type="domain", source="KISA"), RagResult(), rag_score=0))
    print(judge(BlacklistResult(matched=False), RagResult(matched=True, source=["KISA_db"]), rag_score=72))
    print(judge(BlacklistResult(matched=False), RagResult(), rag_score=12))
