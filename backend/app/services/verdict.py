from app.schemas import AllowlistResult, BlacklistResult, ModelResult
from app.services import model

import risk_judge 

_EMPTY = {"verdict": None, "confidence": None, "risk_score": None, "risk_level": None}


# 허용 목록 도메인의 최종 위험도 상한 (정상 범위)
ALLOWLIST_CAP = 25.0


def decide(blacklist: BlacklistResult, model_result: ModelResult, allow: AllowlistResult | None = None) -> dict:
    if not blacklist.matched and model_result.risk_score is None:
        return dict(_EMPTY)

    result = risk_judge.judge(
        blacklist, 
        risk_judge.RagResult(),
        rag_score=model_result.risk_score or 0.0,
    )
    if allow is not None and allow.matched and not blacklist.matched and result["risk_score"] > ALLOWLIST_CAP:
        score = ALLOWLIST_CAP
        result.update(
            verdict="normal",
            risk_score=score,
            risk_level=risk_judge.risk_level_from_score(score),
            confidence=round(abs(score - 50) / 50, 2),
        )
    return {key: result[key] for key in _EMPTY}
