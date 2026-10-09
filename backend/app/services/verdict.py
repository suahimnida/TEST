from app.schemas import BlacklistResult, ModelResult
from app.services import model

import risk_judge 

_EMPTY = {"verdict": None, "confidence": None, "risk_score": None, "risk_level": None}


def decide(blacklist: BlacklistResult, model_result: ModelResult) -> dict:
    if not blacklist.matched and model_result.risk_score is None:
        return dict(_EMPTY)

    result = risk_judge.judge(
        blacklist, 
        risk_judge.RagResult(),
        rag_score=model_result.risk_score or 0.0,
    )
    return {key: result[key] for key in _EMPTY}
