"""분석 결과의 근거를 수치로 설명한다 (ml_integration/url_explain.py).

    model      ML 모델(v2)의 부분별·글자별·n-gram별 기여도. 블랙리스트로 확정돼 ML을 쓰지 않았으면 없다.
    reference  정상 데이터 대비 위치 (참고 지표, 모델 입력 아님)
"""

import logging
import sys
from pathlib import Path

_ML_DIR = Path(__file__).resolve().parents[2] / "ml_integration"
if str(_ML_DIR) not in sys.path:
    sys.path.append(str(_ML_DIR))

import url_explain  # noqa: E402

logger = logging.getLogger(__name__)


def build(url: str, model_used: bool) -> dict | None:
    result = {"model": None, "reference": []}
    try:
        result["reference"] = url_explain.reference(url)
    except Exception:
        logger.exception("참고 지표 계산 실패: %s", url)

    if model_used:
        try:
            from model_integration import _load_v2

            v2 = _load_v2()
            if v2 is not None:
                result["model"] = url_explain.explain_model(v2["model"], url)
        except Exception:
            logger.exception("모델 기여도 계산 실패: %s", url)

    return result if result["model"] or result["reference"] else None
