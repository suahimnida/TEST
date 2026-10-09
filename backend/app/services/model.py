import logging
import sys
from pathlib import Path

from app.schemas import ModelResult

logger = logging.getLogger(__name__)

_ML_DIR = Path(__file__).resolve().parents[2] / "ml_integration"

if str(_ML_DIR) not in sys.path:
    sys.path.append(str(_ML_DIR))


def predict(url: str) -> ModelResult:
    try:
        from model_integration import predict_model

        return ModelResult(**predict_model(url))
    except Exception:
        logger.exception("ML 예측 실패: %s", url)
        return ModelResult(status="not_ready")
