"""ML 피싱 판별 모델.

codes/ml_integration/model_integration.py(ML 담당)의 predict_model()을 그대로 호출한다.
모델 파일이 없거나 예측 중 오류가 나면 status="not_ready"를 반환하고, 서버는 계속 동작한다.

주의: scikit-learn 버전이 학습 때(1.3.2)와 다르면 오류 없이 엉뚱한 점수가 나온다.
      requirements.txt의 고정 버전을 지킬 것.

환경변수:
    ML_MODEL_DIR  모델 파일 폴더 (기본: codes/ml_integration/models)
"""

import logging
import sys
from pathlib import Path

from app.schemas import ModelResult

logger = logging.getLogger(__name__)

_ML_DIR = Path(__file__).resolve().parents[2] / "ml_integration"

# model_integration.py는 같은 폴더의 preprocess.py를 불러온다.
# rag.py가 먼저 codes/preprocess.py를 불러왔다면 그것이 쓰이는데,
# 두 파일의 extract_features()는 같은 내용이라 결과는 같다.
if str(_ML_DIR) not in sys.path:
    sys.path.append(str(_ML_DIR))


def predict(url: str) -> ModelResult:
    # 모델 오류로 분석 전체가 실패하지 않도록 여기서 오류를 막는다
    try:
        from model_integration import predict_model

        return ModelResult(**predict_model(url))
    except Exception:
        logger.exception("ML 예측 실패: %s", url)
        return ModelResult(status="not_ready")
