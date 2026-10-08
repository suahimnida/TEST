"""
피싱 URL 분석 프로젝트 - ML 모델 연동 (FastAPI 백엔드에 붙일 부분)

train_model.py로 만든 models/best_model.joblib, scaler.joblib,
feature_columns.json을 로드해서 preprocess.py의 extract_features()로 뽑은
특징을 넣으면 model: {status, risk_score, label} 형태로 돌려줍니다.

백엔드(박채린/장은서)님이 POST /api/v1/analyses 핸들러 안에서
predict_model(url) 호출 결과를 응답의 "model" 필드에 그대로 넣으시면 됩니다.

사용 예:
    from model_integration import predict_model
    result = predict_model("http://example-login-verify.com")
    # {'status': 'ready', 'risk_score': 83.2, 'label': 'phishing'}

작성자: 성주 (AI 개발자)
"""

import json
import os

import joblib
import pandas as pd

from preprocess import extract_features

MODEL_DIR = os.environ.get("ML_MODEL_DIR", os.path.join(os.path.dirname(__file__), "models"))

_model = None
_scaler = None
_feature_cols = None
_report = None
_load_error = None


def _load_artifacts():
    """모델 파일들을 1회만 로드 (지연 로딩 + 캐시)."""
    global _model, _scaler, _feature_cols, _report, _load_error
    if _model is not None or _load_error is not None:
        return
    try:
        _model = joblib.load(os.path.join(MODEL_DIR, "best_model.joblib"))
        _scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
        with open(os.path.join(MODEL_DIR, "feature_columns.json"), encoding="utf-8") as f:
            _feature_cols = json.load(f)
        with open(os.path.join(MODEL_DIR, "model_report.json"), encoding="utf-8") as f:
            _report = json.load(f)
    except FileNotFoundError as e:
        _load_error = str(e)


def predict_model(url: str) -> dict:
    """
    URL 하나를 받아 model: {status, risk_score, label} 딕셔너리를 반환.
    모델 파일이 아직 없으면 status="not_ready"로 응답해서 프론트가 null 처리하던
    기존 흐름을 그대로 유지합니다 (화면 깨짐 방지).
    """
    _load_artifacts()
    if _load_error is not None:
        return {"status": "not_ready", "risk_score": None, "label": None}

    feats = extract_features(url)
    row = {col: feats.get(col, 0) for col in _feature_cols}
    X = pd.DataFrame([row], columns=_feature_cols)

    if _report.get("needs_scaling"):
        X = _scaler.transform(X)

    proba_phishing = float(_model.predict_proba(X)[0][1])
    risk_score = round(proba_phishing * 100, 2)
    label = "phishing" if proba_phishing >= 0.5 else "normal"

    return {"status": "ready", "risk_score": risk_score, "label": label}


if __name__ == "__main__":
    print(predict_model("http://secure-paypal-login.verify-account.tk"))
    print(predict_model("https://www.naver.com"))
