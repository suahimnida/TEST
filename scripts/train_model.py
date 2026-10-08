"""
피싱 URL 분석 프로젝트 - ML 모델 학습 스크립트

입력: preprocess.py로 만든 features_output.csv
      (url, label, url_length, host_length, ... top_3gram_1~3 컬럼 포함)
출력: 학습된 모델(.joblib) + 성능 리포트(model_report.json)

사용법:
    python train_model.py --input features_output.csv --output-dir models/

- Logistic Regression / Random Forest / XGBoost 세 가지를 모두 학습하고
  검증 데이터 기준 ROC-AUC가 가장 높은 모델을 best model로 저장합니다.
- top_3gram_1~3(문자열 참고용 컬럼)과 url 원문은 수치형 모델 입력에서 제외합니다.

작성자: 성주 (AI 개발자)
"""

import argparse
import json
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

# 모델 입력에서 제외할 컬럼 (원문/참고용 컬럼)
DROP_COLS = ["url", "label", "top_3gram_1", "top_3gram_2", "top_3gram_3"]


def load_dataset(path: str):
    df = pd.read_csv(path)
    if "label" not in df.columns:
        raise ValueError("입력 CSV에 'label' 컬럼이 없습니다. preprocess.py 출력물을 사용하세요.")
    feature_cols = [c for c in df.columns if c not in DROP_COLS]
    X = df[feature_cols].copy()
    y = df["label"].astype(int)
    return X, y, feature_cols


def evaluate(model, X_test, y_test) -> dict:
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    return {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_test, y_proba), 4),
    }


def main():
    parser = argparse.ArgumentParser(description="피싱 URL 분류 모델 학습")
    parser.add_argument("--input", required=True, help="features_output.csv 경로")
    parser.add_argument("--output-dir", default="models", help="모델 저장 폴더")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"[1/4] 데이터 로드: {args.input}")
    X, y, feature_cols = load_dataset(args.input)
    print(f"  - 샘플 수: {len(X)}, 피처 수: {len(feature_cols)}, 피싱 비율: {y.mean():.2%}")

    print("[2/4] train/test 분할")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("[3/4] 모델 학습 및 평가")
    results = {}
    models = {}

    # Logistic Regression (스케일링된 입력 사용)
    lr = LogisticRegression(max_iter=1000, random_state=args.random_state)
    lr.fit(X_train_scaled, y_train)
    results["logistic_regression"] = evaluate(lr, X_test_scaled, y_test)
    models["logistic_regression"] = (lr, True)  # True = 스케일링 필요

    # Random Forest (트리 기반, 스케일링 불필요)
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=None, random_state=args.random_state, n_jobs=-1
    )
    rf.fit(X_train, y_train)
    results["random_forest"] = evaluate(rf, X_test, y_test)
    models["random_forest"] = (rf, False)

    # XGBoost
    if HAS_XGB:
        xgb = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            random_state=args.random_state,
            eval_metric="logloss",
            n_jobs=-1,
        )
        xgb.fit(X_train, y_train)
        results["xgboost"] = evaluate(xgb, X_test, y_test)
        models["xgboost"] = (xgb, False)
    else:
        print("  - xgboost 미설치로 건너뜀")

    for name, metrics in results.items():
        print(f"  - {name}: {metrics}")

    best_name = max(results, key=lambda k: results[k]["roc_auc"])
    best_model, needs_scaling = models[best_name]
    print(f"[4/4] 최고 성능 모델: {best_name} (roc_auc={results[best_name]['roc_auc']})")

    joblib.dump(best_model, os.path.join(args.output_dir, "best_model.joblib"))
    joblib.dump(scaler, os.path.join(args.output_dir, "scaler.joblib"))
    with open(os.path.join(args.output_dir, "feature_columns.json"), "w", encoding="utf-8") as f:
        json.dump(feature_cols, f, ensure_ascii=False, indent=2)

    report = {
        "best_model": best_name,
        "needs_scaling": needs_scaling,
        "feature_columns": feature_cols,
        "metrics": results,
        "train_size": len(X_train),
        "test_size": len(X_test),
    }
    with open(os.path.join(args.output_dir, "model_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"\n저장 완료: {args.output_dir}/best_model.joblib, scaler.joblib, model_report.json")


if __name__ == "__main__":
    main()
