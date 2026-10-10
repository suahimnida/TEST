"""URL 모델 v2 단계별 학습과 비교.

문자 n-gram 기준선에서 시작해 정규화, 구조 분리, 구조 특징, 엔트로피를 하나씩 더하며 비교한다.
모델 선택은 학습 데이터에서 도메인 단위로 떼어 낸 검증 세트로 하고,
외부 평가 세트(evaluation/eval_set.csv)는 결과 확인에만 쓴다.

선택 규칙: 검증 ROC-AUC가 최고와 0.005 이내인 단계 중 가장 단순한 단계 (S1 < S2 < ... < S5b)
기준점: 검증 세트 오탐률이 2% 이하가 되는 점수를 "피싱", 5% 이하가 되는 점수를 "의심" 기준으로 정하고,
        서비스 화면 기준(피싱 60점, 의심 30점)에 맞게 점수를 변환한다 (url_features.calibrate)

실행: python scripts/train_url_model.py            모든 단계 학습 후 최종 선택
      python scripts/train_url_model.py --resume   이어서 학습
      python scripts/train_url_model.py --finalize 학습된 단계 결과로 최종 모델만 다시 만들기
출력: evaluation/results/ablation.md, ablation.json
      backend/ml_integration/models/url_model_v2.joblib, url_model_v2_report.json (선택된 모델)
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, MaxAbsScaler

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / "backend" / "ml_integration"
sys.path.insert(0, str(ML))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import url_features as uf  # noqa: E402
from evaluate_model import shortcut_rule  # noqa: E402

DATA = ROOT / "data"
EVAL = ROOT / "evaluation"
RESULTS = EVAL / "results"


def ngrams(fn, max_features=200_000):
    return Pipeline([
        ("text", FunctionTransformer(fn)),
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=5, max_features=max_features,
                                  sublinear_tf=True, lowercase=False, dtype=np.float32)),
    ])


def numeric(fn):
    # 길이·개수에는 극단값이 많고(경로 길이 수천 자 등) 드문 0/1 특징은 표준화하면 값이 커져서
    # 분류기가 수렴하지 못한다. log(1+x)로 줄인 뒤 0~1 범위로 맞춰 TF-IDF 값과 크기를 비슷하게 한다
    return Pipeline([
        ("values", FunctionTransformer(fn)),
        ("log", FunctionTransformer(np.log1p)),
        ("scale", MaxAbsScaler()),
    ])


def build(step: str) -> Pipeline:
    parts = {
        "S1": [("raw", ngrams(uf.text_raw))],
        "S2": [("normalized", ngrams(uf.text_normalized))],
        "S3": [("host", ngrams(uf.text_host, 100_000)), ("path", ngrams(uf.text_path, 150_000))],
    }
    base = step if step in parts else "S3"
    features = list(parts[base])
    if step in ("S4", "S5a", "S5b"):
        features.append(("struct", numeric(uf.struct_features)))
    if step == "S5a":
        features.append(("entropy", numeric(uf.entropy_host)))
    if step == "S5b":
        features.append(("entropy", numeric(uf.entropy_all)))
    return Pipeline([
        ("features", FeatureUnion(features)),
        ("clf", LogisticRegression(C=4.0, solver="liblinear", max_iter=1000)),
    ])


def slim(model: Pipeline) -> Pipeline:
    """학습 중 버린 n-gram 목록(stop_words_)은 예측에 필요 없고 메모리를 크게 차지해서 지운다."""
    for _, step in model.named_steps["features"].transformer_list:
        tfidf = getattr(step, "named_steps", {}).get("tfidf")
        if tfidf is not None and hasattr(tfidf, "stop_words_"):
            del tfidf.stop_words_
    return model


def rates(y, score, threshold) -> dict:
    pred = score >= threshold
    fp, tn = int((pred & (y == 0)).sum()), int((~pred & (y == 0)).sum())
    fn, tp = int((~pred & (y == 1)).sum()), int((pred & (y == 1)).sum())
    return {"오탐률": round(fp / max(fp + tn, 1), 4), "미탐률": round(fn / max(fn + tp, 1), 4)}


def evaluate(score_val, y_val, score_ext, ext) -> dict:
    y_ext = ext.label.to_numpy()
    legit = ext[ext.label == 0]
    s_legit = score_ext[ext.label.to_numpy() == 0]
    www_home = ((legit.scheme == "https") & (legit.has_www == 1) & (legit.has_path == 0)).to_numpy()
    out = {
        "검증 ROC-AUC": round(roc_auc_score(y_val, score_val), 4) if score_val is not None else None,
        "검증 50점": rates(y_val, score_val, 50) if score_val is not None else None,
        "외부 ROC-AUC": round(roc_auc_score(y_ext, score_ext), 4),
        "외부 60점": rates(y_ext, score_ext, 60),
        "외부 오탐률(https://www 홈페이지)": round(float((s_legit[www_home] >= 60).mean()), 4),
        "외부 오탐률(그 외 정상 형태)": round(float((s_legit[~www_home] >= 60).mean()), 4),
    }
    return out


def old_model_scores(urls) -> np.ndarray:
    from preprocess import extract_features

    model = joblib.load(ML / "models" / "best_model.joblib")
    cols = json.loads((ML / "models" / "feature_columns.json").read_text(encoding="utf-8"))
    return model.predict_proba(pd.DataFrame([extract_features(u) for u in urls])[cols])[:, 1] * 100


def phiusiil_only(eval_domains, n, seed) -> pd.DataFrame:
    df = pd.read_csv(DATA / "PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"]).rename(columns={"URL": "url"})
    df["label"] = 1 - df["label"]
    df["domain"] = [uf.registered_domain(uf.split_url(u)["host"]) for u in df.url]
    df = df[~df.domain.isin(eval_domains)]
    return df.sample(n=min(n, len(df)), random_state=seed)


def md_table(rows) -> str:
    cols = list(rows[0])
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join("-" if r[c] is None else str(r[c]) for c in cols) + " |" for r in rows]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="URL 모델 v2 단계별 학습")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--steps", default="S1_biased,S1,S2,S3,S4,S5a,S5b")
    parser.add_argument("--resume", action="store_true", help="이미 계산한 단계는 건너뛰고 이어서 학습")
    parser.add_argument("--finalize", action="store_true", help="단계별 결과로 최종 모델을 고르고 저장만 한다")
    parser.add_argument("--choose", choices=["S1", "S2", "S3", "S4", "S5a", "S5b"],
                        help="선택 규칙 대신 이 단계를 최종 모델로 쓴다 (보고서에 직접 선택으로 기록)")
    args = parser.parse_args()

    train = pd.read_csv(DATA / "train_v2.csv")
    ext = pd.read_csv(EVAL / "eval_set.csv")
    eval_domains = {uf.registered_domain(uf.split_url(u)["host"]) for u in ext.url}

    split = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=args.seed)
    tr_idx, va_idx = next(split.split(train, groups=train.domain))
    tr, va = train.iloc[tr_idx], train.iloc[va_idx]
    assert not set(tr.domain) & set(va.domain), "학습과 검증에 같은 도메인이 있다"
    print(f"학습 {len(tr)}건, 검증 {len(va)}건 (도메인 단위로 분리), 외부 평가 {len(ext)}건")

    y_va = va.label.to_numpy()
    RESULTS.mkdir(parents=True, exist_ok=True)
    state_path = RESULTS / "ablation_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if args.resume and state_path.exists() else {}
    results = state.get("results", {})
    best = {"auc": state.get("best_auc", -1), "name": state.get("best_name")}
    if "지름길 규칙" not in results:
        results["지름길 규칙"] = evaluate(shortcut_rule(va.url), y_va, shortcut_rule(ext.url), ext)
        results["현재 서비스 모델 (랜덤 포레스트)"] = evaluate(old_model_scores(va.url), y_va, old_model_scores(ext.url), ext)
    names = {
        "S1_biased": "S1-편향: 문자 n-gram, 기존 PhiUSIIL 데이터",
        "S1": "S1: 문자 n-gram (원문)",
        "S2": "S2: + 정규화",
        "S3": "S3: + 구조 분리 (host·path)",
        "S4": "S4: + 구조 특징",
        "S5a": "S5a: + 도메인 엔트로피",
        "S5b": "S5b: + 엔트로피 3개",
    }

    for step in args.steps.split(","):
        name = names[step]
        if name in results:
            print(f"[{step}] 이미 계산됨, 건너뜀")
            continue
        print(f"[{step}] 학습 중...")
        if step == "S1_biased":
            biased = phiusiil_only(eval_domains, len(tr), args.seed)
            model = build("S1").fit(biased.url.tolist(), biased.label.to_numpy())
        else:
            model = build(step).fit(tr.url.tolist(), tr.label.to_numpy())
        model = slim(model)
        s_va = model.predict_proba(va.url.tolist())[:, 1] * 100
        s_ext = model.predict_proba(ext.url.tolist())[:, 1] * 100
        results[name] = evaluate(s_va, y_va, s_ext, ext)
        print("   ", results[name])
        if step != "S1_biased" and results[name]["검증 ROC-AUC"] > best["auc"]:
            best = {"auc": results[name]["검증 ROC-AUC"], "name": name}
        del model
        state_path.write_text(json.dumps({"results": results, "best_auc": best["auc"], "best_name": best["name"]},
                                         ensure_ascii=False, indent=2), encoding="utf-8")

    if args.finalize or set(names.values()) <= set(results):
        finalize(results, names, tr, va, ext, args.choose)


ORDER = ["S1", "S2", "S3", "S4", "S5a", "S5b"]
PHISHING_FPR, SUSPICIOUS_FPR = 0.02, 0.05


def threshold_for_fpr(y, score, target) -> float:
    """검증 세트 정상 URL의 오탐률이 target 이하가 되는 가장 낮은 점수"""
    legit = np.sort(score[y == 0])
    return float(np.round(legit[int(np.ceil(len(legit) * (1 - target))) - 1], 2))


def finalize(results, names, tr, va, ext, choose=None):
    done = [s for s in ORDER if names[s] in results]
    top = max(results[names[s]]["검증 ROC-AUC"] for s in done)
    rule_choice = next(s for s in done if results[names[s]]["검증 ROC-AUC"] >= top - 0.005)
    chosen = choose or rule_choice
    how = "직접 선택 (--choose)" if choose else "검증 ROC-AUC가 최고와 0.005 이내인 단계 중 가장 단순한 단계"
    print(f"선택: {names[chosen]} ({how}, 규칙에 따른 선택은 {names[rule_choice]})")

    model = slim(build(chosen).fit(tr.url.tolist(), tr.label.to_numpy()))
    raw_va = model.predict_proba(va.url.tolist())[:, 1] * 100
    y_va = va.label.to_numpy()
    thresholds = {
        "suspicious": threshold_for_fpr(y_va, raw_va, SUSPICIOUS_FPR),
        "phishing": threshold_for_fpr(y_va, raw_va, PHISHING_FPR),
    }
    cal = lambda raw: np.array([uf.calibrate(v, thresholds["suspicious"], thresholds["phishing"]) for v in raw])
    s_va, s_ext = cal(raw_va), cal(model.predict_proba(ext.url.tolist())[:, 1] * 100)
    final_metrics = evaluate(s_va, y_va, s_ext, ext)
    final_metrics["검증 60점"] = rates(y_va, s_va, 60)
    final_metrics["검증 30점"] = rates(y_va, s_va, 30)
    final_metrics["외부 30점"] = rates(ext.label.to_numpy(), s_ext, 30)
    results[f"최종: {names[chosen]} + 기준점 보정"] = final_metrics
    print("   ", final_metrics)

    joblib.dump(model, ML / "models" / "url_model_v2.joblib", compress=3)
    report = {
        "model": names[chosen],
        "selection_rule": how,
        "thresholds": thresholds,
        "threshold_rule": f"검증 오탐률 {SUSPICIOUS_FPR:.0%} 이하 = 의심(30점), {PHISHING_FPR:.0%} 이하 = 피싱(60점)",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "sklearn_version": sklearn.__version__,
        "train_size": len(tr),
        "metrics": final_metrics,
        "data": "data/train_v2.csv (scripts/build_training_set.py)",
    }
    (ML / "models" / "url_model_v2_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    rows = []
    for name, r in results.items():
        rows.append({
            "모델": name,
            "검증 ROC-AUC": r["검증 ROC-AUC"],
            "검증 오탐률": r["검증 50점"]["오탐률"] if r["검증 50점"] else None,
            "검증 미탐률": r["검증 50점"]["미탐률"] if r["검증 50점"] else None,
            "외부 ROC-AUC": r["외부 ROC-AUC"],
            "외부 오탐률": r["외부 60점"]["오탐률"],
            "외부 미탐률": r["외부 60점"]["미탐률"],
            "외부 오탐률 (https://www 홈페이지 / 그 외)": f'{r["외부 오탐률(https://www 홈페이지)"]} / {r["외부 오탐률(그 외 정상 형태)"]}',
        })
    (RESULTS / "ablation.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    (RESULTS / "ablation.md").write_text(
        "# URL 모델 단계별 비교 (자동 생성)\n\n"
        f"학습 {len(tr)}건 / 검증 {len(va)}건 (도메인 단위 분리) / 외부 평가 {len(ext)}건\n"
        "검증은 50점, 외부는 60점 기준. 최종 행은 기준점 보정 후 점수 기준 (검증·외부 모두 60점)\n\n"
        + md_table(rows)
        + f"\n선택: {names[chosen]} / 기준점: 의심 {thresholds['suspicious']}점, 피싱 {thresholds['phishing']}점 (보정 전 점수)\n",
        encoding="utf-8",
    )
    print(md_table(rows))


if __name__ == "__main__":
    main()
