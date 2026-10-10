"""ML 모델 평가: 오탐률·미탐률, 형태별 결과, 오답 분석.

실행:
    python scripts/evaluate_model.py              서비스 모델(v2) 외부 평가
    python scripts/evaluate_model.py --model v1   기존 랜덤 포레스트 모델 외부 평가
    python scripts/evaluate_model.py --internal   기존 PhiUSIIL 내부 평가 세트도 함께

출력: evaluation/results/ (metrics.json, summary.md, false_positives.csv, false_negatives.csv)
"""

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / "backend" / "ml_integration"
sys.path.insert(0, str(ML))

from preprocess import SUSPICIOUS_KEYWORDS, extract_features, safe_urlparse  # noqa: E402

EVAL = ROOT / "evaluation"
RESULTS = EVAL / "results"
THRESHOLDS = {"의심 이상 (30점)": 30, "모델 기준 (50점)": 50, "피싱 판정 (60점)": 60}
FREE_HOSTING = (
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "github.io", "vercel.app",
    "netlify.app", "herokuapp.com", "blogspot.com", "wixsite.com", "weebly.com", "glitch.me",
    "repl.co", "ngrok.io", "ngrok-free.app", "000webhostapp.com", "run.app", "appspot.com",
)


REQUIRED_SKLEARN = "1.3.2"


def check_environment():
    """모델은 scikit-learn 1.3.2로 저장됐다. 다른 버전으로 불러오면 오류 없이 엉뚱한 점수가 나온다."""
    if sklearn.__version__ != REQUIRED_SKLEARN:
        sys.exit(
            f"[중단] scikit-learn {sklearn.__version__}에서는 모델 점수가 올바르게 계산되지 않습니다.\n"
            f"       모델이 저장된 버전({REQUIRED_SKLEARN})과 Python 3.12 가상환경에서 실행하세요.\n"
            f"       현재 Python: {sys.version.split()[0]} ({sys.executable})"
        )


def load_model(version="v1"):
    if version == "v2":
        report = json.loads((ML / "models" / "url_model_v2_report.json").read_text(encoding="utf-8"))
        return {"model": joblib.load(ML / "models" / "url_model_v2.joblib"), "report": report}, None
    model = joblib.load(ML / "models" / "best_model.joblib")
    columns = json.loads((ML / "models" / "feature_columns.json").read_text(encoding="utf-8"))
    return model, columns


def score(urls, model, columns) -> pd.DataFrame:
    feats = pd.DataFrame([extract_features(u) for u in urls])
    if columns is None:  # v2: 원문 URL을 받는 파이프라인 + 기준점 보정
        from url_features import calibrate

        raw = model["model"].predict_proba(list(urls))[:, 1] * 100
        t = model["report"]["thresholds"]
        feats["score"] = [calibrate(v, t["suspicious"], t["phishing"]) for v in raw]
    else:
        feats["score"] = model.predict_proba(feats[columns])[:, 1] * 100
    if feats["score"].min() < 0 or feats["score"].max() > 100:
        sys.exit("[중단] 모델 점수가 0~100 범위를 벗어났습니다. scikit-learn 버전을 확인하세요.")
    return feats


def confusion(y, s, threshold) -> dict:
    pred = s >= threshold
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    fn, tn = int((~pred & (y == 1)).sum()), int((~pred & (y == 0)).sum())
    rate = lambda a, b: round(a / b, 4) if b else None
    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "오탐률(FPR)": rate(fp, fp + tn),
        "미탐률(FNR)": rate(fn, fn + tp),
        "정밀도": rate(tp, tp + fp),
        "재현율": rate(tp, tp + fn),
    }


def metrics(y, s) -> dict:
    out = {name: confusion(y, s, t) for name, t in THRESHOLDS.items()}
    if len(set(y)) == 2:
        out["ROC-AUC"] = round(roc_auc_score(y, s), 4)
        out["PR-AUC"] = round(average_precision_score(y, s), 4)
    return out


def shortcut_rule(urls) -> np.ndarray:
    """데이터셋 편향을 확인하는 비교 기준: https://www.로 시작하고 경로가 없으면 정상(0), 아니면 피싱(1)."""
    u = pd.Series(list(urls)).str.strip().str.lower()
    has_path = u.str.replace(r"^[a-z]+://", "", regex=True).str.contains("/.", regex=True)
    return (~(u.str.startswith("https://www.") & ~has_path)).astype(int).to_numpy() * 100


def error_type(row) -> str:
    """오답이 왜 생겼는지 URL 형태로 분류한다."""
    url = row["url"].lower()
    host = (safe_urlparse(row["url"]).hostname or "").lower()
    if row["label"] == 0:
        if row["scheme"] != "https" or not row["has_www"]:
            if not row["has_path"]:
                return "정상 홈페이지인데 https://www. 형태가 아님"
        if row["has_path"]:
            if any(k in url for k in SUSPICIOUS_KEYWORDS):
                return "정상 서비스의 로그인·계정 경로 (의심 키워드 포함)"
            return "경로가 있는 정상 URL"
        return "기타 정상"
    if any(host == h or host.endswith("." + h) for h in FREE_HOSTING):
        return "무료 호스팅·플랫폼 하위 도메인"
    if row["is_shortener"]:
        return "단축 URL"
    if "/wp-" in url:
        return "해킹당한 사이트로 의심되는 경로"
    if row["suspicious_keyword_count"] == 0 and not row["is_ip_domain"] and row["host_length"] <= 20:
        return "의심 특징이 거의 없는 짧은 도메인"
    return "기타 피싱"


def slice_table(df, label, col, values) -> list:
    rows = []
    part = df[df.label == label]
    for name, mask in values:
        sub = part[mask(part)]
        if len(sub) == 0:
            continue
        wrong = (sub.score >= 60) if label == 0 else (sub.score < 60)
        rows.append({"형태": name, "건수": len(sub), col: round(wrong.mean(), 4), "평균 점수": round(sub.score.mean(), 1)})
    return rows


def internal_eval(model, columns) -> dict:
    """학습 스크립트(train_model.py)와 같은 방식으로 나눈 내부 평가 세트."""
    from sklearn.model_selection import train_test_split

    raw = pd.read_csv(ROOT / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"])
    raw["label"] = 1 - raw["label"]  # 원본 1=정상 → 모델 기준 1=피싱
    _, test = train_test_split(raw, test_size=0.2, random_state=42, stratify=raw["label"])
    scored = score(test["URL"].tolist(), model, columns)
    y = test["label"].to_numpy()
    return {
        "ML 모델": metrics(y, scored["score"].to_numpy()),
        "지름길 규칙": metrics(y, shortcut_rule(test["URL"])),
    }


def md_table(rows) -> str:
    if not rows:
        return "(없음)\n"
    cols = list(rows[0])
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(str(r[c]) for c in cols) + " |" for r in rows]
    return "\n".join(lines) + "\n"


def confusion_rows(m) -> list:
    return [{"기준": k, **v} for k, v in m.items() if isinstance(v, dict) and "FP" in v]


def main():
    parser = argparse.ArgumentParser(description="ML 모델 평가")
    parser.add_argument("--eval-set", type=Path, default=EVAL / "eval_set.csv")
    parser.add_argument("--internal", action="store_true", help="내부 평가 세트도 계산 (몇 분 걸림)")
    parser.add_argument("--model", choices=["v1", "v2"], default="v2", help="v2: 서비스 모델, v1: 기존 랜덤 포레스트")
    args = parser.parse_args()

    check_environment()
    model, columns = load_model(args.model)
    global RESULTS
    RESULTS = EVAL / "results" / args.model
    data = pd.read_csv(args.eval_set)
    scored = score(data["url"].tolist(), model, columns)
    df = pd.concat([data.reset_index(drop=True), scored.drop(columns=["url"])], axis=1)
    y, s = df["label"].to_numpy(), df["score"].to_numpy()

    report = {"외부 평가 세트": {"건수": {"피싱": int(y.sum()), "정상": int((y == 0).sum())}, **metrics(y, s)}}
    sys.path.insert(0, str(ROOT / "backend"))
    from app.services import allowlist, verdict

    allowed = np.array([allowlist.check(u).matched for u in df["url"]])
    system = np.where(allowed, np.minimum(s, verdict.ALLOWLIST_CAP), s)
    report["서비스 전체 (ML + 허용 목록)"] = metrics(y, system)
    report["허용 목록 적용 범위"] = {
        "정상 URL 중 허용 목록 일치": round(float(allowed[y == 0].mean()), 4),
        "피싱 URL 중 허용 목록 일치": round(float(allowed[y == 1].mean()), 4),
    }
    rule = shortcut_rule(df["url"])
    report["외부 평가 세트 - 지름길 규칙"] = metrics(y, rule)
    report["모델과 지름길 규칙의 판정 일치율"] = round(float(((s >= 50) == (rule >= 50)).mean()), 4)
    unseen = df[(df.label == 1) | (df.in_train_domain == 0)]
    report["외부 평가 세트 (학습에 없던 도메인만)"] = metrics(unseen.label.to_numpy(), unseen.score.to_numpy())
    if args.internal:
        print("내부 평가 세트 계산 중 (PhiUSIIL 4만 7천 건)...")
        internal = internal_eval(model, columns)
        report["내부 평가 세트 (PhiUSIIL) - ML 모델"] = internal["ML 모델"]
        report["내부 평가 세트 (PhiUSIIL) - 지름길 규칙"] = internal["지름길 규칙"]

    legit_slices = slice_table(df, 0, "오탐률(60점)", [
        ("https://www.도메인 (학습 데이터와 같은 형태)", lambda d: (d.scheme == "https") & (d.has_www == 1) & (d.has_path == 0)),
        ("https://도메인 (www 없음)", lambda d: (d.scheme == "https") & (d.has_www == 0) & (d.has_path == 0)),
        ("http://도메인", lambda d: (d.scheme == "http") & (d.has_path == 0)),
        ("scheme 없이 도메인만", lambda d: d.scheme == "none"),
        ("경로가 있는 URL", lambda d: d.has_path == 1),
        ("한국 서비스", lambda d: d.korean == 1),
        ("해외 서비스", lambda d: d.korean == 0),
        ("학습 데이터에 있던 도메인", lambda d: d.in_train_domain == 1),
        ("학습 데이터에 없던 도메인", lambda d: d.in_train_domain == 0),
    ])
    report["정상 URL 형태별 오탐률"] = legit_slices

    df["error_type"] = ""
    fp = df[(df.label == 0) & (df.score >= 60)].copy()
    fn = df[(df.label == 1) & (df.score < 60)].copy()
    fp["error_type"] = [error_type(row) for _, row in fp.iterrows()]
    fn["error_type"] = [error_type(row) for _, row in fn.iterrows()]
    report["오탐 유형"] = fp.error_type.value_counts().to_dict()
    report["미탐 유형"] = fn.error_type.value_counts().to_dict()

    RESULTS.mkdir(parents=True, exist_ok=True)
    keep = ["url", "label", "score", "error_type", "source", "scheme", "has_www", "has_path", "korean",
            "in_train_domain", "url_length", "host_length", "path_length", "subdomain_count",
            "suspicious_keyword_count", "count_www", "count_dash", "url_entropy", "host_entropy", "note"]
    fp.sort_values("score", ascending=False)[keep].round(2).to_csv(RESULTS / "false_positives.csv", index=False, encoding="utf-8-sig")
    fn.sort_values("score")[keep].round(2).to_csv(RESULTS / "false_negatives.csv", index=False, encoding="utf-8-sig")
    (RESULTS / "metrics.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    must = df[df.url.isin([
        "https://www.naver.com", "naver.com", "http://naver.com", "https://github.com",
        "https://github.com/suahimnida/TEST", "https://nid.naver.com/nidlogin.login?mode=form&url=https://www.naver.com/",
        "https://www.google.com", "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    ])][["url", "score"]].round(1)

    lines = [f"# 모델 평가 결과 (자동 생성, 모델 {args.model})\n", f"평가 세트: 피싱 {int(y.sum())}건, 정상 {int((y == 0).sum())}건\n"]
    for name, m in report.items():
        if isinstance(m, dict) and any(isinstance(v, dict) and "FP" in v for v in m.values()):
            lines += [f"\n## {name}\n", md_table(confusion_rows(m))]
            if "ROC-AUC" in m:
                lines.append(f"\nROC-AUC {m['ROC-AUC']}, PR-AUC {m['PR-AUC']}\n")
    cover = report["허용 목록 적용 범위"]
    lines.append(f"\n허용 목록 일치: 정상 {cover['정상 URL 중 허용 목록 일치']:.1%}, 피싱 {cover['피싱 URL 중 허용 목록 일치']:.1%}\n")
    lines.append(f"\n모델과 지름길 규칙의 판정 일치율: {report['모델과 지름길 규칙의 판정 일치율']:.2%}\n")
    lines.append("(지름길 규칙: https://www.로 시작하고 경로가 없으면 정상, 아니면 피싱. 0점 또는 100점만 내므로 기준과 관계없이 결과가 같다)\n")
    lines += ["\n## 정상 URL 형태별 오탐률 (60점 기준)\n", md_table(legit_slices)]
    lines += ["\n## 필수 확인 사례\n", md_table(must.rename(columns={"score": "점수"}).to_dict("records"))]
    lines += ["\n## 오탐 유형 (60점 기준)\n", md_table([{"유형": k, "건수": v} for k, v in report["오탐 유형"].items()])]
    lines += ["\n## 미탐 유형 (60점 기준)\n", md_table([{"유형": k, "건수": v} for k, v in report["미탐 유형"].items()])]
    (RESULTS / "summary.md").write_text("".join(x if x.endswith("\n") else x + "\n" for x in lines), encoding="utf-8")

    print((RESULTS / "summary.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
