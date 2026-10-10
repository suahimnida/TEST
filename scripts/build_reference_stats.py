"""정상 데이터 대비 위치를 보여 줄 기준 분포 만들기.

학습 데이터(data/train_v2.csv)의 정상·피싱 URL에서 참고 지표(URL 길이, 도메인 길이 등)를 계산해
정상 URL의 0~100% 지점(101개), 중앙값, 상위 95% 지점과 피싱 URL의 중앙값을 저장한다.

실행: python scripts/build_reference_stats.py
출력: backend/resources/reference/url_stats.json
"""

import json
import sys
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend" / "ml_integration"))

import url_explain  # noqa: E402

TRAIN = ROOT / "data" / "train_v2.csv"
OUT = ROOT / "backend" / "resources" / "reference" / "url_stats.json"


def main():
    df = pd.read_csv(TRAIN)
    rows = pd.DataFrame([url_explain.metric_values(u) for u in df.url])
    rows["label"] = df.label.to_numpy()
    normal, phishing = rows[rows.label == 0], rows[rows.label == 1]
    metrics = {}
    for key, name, _ in url_explain.METRICS:
        q = np.percentile(normal[key], np.arange(101))
        metrics[key] = {
            "name": name,
            "normal_median": float(np.round(np.median(normal[key]), 3)),
            "normal_p95": float(np.round(np.percentile(normal[key], 95), 3)),
            "phishing_median": float(np.round(np.median(phishing[key]), 3)),
            "normal_quantiles": [float(np.round(v, 3)) for v in q],
        }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "source": "data/train_v2.csv (scripts/build_training_set.py)",
        "created": date.today().isoformat(),
        "normal_count": int(len(normal)),
        "phishing_count": int(len(phishing)),
        "metrics": metrics,
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"저장: {OUT} (정상 {len(normal)}건, 피싱 {len(phishing)}건)")
    for key, m in metrics.items():
        print(f"  {m['name']:28} 정상 중앙값 {m['normal_median']:>7} / 정상 95% {m['normal_p95']:>7} / 피싱 중앙값 {m['phishing_median']:>7}")


if __name__ == "__main__":
    main()
