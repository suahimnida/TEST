"""편향을 고친 학습 데이터 만들기.

기존 학습 데이터(PhiUSIIL)는 정상 URL이 100% https://www.도메인 형태이고 경로가 없어서,
모델이 "https://www.이면 정상"이라는 지름길을 배웠다 (docs/evaluation.md).

1. 출처를 섞는다
    PhiUSIIL           정상 홈페이지 + 피싱
    공개 URL 데이터셋   경로가 있는 정상 URL + 경로가 있는 피싱
                       (github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs, data/data.csv)
    KISA 2024          국내 피싱 (도메인만 있는 형태가 많다)
2. 형태를 두 라벨에 똑같이 바꾼다
    scheme(https/http/없음)과 www 유무를 정상·피싱 모두 같은 확률로 무작위로 정해서, 형태만으로는 정답을 알 수 없게 한다.
    피싱 일부는 경로를 떼어 도메인만 남긴다.
3. 평가 세트(evaluation/eval_set.csv)에 있는 도메인은 학습에서 뺀다.

실행: python scripts/build_training_set.py
출력: data/train_v2.csv (url, label, source, domain)  label: 1=피싱, 0=정상
"""

import argparse
import csv
import random
import sys
import urllib.request
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend" / "ml_integration"))

from url_features import registered_domain, split_url  # noqa: E402

DATA = ROOT / "data"
PHIUSIIL = DATA / "PhiUSIIL_Phishing_URL_Dataset.csv"
KISA_2024 = DATA / "한국인터넷진흥원_피싱사이트_20241231.csv"
PUBLIC = DATA / "public_url_dataset.csv"
PUBLIC_URL = "https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv"
EVAL_SET = ROOT / "evaluation" / "eval_set.csv"

SCHEMES = (("https://", 0.45), ("http://", 0.25), ("", 0.30))


def reform(url: str, rng: random.Random, strip_path: bool) -> str:
    """scheme과 www를 무작위로 다시 정한다. host 글자, 경로, 쿼리의 원문은 그대로 둔다."""
    p = split_url(url)
    host = p["netloc"]
    bare = host[4:] if host.lower().startswith("www.") else host
    if host != bare:
        host = bare if rng.random() < 0.5 else host
    elif registered_domain(split_url(bare)["host"]) == split_url(bare)["host"].lower() and rng.random() < 0.3:
        host = "www." + bare
    scheme = rng.choices([s for s, _ in SCHEMES], weights=[w for _, w in SCHEMES])[0]
    rest = "" if strip_path else p["path"] + ("?" + p["query"] if p["query"] else "")
    return scheme + host + rest


def load_public() -> pd.DataFrame:
    if not PUBLIC.exists():
        print(f"공개 URL 데이터셋 내려받는 중: {PUBLIC_URL}")
        urllib.request.urlretrieve(PUBLIC_URL, PUBLIC)
    df = pd.read_csv(PUBLIC)
    df["label"] = (df["label"] == "bad").astype(int)
    df["source"] = "공개 데이터셋"
    return df[["url", "label", "source"]]


def load_phiusiil() -> pd.DataFrame:
    df = pd.read_csv(PHIUSIIL, usecols=["URL", "label"]).rename(columns={"URL": "url"})
    df["label"] = 1 - df["label"]  # 원본 1=정상
    df["source"] = "PhiUSIIL"
    return df


def load_kisa() -> pd.DataFrame:
    rows = []
    with open(KISA_2024, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            url = (r.get("홈페이지주소") or "").strip()
            if url:
                rows.append({"url": url, "label": 1, "source": "KISA 2024"})
    return pd.DataFrame(rows)


def cap_per_domain(df: pd.DataFrame, cap: int, seed: int) -> pd.DataFrame:
    df = df.sample(frac=1, random_state=seed)
    return df[df.groupby("domain").cumcount() < cap]


def main():
    parser = argparse.ArgumentParser(description="편향을 고친 학습 데이터 만들기")
    parser.add_argument("--per-class", type=int, default=100_000, help="라벨별 최대 건수")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    rng = random.Random(args.seed)

    df = pd.concat([load_phiusiil(), load_public(), load_kisa()], ignore_index=True)
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df.url.str.len() > 3]
    df["domain"] = [registered_domain(split_url(u)["host"]) for u in df.url]
    df = df[df.domain.str.contains(r"\.", regex=True) | df.domain.str.match(r"^\d")]

    eval_domains = {registered_domain(split_url(u)["host"]) for u in pd.read_csv(EVAL_SET).url}
    before = len(df)
    df = df[~df.domain.isin(eval_domains)]
    print(f"평가 세트 도메인 제외: {before - len(df)}건")

    df = df.drop_duplicates("url")
    conflict = df.groupby("url").label.nunique()
    df = df[~df.url.isin(conflict[conflict > 1].index)]
    # 한 캠페인·한 사이트가 학습을 좌우하지 않도록 도메인당 건수를 제한한다
    df = pd.concat([cap_per_domain(df[df.label == 1], 5, args.seed), cap_per_domain(df[df.label == 0], 20, args.seed)])

    parts = []
    for label, mix in ((0, {"PhiUSIIL": 0.5, "공개 데이터셋": 0.5}), (1, {"PhiUSIIL": 0.45, "공개 데이터셋": 0.35, "KISA 2024": 0.20})):
        for source, share in mix.items():
            pool = df[(df.label == label) & (df.source == source)]
            n = min(len(pool), int(args.per_class * share))
            parts.append(pool.sample(n=n, random_state=args.seed))
    df = pd.concat(parts, ignore_index=True)

    df["url"] = [
        reform(u, rng, strip_path=(lab == 1 and rng.random() < 0.25)) for u, lab in zip(df.url, df.label)
    ]
    df = df.drop_duplicates("url").sample(frac=1, random_state=args.seed)

    out = DATA / "train_v2.csv"
    df[["url", "label", "source", "domain"]].to_csv(out, index=False, encoding="utf-8")
    print(f"저장: {out} ({len(df)}건)")
    for label, name in ((0, "정상"), (1, "피싱")):
        sub = df[df.label == label]
        forms = Counter(split_url(u)["scheme"] or "없음" for u in sub.url)
        path = sum(bool(split_url(u)["path"].strip("/")) for u in sub.url) / len(sub)
        www = sum(split_url(u)["host"].lower().startswith("www.") for u in sub.url) / len(sub)
        print(f"  {name} {len(sub)}건 | 출처 {sub.source.value_counts().to_dict()} | scheme {dict(forms)} | www {www:.0%} | 경로 {path:.0%}")


if __name__ == "__main__":
    main()
