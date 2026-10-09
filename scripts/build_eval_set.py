"""외부 평가 세트 만들기.

피싱: KISA 2023 목록 중 2024 블랙리스트에 없고, 학습 데이터(PhiUSIIL)에 없던 도메인.
      한 캠페인이 평가를 좌우하지 않도록 등록 도메인당 최대 --max-per-domain건만 쓴다
정상: evaluation/legit_domains.csv 도메인의 4가지 형태 + evaluation/legit_paths.csv
      (--tranco로 Tranco 상위 사이트 목록 CSV를 주면 그 도메인도 추가)

실행: python scripts/build_eval_set.py
출력: evaluation/eval_set.csv
"""

import argparse
import csv
import json
import random
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.services.detections import _registered_domain  # noqa: E402

DATA = ROOT / "data"
EVAL = ROOT / "evaluation"
KISA_2023 = DATA / "한국인터넷진흥원_피싱사이트 URL_20231231.csv"
PHIUSIIL = DATA / "PhiUSIIL_Phishing_URL_Dataset.csv"
BLACKLIST = BACKEND / "resources" / "blacklist"


def host_of(url: str) -> str:
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        return (urlsplit(raw).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def blacklist_key(url: str) -> str:
    u = url.strip().lower()
    for prefix in ("https://", "http://"):
        if u.startswith(prefix):
            u = u[len(prefix):]
    return u.rstrip("/")


def describe(url: str) -> dict:
    """URL 형태 분류. 원문은 바꾸지 않는다."""
    raw = url.strip()
    scheme = raw.split("://", 1)[0].lower() if "://" in raw else ""
    parts = urlsplit(raw if scheme else "http://" + raw)
    host = (parts.hostname or "").lower()
    return {
        "scheme": scheme or "none",
        "has_www": int(host.startswith("www.")),
        "has_path": int(parts.path not in ("", "/")),
        "has_query": int(bool(parts.query)),
    }


def training_domains() -> set:
    domains = set()
    with open(PHIUSIIL, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            h = host_of(row["URL"])
            if h:
                domains.add(_registered_domain(h))
    return domains


def phishing_rows(train: set, limit: int, seed: int, max_per_domain: int) -> list:
    urls = set(json.loads((BLACKLIST / "urls.json").read_text(encoding="utf-8")))
    hosts = set(json.loads((BLACKLIST / "hosts.json").read_text(encoding="utf-8")))

    seen, rows, dropped = set(), [], {"blacklist": 0, "train_domain": 0, "duplicate": 0}
    with open(KISA_2023, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            url = (row.get("홈페이지주소") or "").strip()
            host = host_of(url)
            if not url or not host:
                continue
            key = blacklist_key(url)
            if key in seen:
                dropped["duplicate"] += 1
                continue
            seen.add(key)
            if key in urls or host in hosts:
                dropped["blacklist"] += 1
                continue
            if _registered_domain(host) in train:
                dropped["train_domain"] += 1
                continue
            rows.append({"url": url, "label": 1, "source": "KISA 2023", "korean": 1, "note": ""})

    random.Random(seed).shuffle(rows)
    per_domain, picked = {}, []
    for r in rows:
        d = _registered_domain(host_of(r["url"]))
        if per_domain.get(d, 0) < max_per_domain:
            per_domain[d] = per_domain.get(d, 0) + 1
            picked.append(r)
    print(
        f"KISA 2023 피싱: 조건에 맞는 {len(rows)}건 → 도메인당 최대 {max_per_domain}건 {len(picked)}건 "
        f"(등록 도메인 {len(per_domain)}개, 제외: {dropped})"
    )
    return picked[:limit]


def legit_rows(tranco: Path | None, tranco_top: int) -> list:
    rows = []
    with open(EVAL / "legit_domains.csv", encoding="utf-8") as f:
        domains = [(r["domain"], int(r["korean"]), "직접 선정") for r in csv.DictReader(f)]
    if tranco:
        with open(tranco, encoding="utf-8") as f:
            for i, (_, domain) in enumerate(csv.reader(f)):
                if i >= tranco_top:
                    break
                domains.append((domain.strip(), int(domain.endswith(".kr")), "Tranco"))

    for domain, korean, source in domains:
        for url in (f"https://www.{domain}", f"https://{domain}", f"http://{domain}", domain):
            rows.append({"url": url, "label": 0, "source": source, "korean": korean, "note": "홈페이지 형태 변형"})

    with open(EVAL / "legit_paths.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append({"url": r["url"], "label": 0, "source": "직접 선정", "korean": int(r["korean"]), "note": r["note"]})
    return rows


def main():
    parser = argparse.ArgumentParser(description="외부 평가 세트 만들기")
    parser.add_argument("--phishing-limit", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-per-domain", type=int, default=3)
    parser.add_argument("--tranco", type=Path, help="Tranco 목록 CSV (순위,도메인)")
    parser.add_argument("--tranco-top", type=int, default=1000)
    args = parser.parse_args()

    print("학습 데이터 도메인 읽는 중...")
    train = training_domains()
    rows = phishing_rows(train, args.phishing_limit, args.seed, args.max_per_domain) + legit_rows(args.tranco, args.tranco_top)

    seen, unique = set(), []
    for r in rows:
        if r["url"] not in seen:
            seen.add(r["url"])
            unique.append(r)

    out = EVAL / "eval_set.csv"
    fields = ["url", "label", "source", "korean", "scheme", "has_www", "has_path", "has_query", "in_train_domain", "note"]
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in unique:
            r.update(describe(r["url"]))
            r["in_train_domain"] = int(_registered_domain(host_of(r["url"])) in train)
            w.writerow(r)

    phishing = sum(r["label"] for r in unique)
    print(f"저장: {out} (피싱 {phishing}건, 정상 {len(unique) - phishing}건)")


if __name__ == "__main__":
    main()
