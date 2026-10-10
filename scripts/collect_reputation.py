import argparse
import csv
import random
import sys
import time
import urllib.request
from datetime import date
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "backend" / "ml_integration"))

from app.services import reputation  # noqa: E402
from url_features import registered_domain, split_url  # noqa: E402

OUT = ROOT / "evaluation" / "reputation"
LOG = OUT / "log.csv"
OPENPHISH = "https://openphish.com/feed.txt"
ALLOWLIST = ROOT / "backend" / "resources" / "allowlist" / "domains.txt"
FIELDS = ["date", "label", "source", "url", "domain", "rdap_status", "domain_age_days", "ct_status",
          "cert_age_days", "hosting_status", "asn", "as_name", "country"]


def read_lines(path: Path) -> list:
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]


def phishing_urls(args) -> list:
    if args.phishing_file:
        return read_lines(args.phishing_file)
    with urllib.request.urlopen(OPENPHISH, timeout=30) as r:
        return [l.strip() for l in r.read().decode("utf-8", "ignore").splitlines() if l.strip()]


def legit_urls(args) -> list:
    urls = read_lines(args.legit_file) if args.legit_file else []
    popular = read_lines(ALLOWLIST)
    random.shuffle(popular)
    return urls + [f"https://{d}" for d in popular[: args.limit // 4]]


def collect(args):
    OUT.mkdir(parents=True, exist_ok=True)
    seen = set(pd.read_csv(LOG).domain) if LOG.exists() else set()
    rows = []
    for label, source, urls in ((1, args.phishing_source, phishing_urls(args)), (0, "정상 목록", legit_urls(args))):
        random.shuffle(urls)
        count = 0
        for url in urls:
            domain = registered_domain(split_url(url)["host"])
            if not domain or domain in seen or count >= args.limit:
                continue
            seen.add(domain)
            info = reputation.lookup(url)
            rdap, ct, hosting = info["rdap"], info["ct"], info["hosting"]
            rows.append({
                "date": date.today().isoformat(), "label": label, "source": source, "url": url, "domain": domain,
                "rdap_status": rdap["status"], "domain_age_days": rdap.get("age_days"),
                "ct_status": ct["status"], "cert_age_days": ct.get("age_days"),
                "hosting_status": hosting["status"], "asn": hosting.get("asn"),
                "as_name": hosting.get("as_name"), "country": hosting.get("country"),
            })
            count += 1
            time.sleep(args.delay)  # 외부 서비스 요청 제한을 지키기 위해 천천히 조회
        print(f"{'피싱' if label else '정상'}: {count}개 도메인 조회")

    new = not LOG.exists()
    with open(LOG, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            writer.writeheader()
        writer.writerows(rows)
    print(f"기록: {LOG} (+{len(rows)}건)")


def summarize(args):
    df = pd.read_csv(LOG)
    lines = [f"# 평판 신호 분포 ({df.date.min()} ~ {df.date.max()}, 자동 생성)\n",
             f"피싱 {int((df.label == 1).sum())}개, 정상 {int((df.label == 0).sum())}개 도메인\n",
             "\n정상 도메인이 유명 사이트 위주면 '오래된 도메인' 비율이 과장된다. 정상 목록의 출처를 함께 확인할 것.\n",
             "\n| 신호 | 피싱 | 정상 |\n|---|---|---|\n"]
    checks = {
        "등록 30일 이내": lambda d: d.domain_age_days.le(30),
        "등록 1년 이내": lambda d: d.domain_age_days.le(365),
        "등록 정보 없음 (RDAP 404)": lambda d: d.rdap_status.eq("not_found"),
        "등록일 확인 불가 (미지원·오류)": lambda d: d.rdap_status.isin(["unsupported", "error", "unknown"]),
        "첫 인증서 30일 이내": lambda d: d.cert_age_days.le(30),
        "인증서 기록 없음": lambda d: d.ct_status.eq("none"),
        "DNS에 도메인 없음": lambda d: d.hosting_status.eq("nxdomain"),
    }
    for name, fn in checks.items():
        p, l = df[df.label == 1], df[df.label == 0]
        lines.append(f"| {name} | {fn(p).mean():.1%} | {fn(l).mean():.1%} |\n")

    asn = df.dropna(subset=["asn"]).groupby("asn").agg(
        이름=("as_name", "first"), 피싱=("label", "sum"), 전체=("label", "size"))
    asn["피싱 비율"] = (asn["피싱"] / asn["전체"]).round(3)
    asn = asn[asn["전체"] >= args.min_count].sort_values(["피싱 비율", "전체"], ascending=False).head(15)
    lines.append(f"\n## 호스팅 업체별 피싱 비율 (도메인 {args.min_count}개 이상)\n\n")
    lines.append("이 표로 피싱 비율이 눈에 띄게 높은 곳만 근거로 쓴다. 짐작으로 업체를 위험하다고 표시하지 않는다.\n\n")
    if len(asn):
        lines.append("| ASN | 이름 | 피싱 | 전체 | 피싱 비율 |\n|---|---|---|---|---|\n")
        lines += [f"| {k} | {r['이름']} | {r['피싱']} | {r['전체']} | {r['피싱 비율']:.1%} |\n" for k, r in asn.iterrows()]
    else:
        lines.append("(데이터 부족)\n")
    (OUT / "summary.md").write_text("".join(lines), encoding="utf-8")
    print("".join(lines))


def main():
    parser = argparse.ArgumentParser(description="평판 신호 평가 데이터")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--phishing-file", type=Path)
    c.add_argument("--phishing-source", default="OpenPhish")
    c.add_argument("--legit-file", type=Path, help="정상 URL 목록 (한 줄에 하나)")
    c.add_argument("--limit", type=int, default=200, help="라벨별 하루 최대 도메인 수")
    c.add_argument("--delay", type=float, default=1.0, help="조회 사이 대기 시간(초)")
    s = sub.add_parser("summarize")
    s.add_argument("--min-count", type=int, default=5)
    args = parser.parse_args()
    collect(args) if args.cmd == "collect" else summarize(args)


if __name__ == "__main__":
    main()
