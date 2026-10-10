import argparse
import csv
import io
import json
import sys
import tarfile
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend" / "ml_integration"))

from url_features import registered_domain  # noqa: E402

TOP_SITES = "https://registry.npmjs.org/top-sites/-/top-sites-1.1.229.tgz"
OUT = ROOT / "backend" / "resources" / "allowlist" / "domains.txt"

KOREAN_MAJOR = [
    "naver.com", "daum.net", "kakao.com", "kakaocorp.com", "coupang.com", "gmarket.co.kr", "11st.co.kr",
    "auction.co.kr", "ssg.com", "musinsa.com", "baemin.com", "yes24.com", "kyobobook.co.kr", "aladin.co.kr",
    "interpark.com", "melon.com", "kbstar.com", "shinhan.com", "wooribank.com", "hanabank.com", "ibk.co.kr",
    "nonghyup.com", "kakaobank.com", "toss.im", "kakaopay.com", "samsung.com", "lg.co.kr", "sktelecom.com",
    "tworld.co.kr", "kt.com", "lguplus.com", "korail.com", "gov.kr", "hometax.go.kr", "nhis.or.kr",
    "kisa.or.kr", "boho.or.kr", "police.go.kr", "fss.or.kr", "payinfo.or.kr", "msafer.or.kr",
    "chosun.com", "joongang.co.kr", "donga.com", "hani.co.kr", "yna.co.kr", "kbs.co.kr", "mbc.co.kr",
    "sbs.co.kr", "nexon.com", "ncsoft.com", "netmarble.com",
]


def top_sites() -> list:
    with urllib.request.urlopen(TOP_SITES, timeout=60) as r:
        tar = tarfile.open(fileobj=io.BytesIO(r.read()), mode="r:gz")
        data = json.load(tar.extractfile("package/top-sites.json"))
    return [registered_domain(item["rootDomain"]) for item in data]


def main():
    parser = argparse.ArgumentParser(description="공식 도메인 허용 목록 만들기")
    parser.add_argument("--tranco", type=Path)
    parser.add_argument("--tranco-top", type=int, default=10_000)
    args = parser.parse_args()

    sources = {"Moz Top 500": top_sites(), "국내 주요 서비스": [registered_domain(d) for d in KOREAN_MAJOR]}
    if args.tranco:
        with open(args.tranco, encoding="utf-8") as f:
            sources["Tranco"] = [registered_domain(row[1]) for i, row in enumerate(csv.reader(f)) if i < args.tranco_top]

    domains = sorted({d for items in sources.values() for d in items if "." in d})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    header = [f"# 공식 도메인 허용 목록 ({date.today()}) - scripts/build_allowlist.py 로 생성"]
    header += [f"# {name}: {len(items)}개" for name, items in sources.items()]
    OUT.write_text("\n".join(header + domains) + "\n", encoding="utf-8")
    print(f"저장: {OUT} ({len(domains)}개 도메인)")


if __name__ == "__main__":
    main()
