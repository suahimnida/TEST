"""
backend/scripts/build_blacklist.py

data/한국인터넷진흥원_피싱사이트_20241231.csv (131,752행, 컬럼: 날짜, 홈페이지주소)
를 읽어 중복을 제거하고, 서버가 읽는 블랙리스트 파일 두 개를 만든다.
    backend/resources/blacklist/urls.json
    backend/resources/blacklist/hosts.json

실행 (어느 폴더에서 실행해도 됨):
    python scripts/build_blacklist.py
"""
import csv
import re
import json
import os

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPTS_DIR)
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")

INPUT_CSV = os.path.join(ROOT_DIR, "data", "한국인터넷진흥원_피싱사이트_20241231.csv")
BUILD_DIR = os.path.join(BACKEND_DIR, "resources", "blacklist")
OUT_URLS = os.path.join(BUILD_DIR, "urls.json")
OUT_HOSTS = os.path.join(BUILD_DIR, "hosts.json")


def normalize(raw_url: str) -> str:
    """URL 정규화: 프로토콜과 끝 슬래시를 제거하고 소문자로 통일한다."""
    u = raw_url.strip()
    u = re.sub(r"^https?://", "", u, flags=re.I)
    u = u.rstrip("/")
    return u.lower()


def host_of(normalized_url: str) -> str:
    """정규화된 주소에서 도메인(첫 '/' 이전) 부분만 추출한다."""
    return normalized_url.split("/")[0]


def main():
    urls = set()
    hosts = set()

    with open(INPUT_CSV, encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        next(reader)

        for row in reader:
            if len(row) < 2 or not row[1].strip():
                continue
            n = normalize(row[1])
            if not n:
                continue
            urls.add(n)
            hosts.add(host_of(n))

    urls_list = sorted(urls)
    hosts_list = sorted(hosts)

    os.makedirs(BUILD_DIR, exist_ok=True)

    with open(OUT_URLS, "w", encoding="utf-8") as f:
        json.dump(urls_list, f, ensure_ascii=False, separators=(",", ":"))

    with open(OUT_HOSTS, "w", encoding="utf-8") as f:
        json.dump(hosts_list, f, ensure_ascii=False, separators=(",", ":"))

    print(f"고유 URL:   {len(urls_list):,}개 -> {OUT_URLS}")
    print(f"고유 도메인: {len(hosts_list):,}개 -> {OUT_HOSTS}")


if __name__ == "__main__":
    main()