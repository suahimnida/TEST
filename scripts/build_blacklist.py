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
    u = raw_url.strip()
    u = re.sub(r"^https?://", "", u, flags=re.I)
    u = u.rstrip("/")
    return u.lower()


def host_of(normalized_url: str) -> str:
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