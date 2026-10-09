import argparse
import math
import re
from collections import Counter
from urllib.parse import urlparse

import pandas as pd

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "webscr", "ebayisapi", "password", "auth",
    "paypal", "kakao", "naver", "coupang", "wallet", "bonus",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "buly.kr", "url.kr",
    "han.gl", "vo.la", "is.gd", "ow.ly", "me2.do", "abit.ly",
}

IP_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def char_ngrams(s: str, n: int = 3) -> list:
    if len(s) < n:
        return [s] if s else []
    return [s[i:i + n] for i in range(len(s) - n + 1)]


def is_ip_address(host: str) -> int:
    if not host:
        return 0
    return 1 if IP_PATTERN.match(host) else 0


def has_punycode(host: str) -> int:
    return 1 if "xn--" in (host or "") else 0


def count_suspicious_keywords(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def is_shortener(host: str) -> int:
    if not host:
        return 0
    host = host.lower().replace("www.", "")
    return 1 if host in SHORTENER_DOMAINS else 0


def safe_urlparse(url: str):
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    try:
        return urlparse(url)
    except ValueError:
        return urlparse("http://invalid")


def extract_features(url: str) -> dict:
    parsed = safe_urlparse(url)
    host = parsed.netloc.split(":")[0] 
    path = parsed.path or ""
    query = parsed.query or ""
    subdomain_parts = host.split(".")
    subdomain_count = max(len(subdomain_parts) - 2, 0) if len(subdomain_parts) > 2 else 0

    digits = sum(c.isdigit() for c in url)
    special_chars = sum(1 for c in url if not c.isalnum() and c not in "://.")
    total_len = len(url) if len(url) > 0 else 1

    features = {
        "url": url,
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "subdomain_count": subdomain_count,
        "digit_count": digits,
        "special_char_count": special_chars,
        "special_char_ratio": round(special_chars / total_len, 4),
        "digit_ratio": round(digits / total_len, 4),
        "is_ip_domain": is_ip_address(host),
        "has_punycode": has_punycode(host),
        "suspicious_keyword_count": count_suspicious_keywords(url),
        "is_shortener": is_shortener(host),
        "url_entropy": round(shannon_entropy(url), 4),
        "path_entropy": round(shannon_entropy(path), 4),
        "host_entropy": round(shannon_entropy(host), 4),
        "count_dash": url.count("-"),
        "count_at": url.count("@"),
        "count_dot": url.count("."),
        "count_equal": url.count("="),
        "count_www": url.lower().count("www"),
    }

    ngrams = char_ngrams(url.lower(), n=3)
    top_ngrams = [g for g, _ in Counter(ngrams).most_common(3)]
    features["top_3gram_1"] = top_ngrams[0] if len(top_ngrams) > 0 else ""
    features["top_3gram_2"] = top_ngrams[1] if len(top_ngrams) > 1 else ""
    features["top_3gram_3"] = top_ngrams[2] if len(top_ngrams) > 2 else ""

    return features


def normalize_label(value) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    v = str(value).strip().lower()
    if v in ("1", "phishing", "bad", "malicious", "phish"):
        return 1
    if v in ("0", "legitimate", "good", "benign", "normal"):
        return 0
    raise ValueError(f"알 수 없는 라벨 값: {value}")


def clean_dataframe(df: pd.DataFrame, url_col: str, label_col: str) -> pd.DataFrame:
    df = df[[url_col, label_col]].copy()
    df.columns = ["url", "label"]

    before = len(df)
    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""]
    df = df.drop_duplicates(subset=["url"])
    after_clean = len(df)

    print(f"[정제] 원본 {before}건 -> 결측치/빈값/중복 제거 후 {after_clean}건")

    return df


def build_feature_dataset(df: pd.DataFrame) -> pd.DataFrame:
    records = []
    for _, row in df.iterrows():
        feats = extract_features(row["url"])
        feats["label"] = row["label"]
        records.append(feats)
    return pd.DataFrame(records)


def main():
    parser = argparse.ArgumentParser(description="피싱 URL 데이터 정제 및 특징 추출")
    parser.add_argument("--input", required=True, help="원본 데이터셋 CSV 경로")
    parser.add_argument("--output", default="features_output.csv", help="출력 CSV 경로")
    parser.add_argument("--url-col", default="url", help="원본 데이터의 URL 컬럼명")
    parser.add_argument("--label-col", default="label", help="원본 데이터의 라벨 컬럼명")
    parser.add_argument(
        "--invert-label",
        action="store_true",
        help=(
            "원본 라벨이 '1=정상, 0=피싱' 방향일 때 사용 (예: UCI PHIUSIIL 원본). "
            "우리 프로젝트 표준(1=피싱, 0=정상)으로 뒤집어서 저장함."
        ),
    )
    args = parser.parse_args()

    print(f"[1/4] 데이터 로드: {args.input}")
    df = pd.read_csv(args.input)

    print(f"[2/4] 컬럼 확인 및 정제 (url_col={args.url_col}, label_col={args.label_col})")
    df = clean_dataframe(df, args.url_col, args.label_col)
    df["label"] = df["label"].apply(normalize_label)
    if args.invert_label:
        print("[정제] --invert-label 적용: 원본 라벨(1=정상,0=피싱) -> 표준(1=피싱,0=정상)으로 반전")
        df["label"] = 1 - df["label"]

    print("[3/4] 특징 추출 진행 중...")
    feature_df = build_feature_dataset(df)

    print(f"[4/4] 결과 저장: {args.output}")
    feature_df.to_csv(args.output, index=False, encoding="utf-8-sig")

    print("\n=== 요약 ===")
    print(f"총 샘플 수: {len(feature_df)}")
    print(f"정상(0) : {(feature_df['label'] == 0).sum()}건")
    print(f"피싱(1) : {(feature_df['label'] == 1).sum()}건")
    print(f"생성된 특징 컬럼 수: {len(feature_df.columns) - 2}개 (url, label 제외)")


if __name__ == "__main__":
    main()
