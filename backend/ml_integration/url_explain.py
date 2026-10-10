"""URL 모델 v2의 판단 근거를 수치로 설명한다.

1. 모델 기여도 (정확한 값)
   v2는 문자 n-gram 값에 가중치를 곱해 더하는 선형 모델이다. 그래서 점수(로그 오즈)는
   "기본값 + 각 n-gram의 (가중치 × 값)"과 정확히 같다. 각 n-gram의 기여를 그 n-gram을 이루는
   글자들에 똑같이 나눠 담으면 글자별 위험도가 되고, 이를 URL 부분별로 더하면 부분별 기여도가 된다.
   양수는 피싱 쪽, 음수는 정상 쪽으로 민 정도다.

2. 정상 데이터 대비 위치 (참고 지표)
   URL 길이, 도메인 길이 같은 지표를 학습 데이터의 정상 URL 분포와 비교한다.
   이 지표들은 v2 모델의 입력이 아니라 사람이 이해하기 쉽도록 보여 주는 참고 정보다.
   분포는 scripts/build_reference_stats.py 로 만든 resources/reference/url_stats.json 을 쓴다.
"""

import bisect
import json
from pathlib import Path

import numpy as np

import url_features as uf

STATS_PATH = Path(__file__).resolve().parents[1] / "resources" / "reference" / "url_stats.json"

# 화면에 보여 줄 참고 지표: (키, 이름, 단위)
METRICS = [
    ("url_length", "URL 길이 (scheme 제외)", "자"),
    ("host_length", "도메인 길이", "자"),
    ("subdomain_depth", "하위 도메인 단계", "단계"),
    ("host_hyphens", "도메인 하이픈 수", "개"),
    ("host_digit_ratio", "도메인 숫자 비율", "%"),
    ("host_entropy", "도메인 문자 무작위성 (엔트로피)", ""),
    ("path_length", "경로 길이", "자"),
    ("path_depth", "경로 깊이", "단계"),
    ("query_length", "쿼리 길이", "자"),
    ("keywords", "의심 키워드 수 (도메인+경로)", "개"),
]

_TEXT_FUNCS = {
    uf.text_raw: "원문",
    uf.text_normalized: "정규화",
    uf.text_host: "도메인",
    uf.text_path: "경로",
}


# ---------------------------------------------------------------------------
# URL 부분 나누기
# ---------------------------------------------------------------------------


def segment_url(raw: str) -> list:
    """원문 URL을 (부분 이름, 시작, 끝) 목록으로 나눈다. 원문 글자는 바꾸지 않는다."""
    p = uf.split_url(raw)
    raw = p["raw"]
    parts = []
    pos = 0
    if p["scheme"]:
        end = len(p["scheme"]) + 3
        parts.append(("scheme", 0, end))
        pos = end
    netloc_start = raw.find(p["netloc"], pos)
    if netloc_start < 0:
        return [("전체", 0, len(raw))]
    host_start = raw.find(p["host"], netloc_start)
    if host_start > netloc_start:
        parts.append(("사용자 정보", netloc_start, host_start))
    host = p["host"]
    lower = host.lower()
    cursor = host_start
    if lower.startswith("www."):
        parts.append(("www", cursor, cursor + 4))
        cursor += 4
    rest = host[cursor - host_start:]
    registered = uf.registered_domain(rest)
    reg_start = host_start + len(host) - len(registered) if lower.endswith(registered) else cursor
    if reg_start > cursor:
        parts.append(("하위 도메인", cursor, reg_start))
    tld = registered.split(".", 1)[1] if "." in registered else ""
    name_end = host_start + len(host) - len(tld) - (1 if tld else 0)
    parts.append(("도메인 이름", reg_start, name_end))
    if tld:
        parts.append(("최상위 도메인", name_end, host_start + len(host)))
    netloc_end = netloc_start + len(p["netloc"])
    if netloc_end > host_start + len(host):
        parts.append(("포트", host_start + len(host), netloc_end))
    path_end = netloc_end + len(p["path"])
    if p["path"]:
        parts.append(("경로", netloc_end, path_end))
    if p["query"]:
        parts.append(("쿼리", path_end, path_end + 1 + len(p["query"])))
    if path_end + (1 + len(p["query"]) if p["query"] else 0) < len(raw):
        parts.append(("기타", path_end + (1 + len(p["query"]) if p["query"] else 0), len(raw)))
    return parts


# ---------------------------------------------------------------------------
# 모델 기여도
# ---------------------------------------------------------------------------


def _occurrences(text: str, gram: str) -> list:
    out, start = [], text.find(gram)
    while start >= 0:
        out.append(start)
        start = text.find(gram, start + 1)
    return out


def explain_model(model, url: str, top: int = 6) -> dict:
    """선형 모델(v2 파이프라인)의 점수를 글자별·부분별·n-gram별 기여로 나눈다."""
    raw = uf.split_url(url)["raw"]
    union = model.named_steps["features"]
    coef = model.named_steps["clf"].coef_[0]
    intercept = float(model.named_steps["clf"].intercept_[0])

    char_scores = np.zeros(len(raw))
    grams, other = [], {}
    offset = 0
    for name, part in union.transformer_list:
        values = part.transform([url])
        width = values.shape[1]
        weights = coef[offset:offset + width]
        offset += width
        tfidf = getattr(part, "named_steps", {}).get("tfidf")
        if tfidf is None:  # 숫자 특징(구조 특징, 엔트로피)은 글자 위치가 없어 묶어서 보여 준다
            other[name] = float(np.asarray(values).ravel() @ weights)
            continue
        func = part.named_steps["text"].func
        text = func([url])[0]
        start = raw.find(text) if text else -1
        vocab = tfidf.get_feature_names_out()
        row = values.tocsr()
        for j, v in zip(row.indices, row.data):
            contribution = float(weights[j] * v)
            gram = vocab[j]
            grams.append({"text": gram, "contribution": contribution, "view": _TEXT_FUNCS.get(func, name)})
            spots = _occurrences(text, gram)
            if start < 0 or not spots:
                continue
            share = contribution / len(spots) / len(gram)
            for s in spots:
                char_scores[start + s:start + s + len(gram)] += share

    parts = []
    for part_name, a, b in segment_url(raw):
        parts.append({"part": part_name, "text": raw[a:b], "contribution": round(float(char_scores[a:b].sum()), 3)})
    for name, value in other.items():
        parts.append({"part": {"struct": "구조 특징", "entropy": "엔트로피"}.get(name, name), "text": "", "contribution": round(value, 3)})

    grams.sort(key=lambda g: g["contribution"], reverse=True)
    risky = [g for g in grams if g["contribution"] > 0][:top]
    safe = [g for g in reversed(grams) if g["contribution"] < 0][: max(top // 2, 1)]
    logit = intercept + float(char_scores.sum()) + sum(other.values())
    return {
        "url": raw,
        "intercept": round(intercept, 3),
        "logit": round(logit, 3),
        "probability": round(float(1 / (1 + np.exp(-logit))), 4),
        "char_scores": [round(float(c), 4) for c in char_scores],
        "parts": parts,
        "top_risky": [{**g, "contribution": round(g["contribution"], 3)} for g in risky],
        "top_safe": [{**g, "contribution": round(g["contribution"], 3)} for g in safe],
    }


# ---------------------------------------------------------------------------
# 정상 데이터 대비 위치
# ---------------------------------------------------------------------------


def metric_values(url: str) -> dict:
    """참고 지표 값. scheme과 www는 빼고 잰다 (형태에 따라 값이 달라지지 않도록)."""
    p = uf.split_url(url)
    row = dict(zip(uf.STRUCT_NAMES, uf._struct_row(url)))
    host = uf.strip_www(p["host"]).lower()
    return {
        "url_length": len(p["raw"]) - (len(p["scheme"]) + 3 if p["scheme"] else 0),
        "host_length": row["host_len"],
        "subdomain_depth": row["host_labels_extra"],
        "host_hyphens": row["host_hyphens"],
        "host_digit_ratio": round(row["host_digit_ratio"] * 100, 1),
        "host_entropy": round(uf.entropy(host), 3),
        "path_length": row["path_len"],
        "path_depth": max(row["path_depth"], 0),
        "query_length": row["query_len"],
        "keywords": row["host_keywords"] + row["path_keywords"],
    }


_stats: dict = {}


def load_stats() -> dict | None:
    if "data" not in _stats:
        _stats["data"] = json.loads(STATS_PATH.read_text(encoding="utf-8")) if STATS_PATH.exists() else None
    return _stats["data"]


def percentile(value: float, quantiles: list) -> float:
    """정상 URL 중 이 값보다 작은 비율(%). quantiles는 0~100% 지점 101개."""
    lo = bisect.bisect_left(quantiles, value)
    hi = bisect.bisect_right(quantiles, value)
    return round(min(max((lo + hi) / 2 / (len(quantiles) - 1) * 100, 0.0), 100.0), 1)


def reference(url: str) -> list:
    stats = load_stats()
    if not stats:
        return []
    values = metric_values(url)
    out = []
    for key, name, unit in METRICS:
        s = stats["metrics"][key]
        v = values[key]
        out.append({
            "key": key,
            "name": name,
            "unit": unit,
            "value": v,
            "normal_median": s["normal_median"],
            "normal_p95": s["normal_p95"],
            "phishing_median": s["phishing_median"],
            "normal_percentile": percentile(v, s["normal_quantiles"]),
            "outside_normal": v > s["normal_p95"],
        })
    return out
