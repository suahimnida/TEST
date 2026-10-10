"""ML·RAG·LLM 역할 분리.

    ML   위험 근거를 만든다      → build_evidence(): 근거 목록 [E1] [E2] ...
    RAG  근거에 맞는 대응 가이드  → retrieve():       가이드 목록 [G1] [G2] ...
    LLM  둘을 합쳐 출처가 있는 설명 → rag.compose(), 실패하면 template_explanation()

가이드는 resources/guides/guides.json (공식 기관 안내를 요약하고 출처 링크를 붙인 것)이다.
LLM이 쓴 설명은 check_citations()로 검사해서, 근거·가이드에 없는 번호를 쓰거나
전화번호·주소를 지어내면 버리고 템플릿으로 대신한다.
"""

import json
import re
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer

_PATH = Path(__file__).resolve().parents[2] / "resources" / "guides" / "guides.json"

TAG_LABELS = {
    "phishing_site": "피싱 판정",
    "brand_impersonation": "브랜드 사칭",
    "login_page": "로그인·계정 화면 흉내",
    "compromised_site": "해킹된 사이트 경로",
    "shortener": "단축 URL",
    "smishing": "문자로 받은 링크",
    "financial": "금융 관련",
    "personal_info": "개인정보 입력 유도",
    "account": "계정 정보",
    "money_sent": "송금·결제",
    "app_install": "앱 설치 유도",
    "file_download": "파일 내려받기",
    "prevention": "예방",
}
LOGIN_WORDS = ("login", "signin", "logon", "verify", "account", "auth", "password", "secure", "update")
FINANCE_WORDS = ("bank", "pay", "card", "wallet", "banking", "kbstar", "shinhan", "woori", "hana", "toss",
                 "kakaobank", "nonghyup", "ibk", "loan", "coin", "crypto")
DOWNLOAD_EXT = (".apk", ".exe", ".zip", ".msi", ".scr", ".dmg")

_state: dict = {}


def _load() -> dict:
    if not _state:
        data = json.loads(_PATH.read_text(encoding="utf-8"))
        guides = data["guides"]
        texts = [f"{g['title']} {g['text']} " + " ".join(TAG_LABELS.get(t, t) for t in g["tags"]) for g in guides]
        vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 3))
        _state.update(guides=guides, vectorizer=vectorizer, matrix=vectorizer.fit_transform(texts),
                      checked=data.get("checked"))
    return _state


def guide_for_action(action_id: str) -> dict | None:
    """후속 조치에 출처를 붙이기 위해, 그 조치를 안내하는 첫 번째 가이드를 찾는다."""
    return next((g for g in _load()["guides"] if action_id in g["actions"]), None)


# ---------------------------------------------------------------------------
# ① ML: 근거 목록
# ---------------------------------------------------------------------------


def build_evidence(*, verdict, risk_score, blacklist, allowlist, model, explanation, detections,
                   similar_cases) -> list[dict]:
    """판정에 쓰인 근거와 참고 근거를 번호 붙은 목록으로 만든다. 문장은 모두 서버가 만든 사실이다."""
    items = []

    def add(source, text, used):
        items.append({"id": f"E{len(items) + 1}", "source": source, "text": text, "used_in_verdict": used})

    if blacklist.matched:
        add("KISA 블랙리스트", f"KISA 피싱 사이트 목록과 일치해 피싱으로 확정됐습니다 ({blacklist.source}).", True)
    if model.status == "ready" and model.risk_score is not None:
        add("ML 모델", f"URL 문자 패턴으로 계산한 위험 점수는 {model.risk_score:g}점입니다.", True)
        parts = sorted([p for p in ((explanation or {}).get("model") or {}).get("parts", [])
                        if p["contribution"] > 0.3 and p["text"]], key=lambda p: -p["contribution"])[:3]
        if parts:
            add("ML 모델 · 부분별 기여",
                "점수를 가장 크게 올린 부분은 " + ", ".join(f"{p['part']} '{p['text']}'(+{p['contribution']:.2f})" for p in parts) + "입니다.",
                True)
    if allowlist.matched and not blacklist.matched:
        add("공식 도메인 허용 목록", f"{allowlist.domain}은(는) 공식 도메인 목록에 있어 ML 점수만으로 피싱 판정을 내리지 않았습니다.", True)

    for key, title in (("url", "URL 구조"), ("domain", "도메인 분석"), ("url_stats", "URL 통계"), ("reputation", "평판 신호")):
        item = getattr(detections, key, None)
        if item and item.get("status") == "suspicious":
            for reason in item.get("reasons", [])[:2]:
                add(f"탐지 결과 · {title}", reason, False)

    if similar_cases:
        phishing = sum(1 for c in similar_cases if c.label == 1)
        add("유사 사례", f"특징이 가장 비슷한 과거 사례 {len(similar_cases)}건 중 피싱이 {phishing}건입니다.", False)
    return items[:10]


def evidence_tags(url: str, verdict: str | None, evidence: list[dict]) -> set:
    """근거에서 어떤 상황인지 뽑아 가이드 검색에 쓴다."""
    text = " ".join(e["text"] for e in evidence).lower()
    lower = url.lower()
    tags = set()
    if verdict in ("phishing", "suspicious"):
        tags.add("phishing_site")
    else:
        tags.add("prevention")
    if "브랜드" in text or "사칭" in text or "공식 도메인(" in text:
        tags.add("brand_impersonation")
    if any(w in lower for w in LOGIN_WORDS):
        tags.update({"login_page", "account"})
    if "관리용 폴더" in text:
        tags.add("compromised_site")
    if "단축 url" in text:
        tags.update({"shortener", "smishing"})
    if any(w in lower for w in FINANCE_WORDS):
        tags.update({"financial", "personal_info"})
    if lower.split("?")[0].endswith(DOWNLOAD_EXT) or "download" in lower:
        tags.update({"app_install", "file_download"})
    return tags


# ---------------------------------------------------------------------------
# ② RAG: 대응 가이드 검색
# ---------------------------------------------------------------------------


def retrieve(tags: set, evidence: list[dict], top_k: int = 4) -> list[dict]:
    """태그가 많이 겹치는 가이드를 먼저, 같으면 근거 문장과 글자가 비슷한 가이드를 앞에 둔다."""
    state = _load()
    query = " ".join(e["text"] for e in evidence) + " " + " ".join(TAG_LABELS.get(t, t) for t in tags)
    similarity = (state["vectorizer"].transform([query]) @ state["matrix"].T).toarray()[0]
    scored = []
    for i, g in enumerate(state["guides"]):
        matched = [t for t in g["tags"] if t in tags]
        if matched:
            scored.append((len(matched) + float(similarity[i]), i, matched))
    scored.sort(reverse=True)
    hits = []
    for rank, (score, i, matched) in enumerate(scored[:top_k], start=1):
        g = state["guides"][i]
        hits.append({
            "id": f"G{rank}", "key": g["key"], "title": g["title"], "source": g["source"], "url": g["url"],
            "text": g["text"], "matched": [TAG_LABELS.get(t, t) for t in matched], "score": round(score, 3),
            "checked": state["checked"],
        })
    return hits


# ---------------------------------------------------------------------------
# ③ LLM 설명 검사와 템플릿
# ---------------------------------------------------------------------------

_CITATION = re.compile(r"\[([EG]\d+)\]")
# 한글이 바로 붙어도(예: "118로") 잡도록 단어 경계 대신 앞뒤에 다른 숫자가 없는지로 본다
_FORBIDDEN = re.compile(r"https?://|www\.|(?<!\d)\d{2,4}-\d{3,4}-\d{4}(?!\d)|(?<![\d.])(?:112|118|1332)(?![\d.])")


def check_citations(text: str, evidence: list[dict], guides: list[dict]) -> str:
    """모든 문장에 출처 번호가 있고, 번호가 실제 근거·가이드를 가리키는지 검사한다. 어기면 ValueError."""
    text = (text or "").strip()
    if not text:
        raise ValueError("설명이 비어 있습니다")
    if _FORBIDDEN.search(text):
        raise ValueError("설명에 주소나 전화번호가 들어 있습니다 (출처 링크는 서버가 보여 준다)")
    valid = {e["id"] for e in evidence} | {g["id"] for g in guides}
    cited = _CITATION.findall(text)
    if not cited:
        raise ValueError("출처 표시가 없습니다")
    unknown = set(cited) - valid
    if unknown:
        raise ValueError(f"없는 출처 번호를 썼습니다: {sorted(unknown)}")
    # 문장 끝 마침표 뒤에 바로 오는 출처 표시([E1])는 앞 문장에 붙은 것으로 본다
    sentences = [s for s in re.split(r"(?<=[.!?])\s+(?!\[)", text) if s.strip()]
    if any(not _CITATION.search(s) for s in sentences):
        raise ValueError("출처 표시가 없는 문장이 있습니다")
    return text


VERDICT_KO = {"phishing": "피싱", "suspicious": "피싱 의심", "normal": "정상"}


def template_explanation(verdict: str | None, evidence: list[dict], guides: list[dict]) -> str:
    """LLM을 쓸 수 없을 때 근거와 가이드로 같은 형식의 설명을 만든다."""
    def cite(text, ref):
        return f"{text.rstrip('.')} [{ref}]."

    sentences = []
    if evidence:
        head = evidence[0]
        sentences.append(cite(f"이 URL은 '{VERDICT_KO.get(verdict, '판정 불가')}'으로 판정됐습니다", head["id"]))
        sentences.append(cite(head["text"], head["id"]))
    for e in evidence[1:3]:
        sentences.append(cite(f"{e['source']}: {e['text']}", e["id"]))
    for g in guides[:2]:
        first = g["text"].split(". ")[0]
        sentences.append(cite(f"{g['title']} 안내에 따르면 {first}", g["id"]))
    return " ".join(sentences)
