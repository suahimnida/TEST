import pytest

from app.services import rag

FAKE_CASES = [
    {"url": "http://evil.tk/login", "label": 1, "description": "...", "similarity": 0.91},
    {"url": "https://naver.com", "label": 0, "description": "...", "similarity": 0.52},
]


@pytest.fixture
def fake_rag(monkeypatch):
    """벡터 스토어와 Claude 대신 가짜 함수를 끼워 넣는다."""
    monkeypatch.setattr(
        rag, "_state", {"search_features": lambda url: {"url": url}, "client": object()}
    )
    monkeypatch.setattr(rag, "_row_to_description", lambda feats: f"URL: {feats['url']}")
    monkeypatch.setattr(rag, "_retrieve", lambda features: FAKE_CASES)
    monkeypatch.setattr(
        rag,
        "_ask_claude",
        lambda description, cases: {"verdict": "phishing", "confidence": 0.9, "reason": "근거 요약"},
    )


def test_explain_without_rag_returns_empty():
    assert rag._state is None
    result = rag.explain("https://example.com")
    assert result == rag.RagResult()


def test_explain_maps_rag_output(fake_rag):
    result = rag.explain("http://evil.tk/login")
    assert result.verdict == "phishing"
    assert result.confidence == pytest.approx(0.9)
    assert result.summary == "근거 요약"
    assert result.features == {"url": "http://evil.tk/login"}
    assert [c.url for c in result.similar_cases] == ["http://evil.tk/login", "https://naver.com"]
    assert result.similar_cases[0].label == 1
    assert result.similar_cases[0].similarity == pytest.approx(0.91)


def test_explain_keeps_search_results_when_claude_fails(fake_rag, monkeypatch):
    def fail(description, cases):
        raise RuntimeError("API 오류")

    monkeypatch.setattr(rag, "_ask_claude", fail)
    result = rag.explain("http://evil.tk/login")
    assert result.verdict is None
    assert result.summary is None
    assert result.features == {"url": "http://evil.tk/login"}
    assert len(result.similar_cases) == 2


def test_explain_returns_empty_when_search_fails(fake_rag, monkeypatch):
    def fail(features):
        raise RuntimeError("검색 오류")

    monkeypatch.setattr(rag, "_retrieve", fail)
    assert rag.explain("http://evil.tk/login") == rag.RagResult()


def test_load_rag_without_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("RAG_INDEX_DIR", str(tmp_path))
    assert rag.load_rag() is False
    assert rag._state is None


def test_parse_verdict_plain_json():
    text = '{"verdict": "phishing", "confidence": 0.87, "reason": "의심 키워드가 많습니다."}'
    assert rag._parse_verdict(text) == {
        "verdict": "phishing",
        "confidence": pytest.approx(0.87),
        "reason": "의심 키워드가 많습니다.",
    }


def test_parse_verdict_with_code_fence_and_percent():
    text = '```json\n{"verdict": "Normal", "confidence": 92, "reason": "정상 사례와 유사합니다."}\n```'
    result = rag._parse_verdict(text)
    assert result["verdict"] == "normal"
    assert result["confidence"] == pytest.approx(0.92)


@pytest.mark.parametrize(
    "text",
    [
        "판정할 수 없습니다.",
        '{"verdict": "unknown", "confidence": 0.5, "reason": "x"}',
        '{"verdict": "phishing", "confidence": 0.5, "reason": ""}',
    ],
)
def test_parse_verdict_rejects_bad_output(text):
    with pytest.raises(ValueError):
        rag._parse_verdict(text)


def test_explain_without_claude_returns_cases_only(fake_rag, monkeypatch):
    monkeypatch.setitem(rag._state, "client", None)
    result = rag.explain("http://evil.tk/login")
    assert result.summary is None and result.verdict is None
    assert len(result.similar_cases) == 2


# ---- 실제 사례 5,000건으로 검색 (Claude는 부르지 않는다) ----


@pytest.fixture
def real_rag(monkeypatch):
    for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(rag, "_state", None)
    assert rag.load_rag() is True
    assert rag._state["client"] is None


def labels_of(url):
    return [c.label for c in rag.explain(url).similar_cases]


def test_phishing_url_finds_phishing_cases(real_rag):
    assert labels_of("http://secure-paypal-login.verify-account.tk") == [1, 1, 1, 1, 1]
    assert labels_of("http://m.login.secure.naver-account-verify-center.xyz/update?id=1029") == [1] * 5


def test_official_brand_homepage_finds_normal_cases(real_rag):
    # 'naver'가 의심 키워드로 세어지지 않아야 정상 홈페이지들이 검색된다
    assert labels_of("https://www.naver.com") == [0, 0, 0, 0, 0]


def test_similarity_is_sorted_and_in_range(real_rag):
    cases = rag.explain("http://secure-paypal-login.verify-account.tk").similar_cases
    sims = [c.similarity for c in cases]
    assert sims == sorted(sims, reverse=True)
    assert all(0 < s <= 1 for s in sims)
    # 예전 문장 임베딩 방식처럼 모든 사례가 같은 점수로 나오지 않는다
    homepage = rag.explain("https://www.naver.com").similar_cases[0].similarity
    assert homepage > sims[0]


def test_search_features_keeps_ml_features_except_brand_keyword():
    feats = rag.search_features("https://www.naver.com")
    assert feats["suspicious_keyword_count"] == 0
    assert rag.search_features("http://naver-login.xyz")["suspicious_keyword_count"] == 2
