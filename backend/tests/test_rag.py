import pytest

from app.services import rag

FAKE_CASES = [
    {"url": "http://evil.tk/login", "label": 1, "description": "...", "similarity": 0.91},
    {"url": "https://naver.com", "label": 0, "description": "...", "similarity": 0.52},
]


@pytest.fixture
def fake_rag(monkeypatch):
    """벡터 스토어와 Claude 대신 가짜 함수를 끼워 넣는다."""
    monkeypatch.setattr(rag, "_state", {"extract_features": lambda url: {"url": url}})
    monkeypatch.setattr(rag, "_row_to_description", lambda feats: f"URL: {feats['url']}")
    monkeypatch.setattr(rag, "_retrieve", lambda description: FAKE_CASES)
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
    def fail(description):
        raise RuntimeError("검색 오류")

    monkeypatch.setattr(rag, "_retrieve", fail)
    assert rag.explain("http://evil.tk/login") == rag.RagResult()


def test_load_rag_without_vector_store(tmp_path, monkeypatch):
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
