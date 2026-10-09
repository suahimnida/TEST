"""OpenAI 호환 클라이언트 테스트.

실제 OpenAI SDK를 쓰고, 네트워크 대신 가짜 중간 서버(MockTransport)가 응답한다.
"""

import json

import openai
import pytest
from pydantic import BaseModel

from app.services import llm_openai
from app.services.llm_openai import OpenAIJsonClient, normalize_base_url


class Answer(BaseModel):
    summary: str
    score: int


def completion(model, content):
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content, "refusal": None},
                "finish_reason": "stop",
            }
        ],
    }


@pytest.fixture
def fake_server(monkeypatch):
    """OpenAI 클라이언트가 가짜 중간 서버로 요청하게 한다. 받은 요청은 server.requests에 쌓인다."""
    import httpx2

    server = type("Server", (), {})()
    server.requests = []
    server.reject_structured = False
    server.status = 200
    server.reply = json.dumps({"summary": "요약", "score": 3}, ensure_ascii=False)

    def handler(request):
        body = json.loads(request.content)
        server.requests.append({"url": str(request.url), "headers": dict(request.headers), "body": body})
        if server.status != 200:
            return httpx2.Response(server.status, json={"error": {"message": "fail", "type": "x"}})
        if server.reject_structured and "response_format" in body:
            return httpx2.Response(400, json={"error": {"message": "response_format not supported", "type": "invalid_request_error"}})
        return httpx2.Response(200, json=completion(body["model"], server.reply))

    real = openai.OpenAI
    monkeypatch.setattr(
        openai, "OpenAI", lambda **kw: real(**kw, http_client=httpx2.Client(transport=httpx2.MockTransport(handler)))
    )
    for name in ("MODEL", "BASE_URL", "API_KEY", "AUTH_TOKEN"):
        monkeypatch.delenv(f"TEST_OPENAI_{name}", raising=False)
    return server


# ---- 1. 모델명 지정 ----


def test_model_from_env_overrides_default(fake_server, monkeypatch):
    monkeypatch.setenv("TEST_OPENAI_API_KEY", "key")
    monkeypatch.setenv("TEST_OPENAI_MODEL", "env-model")
    client = OpenAIJsonClient.from_env("TEST", "테스트", default_model="doc-model")
    client.ask("system", "user", Answer)
    assert fake_server.requests[0]["body"]["model"] == "env-model"


def test_default_model_used_when_env_missing(fake_server, monkeypatch):
    monkeypatch.setenv("TEST_OPENAI_API_KEY", "key")
    client = OpenAIJsonClient.from_env("TEST", "테스트", default_model="doc-model")
    assert client.model == "doc-model"


def test_missing_model_disables_client(fake_server, monkeypatch):
    monkeypatch.setenv("TEST_OPENAI_API_KEY", "key")
    assert OpenAIJsonClient.from_env("TEST", "테스트", default_model="") is None


# ---- 2. 키/토큰 검사 ----


def test_missing_key_and_token_disables_client(fake_server, monkeypatch):
    monkeypatch.setenv("TEST_OPENAI_MODEL", "m")
    assert OpenAIJsonClient.from_env("TEST", "테스트") is None


@pytest.mark.parametrize("name", ["API_KEY", "AUTH_TOKEN"])
def test_either_key_or_token_is_enough(fake_server, monkeypatch, name):
    monkeypatch.setenv("TEST_OPENAI_MODEL", "m")
    monkeypatch.setenv(f"TEST_OPENAI_{name}", "secret-123")
    client = OpenAIJsonClient.from_env("TEST", "테스트")
    client.ask("system", "user", Answer)
    assert fake_server.requests[0]["headers"]["authorization"] == "Bearer secret-123"


def test_token_wins_over_key(fake_server, monkeypatch):
    monkeypatch.setenv("TEST_OPENAI_MODEL", "m")
    monkeypatch.setenv("TEST_OPENAI_API_KEY", "key-value")
    monkeypatch.setenv("TEST_OPENAI_AUTH_TOKEN", "token-value")
    OpenAIJsonClient.from_env("TEST", "테스트").ask("system", "user", Answer)
    assert fake_server.requests[0]["headers"]["authorization"] == "Bearer token-value"


# ---- 3. Base URL ----


@pytest.mark.parametrize(
    "given, expected",
    [
        ("https://copa.codyssey.kr", "https://copa.codyssey.kr/v1"),
        ("https://copa.codyssey.kr/", "https://copa.codyssey.kr/v1"),
        ("https://copa.codyssey.kr/v1", "https://copa.codyssey.kr/v1"),
        ("https://copa.codyssey.kr/openai/v1/", "https://copa.codyssey.kr/openai/v1"),
        ("", None),
        (None, None),
    ],
)
def test_normalize_base_url(given, expected):
    assert normalize_base_url(given) == expected


def test_requests_go_to_middle_server(fake_server, monkeypatch):
    monkeypatch.setenv("TEST_OPENAI_MODEL", "m")
    monkeypatch.setenv("TEST_OPENAI_AUTH_TOKEN", "t")
    monkeypatch.setenv("TEST_OPENAI_BASE_URL", "https://copa.codyssey.kr")
    OpenAIJsonClient.from_env("TEST", "테스트").ask("system", "user", Answer)
    assert fake_server.requests[0]["url"] == "https://copa.codyssey.kr/v1/chat/completions"


# ---- 응답 형식 ----


def make_client(monkeypatch):
    monkeypatch.setenv("TEST_OPENAI_MODEL", "m")
    monkeypatch.setenv("TEST_OPENAI_API_KEY", "k")
    return OpenAIJsonClient.from_env("TEST", "테스트")


def test_structured_output_request(fake_server, monkeypatch):
    result = make_client(monkeypatch).ask("system", "user", Answer)
    assert result == Answer(summary="요약", score=3)
    fmt = fake_server.requests[0]["body"]["response_format"]
    assert fmt["type"] == "json_schema" and fmt["json_schema"]["strict"] is True


def test_falls_back_to_plain_json_when_structured_rejected(fake_server, monkeypatch):
    fake_server.reject_structured = True
    fake_server.reply = '```json\n{"summary": "일반 요청", "score": 5}\n```'
    client = make_client(monkeypatch)

    assert client.ask("system", "user", Answer) == Answer(summary="일반 요청", score=5)
    first, second = fake_server.requests
    assert "response_format" in first["body"] and "response_format" not in second["body"]
    assert "JSON 스키마" in second["body"]["messages"][0]["content"]

    # 한 번 거절된 뒤에는 처음부터 일반 요청을 보낸다
    client.ask("system", "user", Answer)
    assert len(fake_server.requests) == 3 and "response_format" not in fake_server.requests[2]["body"]


def test_auth_error_is_not_retried_as_plain(fake_server, monkeypatch):
    fake_server.status = 401
    client = make_client(monkeypatch)
    with pytest.raises(openai.AuthenticationError):
        client.ask("system", "user", Answer)
    assert len(fake_server.requests) == 1


def test_parse_json_reply_rejects_bad_text():
    with pytest.raises(ValueError):
        llm_openai.parse_json_reply("JSON이 아닙니다", Answer)
    with pytest.raises(ValueError):
        llm_openai.parse_json_reply('{"summary": "x"}', Answer)
