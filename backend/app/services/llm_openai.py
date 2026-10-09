"""OpenAI 호환 API 호출 (교육 센터 중간 서버 포함).

후속 조치 조사(첫번째 키)와 리포트 작성(두번째 키)이 함께 쓴다. 키마다 환경변수 접두어만 다르다.

    {접두어}_OPENAI_MODEL        모델 이름 (코디세이 API 문서에 있는 이름)
    {접두어}_OPENAI_BASE_URL     중간 서버 주소. 비우면 OpenAI 공식 서버(api.openai.com)
    {접두어}_OPENAI_API_KEY      키
    {접두어}_OPENAI_AUTH_TOKEN   또는 토큰 (둘 중 하나만 있으면 된다)

    접두어: FOLLOWUP (첫번째 키, 후속 조치 조사) / REPORT (두번째 키, 리포트 작성)

코디세이 중간 서버 (API 콘솔 문서 기준)
    OpenAI 호환 엔드포인트는 /v1/chat/completions 이고 Responses API는 쓰지 않는다.
    Base URL은 https://copa.codyssey.kr/v1 (https://copa.codyssey.kr 만 넣어도 /v1을 붙인다).
    인증은 Authorization: Bearer <virtual-key>.

Anthropic SDK는 api_key(x-api-key 헤더)와 auth_token(Authorization: Bearer 헤더)을 따로 받지만,
OpenAI SDK는 api_key 하나를 Authorization: Bearer 헤더로 보낸다. 그래서 키와 토큰 중 있는 쪽을
api_key로 넘긴다.

응답 형식
    먼저 구조화 출력(response_format=json_schema)으로 요청한다. 중간 서버나 모델이 이를 지원하지
    않아 요청을 거절하면, 같은 내용을 "JSON으로만 답하라"는 일반 요청으로 다시 보내고 응답을 직접
    검증한다. 한 번 거절된 뒤에는 처음부터 일반 요청을 쓴다.
"""

import json
import logging
import os
from urllib.parse import urlsplit

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)


def normalize_base_url(base_url: str | None) -> str | None:
    """주소에 경로가 없으면 /v1을 붙인다 (https://copa.codyssey.kr → https://copa.codyssey.kr/v1).

    OpenAI SDK는 base_url 뒤에 /chat/completions를 붙여 요청하므로 주소가 /v1로 끝나야 한다.
    Anthropic SDK는 반대로 /v1/messages를 스스로 붙이기 때문에, 같은 중간 서버라도 Anthropic용
    주소에는 /v1이 없었다.
    """
    if not base_url:
        return None
    base_url = base_url.strip().rstrip("/")
    if urlsplit(base_url).path in ("", "/"):
        base_url += "/v1"
    return base_url


class OpenAIJsonClient:
    """한 개의 키(접두어)에 대응하는 클라이언트. ask()는 pydantic 모델 인스턴스를 돌려준다."""

    def __init__(self, name: str, model: str, client):
        self.name = name  # 로그용 이름 (예: "후속 조치 조사")
        self.model = model
        self.client = client
        self.structured_supported = True

    @classmethod
    def from_env(cls, prefix: str, name: str, default_model: str = "") -> "OpenAIJsonClient | None":
        """환경변수로 클라이언트를 만든다. 키나 모델이 없으면 경고만 남기고 None (템플릿으로 대신)."""
        model = os.environ.get(f"{prefix}_OPENAI_MODEL") or default_model
        api_key = os.environ.get(f"{prefix}_OPENAI_API_KEY")
        auth_token = os.environ.get(f"{prefix}_OPENAI_AUTH_TOKEN")

        if not api_key and not auth_token:
            logger.warning(
                "%s 비활성화: %s_OPENAI_API_KEY 또는 %s_OPENAI_AUTH_TOKEN이 설정되지 않았습니다",
                name, prefix, prefix,
            )
            return None
        if not model:
            logger.warning("%s 비활성화: %s_OPENAI_MODEL(모델 이름)이 설정되지 않았습니다", name, prefix)
            return None

        from openai import OpenAI

        # GPT-5 계열은 답하기 전에 추론하는 시간이 있어 대기 시간을 넉넉히 둔다
        client_kwargs = {"api_key": auth_token or api_key, "timeout": 90, "max_retries": 1}
        base_url = normalize_base_url(os.environ.get(f"{prefix}_OPENAI_BASE_URL"))
        if base_url:
            client_kwargs["base_url"] = base_url

        logger.info("%s 모델: %s (%s)", name, model, base_url or "api.openai.com")
        return cls(name, model, OpenAI(**client_kwargs))

    def ask(self, system: str, user: str, schema: type[BaseModel]) -> BaseModel:
        if self.structured_supported:
            try:
                return self._ask_structured(system, user, schema)
            except Exception as error:
                if not _is_unsupported_request(error):
                    raise
                logger.warning(
                    "%s: 구조화 출력이 지원되지 않아 일반 JSON 요청으로 전환합니다 (%s)",
                    self.name, type(error).__name__,
                )
                self.structured_supported = False
        return self._ask_plain(system, user, schema)

    def _ask_structured(self, system: str, user: str, schema: type[BaseModel]) -> BaseModel:
        completion = self.client.chat.completions.parse(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            response_format=schema,
        )
        message = completion.choices[0].message
        if getattr(message, "refusal", None):
            raise RuntimeError(f"모델이 응답을 거절했습니다: {message.refusal}")
        if message.parsed is None:
            raise RuntimeError("모델 응답이 비어 있습니다")
        return message.parsed

    def _ask_plain(self, system: str, user: str, schema: type[BaseModel]) -> BaseModel:
        format_rule = (
            "\n\n반드시 아래 JSON 스키마를 따르는 JSON 객체 하나만 출력하세요. "
            "다른 말이나 코드블록 표시는 쓰지 마세요.\n"
            + json.dumps(schema.model_json_schema(), ensure_ascii=False)
        )
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system + format_rule}, {"role": "user", "content": user}],
        )
        text = completion.choices[0].message.content or ""
        return parse_json_reply(text, schema)


def parse_json_reply(text: str, schema: type[BaseModel]) -> BaseModel:
    """응답 텍스트에서 JSON 객체를 꺼내 스키마로 검증한다. 실패하면 ValueError."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"응답에 JSON이 없습니다: {text[:200]}")
    try:
        return schema.model_validate(json.loads(text[start : end + 1]))
    except (json.JSONDecodeError, ValidationError) as error:
        raise ValueError(f"응답 형식이 맞지 않습니다: {error}") from error


def _is_unsupported_request(error: Exception) -> bool:
    """중간 서버·모델이 구조화 출력 요청 자체를 받아들이지 않은 경우 (400/404/415/422)."""
    import openai

    return isinstance(
        error,
        (openai.BadRequestError, openai.NotFoundError, openai.UnprocessableEntityError),
    ) or getattr(error, "status_code", None) == 415
