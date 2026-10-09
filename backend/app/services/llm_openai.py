import json
import logging
import os
from urllib.parse import urlsplit

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)


def normalize_base_url(base_url: str | None) -> str | None:
    if not base_url:
        return None
    base_url = base_url.strip().rstrip("/")
    if urlsplit(base_url).path in ("", "/"):
        base_url += "/v1"
    return base_url


class OpenAIJsonClient:

    def __init__(self, name: str, model: str, client):
        self.name = name  
        self.model = model
        self.client = client
        self.structured_supported = True

    @classmethod
    def from_env(cls, prefix: str, name: str, default_model: str = "") -> "OpenAIJsonClient | None":
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
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"응답에 JSON이 없습니다: {text[:200]}")
    try:
        return schema.model_validate(json.loads(text[start : end + 1]))
    except (json.JSONDecodeError, ValidationError) as error:
        raise ValueError(f"응답 형식이 맞지 않습니다: {error}") from error


def _is_unsupported_request(error: Exception) -> bool:
    import openai

    return isinstance(
        error,
        (openai.BadRequestError, openai.NotFoundError, openai.UnprocessableEntityError),
    ) or getattr(error, "status_code", None) == 415
