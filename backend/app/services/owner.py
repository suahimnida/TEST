"""분석 요청자 확인 (성명, 사용자 식별 암호).

    성명      공개 분석 목록에는 가린 형태("김**")를 보여 주고, 삭제할 때 본인 확인용으로 해시를 저장한다.
    식별 암호  영문 대소문자와 숫자 8~12자리. 원문은 저장하지 않고 salt를 섞은 해시(PBKDF2-SHA256)만 저장한다.
    삭제할 때 성명과 식별 암호가 모두 맞아야 본인으로 본다.
    잠금      같은 분석 결과에 암호를 5번 틀리면 15분 동안 확인을 막는다 (암호 추측 방지).
"""

import hashlib
import hmac
import re
import secrets
import threading
import time

SECRET_PATTERN = re.compile(r"^[A-Za-z0-9]{8,12}$")
CONFIRM_TEXT = "분석 결과를 삭제하겠습니다"
ITERATIONS = 200_000
MAX_FAILURES = 5
LOCK_SECONDS = 15 * 60

_failures: dict = {}  # 분석 ID → (실패 횟수, 처음 실패한 시각)
_lock = threading.Lock()


def mask_name(name: str) -> str:
    """첫 글자만 남기고 나머지는 *로 가린다. 김수아 → 김**, 홍길 → 홍*, 남궁민수 → 남***"""
    chars = [c for c in name.strip() if not c.isspace()]
    if not chars:
        return ""
    if len(chars) == 1:
        return "*"
    return chars[0] + "*" * (len(chars) - 1)


def _hash(value: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify(value: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        _, iterations, salt, expected = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", value.encode(), bytes.fromhex(salt), int(iterations))
    except ValueError:
        return False
    return hmac.compare_digest(digest.hex(), expected)


def normalize_name(name: str) -> str:
    """성명 비교용: 공백을 빼고 비교한다 (김 수아 = 김수아)."""
    return "".join((name or "").split())


def hash_secret(secret: str) -> str:
    return _hash(secret)


def verify_secret(secret: str, stored: str | None) -> bool:
    return bool(SECRET_PATTERN.match(secret or "")) and _verify(secret, stored)


def hash_name(name: str) -> str:
    return _hash(normalize_name(name))


def verify_name(name: str, stored_hash: str | None, masked: str | None) -> bool:
    """성명 해시로 비교한다. 해시가 없는 예전 기록은 가린 성명끼리 비교한다."""
    if not normalize_name(name):
        return False
    if stored_hash:
        return _verify(normalize_name(name), stored_hash)
    return bool(masked) and mask_name(name) == masked


def locked(analysis_id: str) -> bool:
    with _lock:
        count, first = _failures.get(analysis_id, (0, 0.0))
        if count and time.time() - first > LOCK_SECONDS:
            _failures.pop(analysis_id, None)
            return False
        return count >= MAX_FAILURES


def record_failure(analysis_id: str) -> None:
    with _lock:
        count, first = _failures.get(analysis_id, (0, time.time()))
        _failures[analysis_id] = (count + 1, first)


def clear_failures(analysis_id: str) -> None:
    with _lock:
        _failures.pop(analysis_id, None)
