import pytest

from app.schemas import BlacklistResult, ModelResult
from app.services import verdict

NOT_MATCHED = BlacklistResult(matched=False, match_type="none", source="KISA 2024")
MATCHED = BlacklistResult(matched=True, match_type="host", source="KISA 2024")


def test_blacklist_match_is_phishing_without_model():
    result = verdict.decide(MATCHED, ModelResult(status="not_ready"))
    assert result == {
        "verdict": "phishing", "confidence": 1.0, "risk_score": 100.0, "risk_level": "danger"
    }


@pytest.mark.parametrize(
    "score, expected_verdict, expected_level",
    [
        (12.0, "normal", "safe"),
        (45.0, "suspicious", "caution"),
        (72.0, "phishing", "warning"),
        (95.0, "phishing", "danger"),
        (29.99, "normal", "safe"),
        (30.0, "suspicious", "caution"),
        (59.99, "suspicious", "caution"),
        (60.0, "phishing", "warning"),
        (85.0, "phishing", "danger"),
        (100.0, "phishing", "danger"),
    ],
)
def test_uses_ml_score_when_not_blacklisted(score, expected_verdict, expected_level):
    result = verdict.decide(NOT_MATCHED, ModelResult(status="ready", risk_score=score))
    assert result["risk_score"] == score
    assert result["verdict"] == expected_verdict
    assert result["risk_level"] == expected_level


def test_no_score_returns_nulls():
    result = verdict.decide(NOT_MATCHED, ModelResult(status="not_ready"))
    assert result == {"verdict": None, "confidence": None, "risk_score": None, "risk_level": None}
