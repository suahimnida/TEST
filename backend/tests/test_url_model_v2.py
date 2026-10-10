import pytest

from app.schemas import AllowlistResult, BlacklistResult, ModelResult
from app.services import allowlist, verdict

import url_features as uf
from model_integration import predict_model


@pytest.mark.parametrize(
    "url, scheme, host, path, query",
    [
        ("naver.com", "", "naver.com", "", ""),
        ("http://naver.com", "http", "naver.com", "", ""),
        ("HTTPS://PaypaI-login.example.XYZ/Account?a=1", "HTTPS", "PaypaI-login.example.XYZ", "/Account", "a=1"),
        ("user@evil.com/login", "", "evil.com", "/login", ""),
        ("http://1.2.3.4:8080/x.php?y=1", "http", "1.2.3.4", "/x.php", "y=1"),
    ],
)
def test_split_url_keeps_original_text(url, scheme, host, path, query):
    p = uf.split_url(url)
    assert (p["scheme"], p["host"], p["path"], p["query"]) == (scheme, host, path, query)


def test_scheme_and_www_do_not_change_features():
    forms = ["https://www.example.com/a", "http://example.com/a", "example.com/a"]
    assert len({tuple(r) for r in uf.struct_features(forms).tolist()}) == 1
    assert len(set(uf.text_normalized(forms))) == 1


def test_calibrate_maps_thresholds_to_service_scale():
    assert uf.calibrate(50, 50, 80) == 30
    assert uf.calibrate(80, 50, 80) == 60
    assert uf.calibrate(100, 50, 80) == 100
    scores = [uf.calibrate(v, 50, 80) for v in range(0, 101, 5)]
    assert scores == sorted(scores)  # 순서 유지


def test_v2_model_is_used_and_scores_in_range():
    for url in ("https://www.naver.com", "http://secure-paypal-login.verify-account.tk"):
        result = predict_model(url)
        assert result["status"] == "ready" and 0 <= result["risk_score"] <= 100
    assert predict_model("http://secure-paypal-login.verify-account.tk")["label"] == "phishing"


@pytest.mark.parametrize(
    "url, matched",
    [
        ("https://www.naver.com", True),
        ("naver.com", True),
        ("https://nid.naver.com/nidlogin.login?mode=form", True),
        ("https://github.com/suahimnida/TEST", True),
        ("https://naver.com.evil.xyz/login", False),
        ("https://sites.google.com/view/fake-login", False),  # 누구나 페이지를 올릴 수 있는 곳
        ("https://docs.google.com/forms/d/e/abc/viewform", False),
        ("https://my-app.github.io", False),
        ("https://example-shop.blogspot.com", False),
    ],
)
def test_allowlist(url, matched):
    assert allowlist.check(url).matched is matched


def test_allowlist_caps_ml_score_but_not_blacklist():
    ml = ModelResult(status="ready", risk_score=95.0, label="phishing")
    allow = AllowlistResult(matched=True, domain="naver.com")
    clean = BlacklistResult(matched=False, match_type="none", source="KISA 2024")
    result = verdict.decide(clean, ml, allow)
    assert result["verdict"] == "normal" and result["risk_score"] == verdict.ALLOWLIST_CAP

    listed = BlacklistResult(matched=True, match_type="host", source="KISA 2024")
    assert verdict.decide(listed, ModelResult(status="not_ready"), allow)["verdict"] == "phishing"
    assert verdict.decide(clean, ml, AllowlistResult())["verdict"] == "phishing"
