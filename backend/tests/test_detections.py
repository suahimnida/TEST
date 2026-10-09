import pytest

from app.services import detections


def statuses(url):
    result = detections.analyze(url)
    return {key: value["status"] for key, value in result.items()}


@pytest.mark.parametrize(
    "url",
    [
        "https://www.naver.com",
        "naver.com",
        "https://nid.naver.com/nidlogin.login?mode=form", 
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://phishing-link-checker-five.vercel.app",
        "https://portal.sch.ac.kr", 
        "https://www.paypal.com/signin",
    ],
)
def test_legit_urls_are_not_flagged(url):
    result = statuses(url)
    assert result["url"] == result["url_stats"] == result["domain"] == "normal"


def test_brand_impersonation_and_tld():
    result = detections.analyze("http://secure-paypal-login.verify-account.tk")
    assert result["domain"]["status"] == "suspicious"
    reasons = " ".join(result["domain"]["reasons"])
    assert "'.tk'" in reasons and "'paypal'" in reasons
    assert result["url"]["status"] == "suspicious" 


def test_ip_at_punycode_shortener():
    assert statuses("http://154.92.182.159/download.php")["url"] == "suspicious"
    assert statuses("http://user@evil.com")["url"] == "suspicious"
    assert statuses("http://xn--80ak6aa92e.com")["url"] == "suspicious"
    assert statuses("https://bit.ly/3abcd")["url"] == "suspicious"


def test_userinfo_is_not_part_of_domain():
    result = detections.analyze("http://user@evil.com")
    assert any("evil.com" in note for note in result["domain"]["notes"])


def test_html_and_image_are_not_analyzed():
    result = detections.analyze("https://example.com")
    assert result["html"]["status"] == result["image"]["status"] == "not_analyzed"
    assert result["html"]["notes"]


def test_every_item_has_display_text():
    for value in detections.analyze("http://secure-paypal-login.verify-account.tk").values():
        assert value["reasons"] or value["notes"]
