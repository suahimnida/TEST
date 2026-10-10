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


def test_page_content_is_not_reported():
    # 사이트에 접속하지 않으므로 HTML·이미지 항목을 만들지 않는다
    assert set(detections.analyze("https://example.com")) == {"url", "url_stats", "domain"}


@pytest.mark.parametrize(
    "url",
    [
        "https://example-shop.com/wp-content/uploads/2024/verify/login.php",
        "https://random-shop.com/paypal/signin",
        "https://evil.com/www.naver.com/login/",
        "https://hacked.org/.well-known/pki-validation/account/update.html",
        "https://hacked.org/wp-admin/includes/paypal/index.php",
    ],
)
def test_compromised_site_path_patterns(url):
    result = detections.analyze(url)["url"]
    assert result["status"] == "suspicious"


@pytest.mark.parametrize(
    "url",
    [
        "https://myblog.com/wp-login.php",  # 워드프레스 자체 관리자 로그인
        "https://myblog.com/wp-admin/",
        "https://myblog.com/wp-content/uploads/2024/photo.jpg",
        "https://www.paypal.com/signin",  # 공식 도메인
        "https://blog.example.com/review-of-paypal-fees",  # 로그인 단어 없음
        "https://erpsoftwareblog.com/2010/08/microsoft-dynamics-gp-accounting-software/",  # accounting ≠ account
    ],
)
def test_path_patterns_do_not_flag_normal_sites(url):
    result = detections.analyze(url)["url"]
    assert not any("관리용 폴더" in r or "브랜드 이름" in r or "공식 도메인(" in r for r in result["reasons"])

def test_every_item_has_display_text():
    for value in detections.analyze("http://secure-paypal-login.verify-account.tk").values():
        assert value["reasons"] or value["notes"]
