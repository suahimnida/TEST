import pytest

from app.services import guides
from app.services.followup import ACTIONS


def ev(*texts):
    return [{"id": f"E{i}", "source": "테스트", "text": t, "used_in_verdict": False} for i, t in enumerate(texts, 1)]


def keys(url, verdict, evidence):
    return [g["key"] for g in guides.retrieve(guides.evidence_tags(url, verdict, evidence), evidence)]


def test_login_impersonation_finds_report_and_account_guides():
    found = keys("http://m.login.secure.naver-account-verify-center.xyz/update", "phishing",
                 ev("'naver' 브랜드명을 쓰지만 공식 도메인이 아닙니다."))
    assert {"report_site", "official_path", "account_protect"} <= set(found)


def test_download_url_finds_malware_guide():
    assert "malware_app" in keys("http://1.2.3.4/download/app.apk", "phishing", ev("IP 주소를 사용합니다."))


def test_financial_url_finds_financial_guides():
    found = keys("http://kbstar-secure-bank.top/login", "phishing", ev("새로 만든 도메인입니다."))
    assert {"exposure_register", "account_info"} & set(found)


def test_normal_url_gets_prevention_guide_only():
    assert keys("https://www.example.com", "normal", ev("특이 사항이 없습니다.")) == ["official_path"]


def test_guides_have_official_sources():
    for g in guides._load()["guides"]:
        assert g["url"].startswith("https://") and g["source"] and g["tags"]


def test_every_action_has_a_source_guide():
    assert all(guides.guide_for_action(aid) for aid in ACTIONS)


def test_template_explanation_passes_citation_check():
    evidence = ev("위험 점수는 99점입니다.", "도메인에 로그인 단어가 있습니다.")
    found = guides.retrieve({"phishing_site", "login_page"}, evidence)
    text = guides.template_explanation("phishing", evidence, found)
    assert guides.check_citations(text, evidence, found) == text


@pytest.mark.parametrize("text", ["118로 전화하세요 [E1].", "02-1234-5678로 문의 [E1].", "www.boho.or.kr 참고 [G1]."])
def test_contact_details_are_rejected(text):
    with pytest.raises(ValueError):
        guides.check_citations(text, ev("x"), [{"id": "G1"}])
