"""성명·사용자 식별 암호, 공개 분석의 가린 성명, 분석 결과 삭제 테스트."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app import db
from app.main import app
from app.services import owner

client = TestClient(app)
SECRET = "Abc123Xyz789"
CONFIRM = "분석 결과를 삭제하겠습니다"


@pytest.fixture(autouse=True)
def reset_lock():
    owner._failures.clear()
    yield
    owner._failures.clear()


def analyze(is_public=True, name="김수아", secret=SECRET) -> dict:
    body = {"url": "http://secure-login-verify.tk/account", "is_public": is_public}
    if name is not None:
        body["owner_name"] = name
    if secret is not None:
        body["owner_secret"] = secret
    res = client.post("/api/v1/analyses", json=body, headers={"X-Client-Id": str(uuid.uuid4())})
    assert res.status_code == 200, res.text
    return res.json()


@pytest.mark.parametrize(
    "name, masked",
    [("김수아", "김**"), ("홍길", "홍*"), ("남궁민수", "남***"), ("제갈공명이", "제****"), ("김 수 아", "김**"), ("이", "*")],
)
def test_mask_name(name, masked):
    assert owner.mask_name(name) == masked


@pytest.mark.parametrize("secret", ["Abc1234", "Abc123Xyz7890", "Abc123Xyz78!", "가나다123456789", "abc 123xyz78"])
def test_secret_must_be_8_to_12_letters_or_digits(secret):
    res = client.post("/api/v1/analyses", json={"url": "https://a.com", "owner_name": "김수아", "owner_secret": secret})
    assert res.status_code == 422


@pytest.mark.parametrize("secret", ["Abcd1234", "Abc123Xyz7", "Abc123Xyz789"])
def test_secret_8_to_12_is_accepted(secret):
    body = analyze(secret=secret)
    ok = client.post(f"/api/v1/analyses/{body['id']}/verify-owner", json={"name": "김수아", "secret": secret})
    assert ok.json() == {"ok": True}


def test_public_list_shows_masked_name():
    body = analyze()
    assert body["owner_name"] == "김**"
    items = client.get("/api/v1/analyses?scope=public").json()["items"]
    assert next(i for i in items if i["id"] == body["id"])["owner_name"] == "김**"


def test_secret_is_never_stored_or_returned_in_plain_text():
    body = analyze()
    assert SECRET not in str(body)
    with db._connect() as (conn, p):
        row = conn.execute(f"SELECT masked_name, secret_hash FROM owners WHERE analysis_id = {p}", (body["id"],)).fetchone()
        stored = conn.execute(f"SELECT result_json FROM analyses WHERE id = {p}", (body["id"],)).fetchone()
    assert row["masked_name"] == "김**" and SECRET not in row["secret_hash"]
    assert row["secret_hash"].startswith("pbkdf2_sha256$")
    assert "김수아" not in stored["result_json"] and SECRET not in stored["result_json"]


def test_verify_owner():
    body = analyze()
    assert client.post(f"/api/v1/analyses/{body['id']}/verify-owner", json={"name": "김수아", "secret": SECRET}).json() == {"ok": True}
    assert client.post(f"/api/v1/analyses/{body['id']}/verify-owner", json={"name": "김수아", "secret": "Wrong1234567"}).status_code == 403


def test_delete_removes_result_report_and_share():
    body = analyze()
    aid = body["id"]
    client.post(f"/api/v1/analyses/{aid}/report")  # 공개 결과라 누구나 리포트를 만들 수 있다
    res = client.post(f"/api/v1/analyses/{aid}/delete", json={"name": "김수아", "secret": SECRET, "confirm_text": CONFIRM})
    assert res.json() == {"deleted": True}
    assert client.get(f"/api/v1/analyses/{aid}").status_code == 404
    assert aid not in [i["id"] for i in client.get("/api/v1/analyses?scope=public").json()["items"]]
    assert db.get_report(aid) is None


def test_delete_needs_exact_confirm_text_and_secret():
    body = analyze()
    aid = body["id"]
    assert client.post(f"/api/v1/analyses/{aid}/delete", json={"name": "김수아", "secret": SECRET, "confirm_text": "삭제"}).status_code == 400
    assert client.post(f"/api/v1/analyses/{aid}/delete", json={"name": "김수아", "secret": "Wrong1234567", "confirm_text": CONFIRM}).status_code == 403
    assert client.get(f"/api/v1/analyses/{aid}").status_code == 200  # 아직 남아 있다


def test_lock_after_repeated_wrong_secrets():
    aid = analyze()["id"]
    for _ in range(owner.MAX_FAILURES):
        assert client.post(f"/api/v1/analyses/{aid}/verify-owner", json={"name": "김수아", "secret": "Wrong1234567"}).status_code == 403
    # 잠긴 뒤에는 맞는 암호도 잠시 받지 않는다
    assert client.post(f"/api/v1/analyses/{aid}/verify-owner", json={"name": "김수아", "secret": SECRET}).status_code == 429


def test_private_result_cannot_be_deleted_yet():
    aid = analyze(is_public=False)["id"]
    res = client.post(f"/api/v1/analyses/{aid}/delete", json={"name": "김수아", "secret": SECRET, "confirm_text": CONFIRM})
    assert res.status_code == 404


def test_analysis_without_owner_info_still_works():
    body = analyze(name=None, secret=None)
    assert body["owner_name"] is None
    res = client.post(f"/api/v1/analyses/{body['id']}/verify-owner", json={"name": "김수아", "secret": SECRET})
    assert res.status_code == 404


def test_name_must_also_match():
    aid = analyze()["id"]
    for wrong in ("김수희", "이수아", "김**", ""):
        res = client.post(f"/api/v1/analyses/{aid}/verify-owner", json={"name": wrong, "secret": SECRET})
        assert res.status_code == 403
    # 공백은 무시하고 비교한다
    assert client.post(f"/api/v1/analyses/{aid}/verify-owner", json={"name": " 김 수아 ", "secret": SECRET}).status_code == 200


def test_name_is_stored_only_as_hash_and_mask():
    aid = analyze()["id"]
    with db._connect() as (conn, p):
        row = conn.execute(f"SELECT masked_name, name_hash FROM owners WHERE analysis_id = {p}", (aid,)).fetchone()
    assert row["masked_name"] == "김**" and row["name_hash"].startswith("pbkdf2_sha256$")
    assert "김수아" not in row["name_hash"]


def test_older_owner_without_name_hash_uses_masked_name():
    """성명 해시 칸이 생기기 전에 저장된 공개 결과도 삭제할 수 있다."""
    aid = analyze(name=None, secret=None)["id"]
    client.patch(f"/api/v1/analyses/{aid}/visibility", json={"is_public": True})  # 브라우저 ID 없어 실패해도 무관
    with db._connect() as (conn, p):
        conn.execute(f"UPDATE analyses SET is_public = 1 WHERE id = {p}", (aid,))
    db.save_owner(aid, "김**", owner.hash_secret(SECRET))  # name_hash 없음
    assert client.post(f"/api/v1/analyses/{aid}/verify-owner", json={"name": "김민수", "secret": SECRET}).status_code == 200
    assert client.post(f"/api/v1/analyses/{aid}/verify-owner", json={"name": "이민수", "secret": SECRET}).status_code == 403


def test_init_db_adds_name_hash_column_to_existing_table(tmp_path, monkeypatch):
    import os
    import sqlite3

    if os.environ.get("DATABASE_URL"):
        pytest.skip("SQLite에서만 확인")
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE owners (analysis_id TEXT PRIMARY KEY, masked_name TEXT, secret_hash TEXT)")
    monkeypatch.setenv("DB_PATH", str(path))
    db.init_db()
    db.init_db()  # 두 번 실행해도 오류가 없어야 한다
    with sqlite3.connect(path) as conn:
        assert "name_hash" in {r[1] for r in conn.execute("PRAGMA table_info(owners)")}
