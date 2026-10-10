"""공개/비공개와 '링크가 있는 사람은 볼 수 있음' 테스트."""

import uuid

from fastapi.testclient import TestClient

from app import db
from app.main import app

client = TestClient(app)
URL = "http://secure-login-verify.tk/account"


def new_user() -> dict:
    return {"X-Client-Id": str(uuid.uuid4())}


def analyze(headers, is_public=False) -> dict:
    return client.post("/api/v1/analyses", json={"url": URL, "is_public": is_public}, headers=headers).json()


def test_private_result_is_only_for_owner():
    me, other = new_user(), new_user()
    body = analyze(me)
    assert body["viewer"] == "owner" and body["is_public"] is False
    assert client.get(f"/api/v1/analyses/{body['id']}", headers=me).json()["viewer"] == "owner"
    assert client.get(f"/api/v1/analyses/{body['id']}", headers=other).status_code == 404


def test_share_link_opens_private_result_for_anyone():
    me = new_user()
    body = analyze(me)
    token = client.post(f"/api/v1/analyses/{body['id']}/share", headers=me).json()["token"]
    assert token and len(token) >= 20

    shared = client.get(f"/api/v1/shared/{token}").json()  # 브라우저 ID 없이도 열린다
    assert shared["id"] == body["id"] and shared["viewer"] == "shared"
    assert shared["share_token"] is None  # 토큰은 본인에게만 보낸다
    assert client.get(f"/api/v1/analyses/{body['id']}", headers=me).json()["share_token"] == token
    # 같은 결과에 다시 만들면 같은 링크
    assert client.post(f"/api/v1/analyses/{body['id']}/share", headers=me).json()["token"] == token


def test_revoked_link_stops_working():
    me = new_user()
    body = analyze(me)
    token = client.post(f"/api/v1/analyses/{body['id']}/share", headers=me).json()["token"]
    assert client.delete(f"/api/v1/analyses/{body['id']}/share", headers=me).json() == {"token": None}
    assert client.get(f"/api/v1/shared/{token}").status_code == 404
    assert client.get("/api/v1/shared/not-a-real-token").status_code == 404


def test_only_owner_can_share_or_change_visibility():
    me, other = new_user(), new_user()
    body = analyze(me)
    assert client.post(f"/api/v1/analyses/{body['id']}/share", headers=other).status_code == 404
    assert client.delete(f"/api/v1/analyses/{body['id']}/share", headers=other).status_code == 404
    assert client.post(f"/api/v1/analyses/{body['id']}/share").status_code == 404  # 브라우저 ID 없음
    res = client.patch(f"/api/v1/analyses/{body['id']}/visibility", json={"is_public": True}, headers=other)
    assert res.status_code == 404


def test_visibility_change_controls_public_list():
    me, other = new_user(), new_user()
    body = analyze(me)
    public_ids = lambda: [i["id"] for i in client.get("/api/v1/analyses?scope=public").json()["items"]]
    assert body["id"] not in public_ids()

    changed = client.patch(f"/api/v1/analyses/{body['id']}/visibility", json={"is_public": True}, headers=me).json()
    assert changed["is_public"] is True and changed["viewer"] == "owner"
    assert body["id"] in public_ids()
    seen = client.get(f"/api/v1/analyses/{body['id']}", headers=other).json()
    assert seen["viewer"] == "public" and seen["share_token"] is None

    client.patch(f"/api/v1/analyses/{body['id']}/visibility", json={"is_public": False}, headers=me)
    assert body["id"] not in public_ids()
    assert client.get(f"/api/v1/analyses/{body['id']}", headers=other).status_code == 404


def test_public_choice_at_analysis_time():
    body = analyze(new_user(), is_public=True)
    assert body["is_public"] is True
    assert client.get(f"/api/v1/analyses/{body['id']}", headers=new_user()).json()["viewer"] == "public"


def test_report_through_share_link():
    me = new_user()
    body = analyze(me)
    token = client.post(f"/api/v1/analyses/{body['id']}/share", headers=me).json()["token"]
    assert client.post(f"/api/v1/analyses/{body['id']}/report").status_code == 404
    assert client.post(f"/api/v1/analyses/{body['id']}/report?share={token}").status_code == 200
    assert client.get(f"/api/v1/analyses/{body['id']}/report.pdf?share={token}").status_code == 200
    # 다른 결과의 토큰으로는 열 수 없다
    other = analyze(new_user())
    assert client.post(f"/api/v1/analyses/{other['id']}/report?share={token}").status_code == 404


def test_viewer_fields_are_not_stored():
    me = new_user()
    body = analyze(me)
    client.post(f"/api/v1/analyses/{body['id']}/share", headers=me)
    with db._connect() as (conn, p):
        stored = conn.execute(f"SELECT result_json FROM analyses WHERE id = {p}", (body["id"],)).fetchone()
    assert '"viewer"' not in stored["result_json"] and '"share_token"' not in stored["result_json"]
