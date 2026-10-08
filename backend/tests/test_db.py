from app import db
from app.schemas import AnalysisResponse, BlacklistResult, ModelResult


def make(analysis_id, url, is_public=False):
    return AnalysisResponse(
        id=analysis_id,
        status="completed",
        url=url,
        is_public=is_public,
        blacklist=BlacklistResult(matched=False, match_type="none", source="KISA 2024"),
        model=ModelResult(status="not_ready"),
    )


def test_save_and_get_roundtrip():
    db.save_analysis(make("a1", "https://example.com"), "client-1")
    result = db.get_analysis("a1", "client-1")
    assert result is not None and result.url == "https://example.com"


def test_private_result_is_hidden_from_other_clients():
    db.save_analysis(make("a1", "https://example.com"), "client-1")
    assert db.get_analysis("a1", "client-2") is None
    assert db.get_analysis("a1", None) is None


def test_public_result_is_visible_to_everyone():
    db.save_analysis(make("a1", "https://example.com", is_public=True), "client-1")
    assert db.get_analysis("a1", None) is not None
    assert [r.id for r in db.list_analyses(10)] == ["a1"]


def test_list_is_newest_first_and_per_client():
    for i in range(3):
        db.save_analysis(make(f"mine-{i}", f"https://site{i}.com"), "client-1")
    db.save_analysis(make("other", "https://other.com"), "client-2")
    assert [r.id for r in db.list_analyses(10, "client-1")] == ["mine-2", "mine-1", "mine-0"]
    assert [r.id for r in db.list_analyses(2, "client-1")] == ["mine-2", "mine-1"]


def test_init_db_is_idempotent():
    db.init_db()
    db.init_db()


def test_describe_hides_password(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:secret@db.example.com/phish?sslmode=require")
    text = db.describe()
    assert "secret" not in text and "db.example.com" in text
