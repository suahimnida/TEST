import os

import pytest

from app import db


@pytest.fixture(autouse=True)
def no_real_llm(monkeypatch):
    """.env에 실제 OpenAI 키가 있어도 테스트가 진짜 API를 호출해 토큰을 쓰지 않도록 막는다."""
    from app import main

    for prefix in ("FOLLOWUP", "REPORT"):
        for name in ("MODEL", "BASE_URL", "API_KEY", "AUTH_TOKEN"):
            monkeypatch.delenv(f"{prefix}_OPENAI_{name}", raising=False)
    monkeypatch.setattr(main.followup, "DEFAULT_FOLLOWUP_MODEL", "")
    monkeypatch.setattr(main.report, "DEFAULT_REPORT_MODEL", "")
    main._llm_clients.clear()
    yield
    main._llm_clients.clear()


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """모든 테스트가 실제 DB 대신 테스트용 DB를 쓰게 한다.

    기본은 테스트마다 새로 만든 임시 SQLite 파일이다. .env에 DATABASE_URL(실제 배포 DB)이
    있어도 테스트가 그 DB에 쓰지 않도록 반드시 지운다.
    PostgreSQL로 테스트하려면 TEST_DATABASE_URL에 테스트 전용 DB 주소를 넣는다.
    """
    test_pg = os.environ.get("TEST_DATABASE_URL")
    if test_pg:
        monkeypatch.setenv("DATABASE_URL", test_pg)
        db.init_db()
        with db._connect() as (conn, _):
            conn.execute("TRUNCATE analyses, reports")
    else:
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
        db.init_db()
