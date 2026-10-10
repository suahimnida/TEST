import os

import pytest

from app import db


@pytest.fixture(autouse=True)
def no_network_reputation(monkeypatch):
    monkeypatch.setenv("REPUTATION_ENABLED", "0")


@pytest.fixture(autouse=True)
def no_real_llm(monkeypatch):
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
