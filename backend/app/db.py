import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from app.schemas import AnalysisResponse, AnalysisSummary, ReportResponse

logger = logging.getLogger(__name__)

_DEFAULT_PATH = Path(__file__).resolve().parents[1] / "data" / "analyses.db"


def _database_url() -> str | None:
    return os.environ.get("DATABASE_URL") or None


def _db_path() -> Path:
    return Path(os.environ.get("DB_PATH") or _DEFAULT_PATH)


def describe() -> str:
    url = _database_url()
    if url:
        parts = urlsplit(url)
        return f"PostgreSQL ({parts.hostname}{parts.path})"
    return f"SQLite ({_db_path()})"


@contextmanager
def _connect():
    url = _database_url()
    if url:
        import psycopg
        from psycopg.rows import dict_row

        conn = psycopg.connect(url, row_factory=dict_row, connect_timeout=10)
        placeholder = "%s"
    else:
        path = _db_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row 
        placeholder = "?"
    try:
        yield conn, placeholder
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    seq_column = "seq BIGSERIAL," if _database_url() else ""
    with _connect() as (conn, _):
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS analyses (
                {seq_column}
                id          TEXT PRIMARY KEY,
                url         TEXT NOT NULL,
                verdict     TEXT,
                created_at  TEXT NOT NULL,
                client_id   TEXT,
                is_public   INTEGER NOT NULL DEFAULT 0,
                result_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_analyses_client ON analyses (client_id, created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_analyses_public ON analyses (is_public, created_at)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                analysis_id TEXT PRIMARY KEY,
                created_at  TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )


def save_analysis(result: AnalysisResponse, client_id: str | None) -> None:
    with _connect() as (conn, p):
        conn.execute(
            f"""
            INSERT INTO analyses (id, url, verdict, created_at, client_id, is_public, result_json)
            VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p})
            """,
            (
                result.id,
                result.url,
                result.verdict,
                datetime.now(timezone.utc).isoformat(),
                client_id,
                int(result.is_public),
                result.model_dump_json(),
            ),
        )


def get_analysis(analysis_id: str, client_id: str | None) -> AnalysisResponse | None:
    with _connect() as (conn, p):
        row = conn.execute(
            f"SELECT result_json FROM analyses WHERE id = {p} AND (is_public = 1 OR client_id = {p})",
            (analysis_id, client_id),
        ).fetchone()

    if row is None:
        return None
    return AnalysisResponse.model_validate_json(row["result_json"])


def get_analysis_record(analysis_id: str, client_id: str | None):
    with _connect() as (conn, p):
        row = conn.execute(
            f"SELECT result_json, created_at FROM analyses "
            f"WHERE id = {p} AND (is_public = 1 OR client_id = {p})",
            (analysis_id, client_id),
        ).fetchone()

    if row is None:
        return None
    return AnalysisResponse.model_validate_json(row["result_json"]), row["created_at"]


def save_report(report: ReportResponse) -> None:
    with _connect() as (conn, p):
        conn.execute(
            f"""
            INSERT INTO reports (analysis_id, created_at, report_json) VALUES ({p}, {p}, {p})
            ON CONFLICT (analysis_id) DO UPDATE
            SET created_at = excluded.created_at, report_json = excluded.report_json
            """,
            (report.analysis_id, report.created_at, report.model_dump_json()),
        )


def get_report(analysis_id: str) -> ReportResponse | None:
    with _connect() as (conn, p):
        row = conn.execute(
            f"SELECT report_json FROM reports WHERE analysis_id = {p}", (analysis_id,)
        ).fetchone()

    if row is None:
        return None
    return ReportResponse.model_validate_json(row["report_json"])


def list_analyses(limit: int, client_id: str | None = None) -> list[AnalysisSummary]:
    with _connect() as (conn, p):
        if client_id is None:
            where, params = "is_public = 1", ()
        else:
            where, params = f"client_id = {p}", (client_id,)
        tiebreak = "seq" if _database_url() else "rowid"
        rows = conn.execute(
            f"SELECT id, url, verdict, created_at FROM analyses WHERE {where} "
            f"ORDER BY created_at DESC, {tiebreak} DESC LIMIT {p}",
            (*params, limit),
        ).fetchall()

    return [
        AnalysisSummary(
            id=row["id"], url=row["url"], verdict=row["verdict"], created_at=row["created_at"]
        )
        for row in rows
    ]
