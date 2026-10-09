"""분석 결과를 저장/조회한다.

저장소는 환경변수로 고른다.
    DATABASE_URL  설정되어 있으면 PostgreSQL에 저장 (배포용. Neon, Supabase 등의 연결 문자열)
                  예: postgresql://user:password@host/dbname?sslmode=require
    DB_PATH       DATABASE_URL이 없을 때 쓰는 SQLite 파일 경로 (기본: backend/data/analyses.db)

Render 무료 인스턴스는 디스크가 임시라서 재배포하거나 서버가 잠들면 SQLite 파일이
지워진다. 배포 환경에서는 반드시 DATABASE_URL로 외부 DB를 연결해야 기록이 남는다.
"""

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
    """로그용 저장소 설명. 비밀번호는 출력하지 않는다."""
    url = _database_url()
    if url:
        parts = urlsplit(url)
        return f"PostgreSQL ({parts.hostname}{parts.path})"
    return f"SQLite ({_db_path()})"


@contextmanager
def _connect():
    """(연결, 자리표시자) 를 돌려준다. SQLite는 '?', PostgreSQL은 '%s'를 쓴다."""
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
        conn.row_factory = sqlite3.Row  # 조회 결과를 row["url"]처럼 열 이름으로 꺼낼 수 있게
        placeholder = "?"
    try:
        yield conn, placeholder
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """테이블이 없으면 만든다. 이미 있으면 아무 일도 하지 않는다."""
    # 같은 시각에 저장된 기록의 순서를 정하는 열: SQLite는 내장 rowid, PostgreSQL은 seq
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
        # 분석 1건당 리포트 1개. 다시 만들면 덮어쓴다
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
    """client_id는 응답(result_json)에 넣지 않고 별도 열에만 저장한다."""
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
    """공개 결과이거나 요청한 브라우저가 만든 결과만 반환한다. 아니면 None."""
    with _connect() as (conn, p):
        row = conn.execute(
            f"SELECT result_json FROM analyses WHERE id = {p} AND (is_public = 1 OR client_id = {p})",
            (analysis_id, client_id),
        ).fetchone()

    if row is None:
        return None
    return AnalysisResponse.model_validate_json(row["result_json"])


def get_analysis_record(analysis_id: str, client_id: str | None):
    """get_analysis와 같은 권한 규칙으로 (분석 결과, 저장 시각)을 반환한다. 없으면 None."""
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
    """권한 확인은 하지 않는다. 호출 전에 get_analysis_record로 분석 결과 접근 권한을 확인할 것."""
    with _connect() as (conn, p):
        row = conn.execute(
            f"SELECT report_json FROM reports WHERE analysis_id = {p}", (analysis_id,)
        ).fetchone()

    if row is None:
        return None
    return ReportResponse.model_validate_json(row["report_json"])


def list_analyses(limit: int, client_id: str | None = None) -> list[AnalysisSummary]:
    """client_id가 있으면 그 브라우저의 기록을, 없으면 공개 기록을 최근 순으로 반환한다."""
    with _connect() as (conn, p):
        if client_id is None:
            where, params = "is_public = 1", ()
        else:
            where, params = f"client_id = {p}", (client_id,)
        # 저장 시각이 같으면(빠르게 연달아 저장) 나중에 저장된 행을 앞에
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
