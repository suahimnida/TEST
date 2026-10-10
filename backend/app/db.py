import logging
import secrets
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
        # 분석 요청자: 가린 성명과 식별 암호의 해시만 저장한다 (원문 저장 안 함)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS owners (
                analysis_id TEXT PRIMARY KEY,
                masked_name TEXT,
                secret_hash TEXT
            )
            """
        )
        # 비공개 결과의 공유 링크. 분석 1건당 링크 1개, 공유를 중지하면 행을 지운다
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS shares (
                token       TEXT PRIMARY KEY,
                analysis_id TEXT NOT NULL UNIQUE,
                created_at  TEXT NOT NULL
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
                result.model_dump_json(exclude=VIEW_ONLY_FIELDS),
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


# 요청한 사람에 따라 달라지는 값이라 저장하지 않는다
VIEW_ONLY_FIELDS = {"viewer", "share_token"}


def get_analysis_access(analysis_id: str, client_id: str | None):
    """공개 결과이거나 본인 결과이면 (분석 결과, 저장 시각, 본인 여부)를 돌려준다. 아니면 None."""
    with _connect() as (conn, p):
        row = conn.execute(
            f"SELECT result_json, created_at, client_id FROM analyses "
            f"WHERE id = {p} AND (is_public = 1 OR client_id = {p})",
            (analysis_id, client_id),
        ).fetchone()
    if row is None:
        return None
    owner = client_id is not None and row["client_id"] == client_id
    return AnalysisResponse.model_validate_json(row["result_json"]), row["created_at"], owner


def set_visibility(analysis_id: str, client_id: str | None, is_public: bool) -> AnalysisResponse | None:
    """본인 결과의 공개 여부를 바꾼다. 본인 결과가 아니면 None."""
    if client_id is None:
        return None
    with _connect() as (conn, p):
        row = conn.execute(
            f"SELECT result_json FROM analyses WHERE id = {p} AND client_id = {p}", (analysis_id, client_id)
        ).fetchone()
        if row is None:
            return None
        result = AnalysisResponse.model_validate_json(row["result_json"])
        result.is_public = is_public
        conn.execute(
            f"UPDATE analyses SET is_public = {p}, result_json = {p} WHERE id = {p} AND client_id = {p}",
            (int(is_public), result.model_dump_json(exclude=VIEW_ONLY_FIELDS), analysis_id, client_id),
        )
    return result


def is_owner(analysis_id: str, client_id: str | None) -> bool:
    if client_id is None:
        return False
    with _connect() as (conn, p):
        row = conn.execute(
            f"SELECT 1 FROM analyses WHERE id = {p} AND client_id = {p}", (analysis_id, client_id)
        ).fetchone()
    return row is not None


def get_share_token(analysis_id: str) -> str | None:
    with _connect() as (conn, p):
        row = conn.execute(f"SELECT token FROM shares WHERE analysis_id = {p}", (analysis_id,)).fetchone()
    return row["token"] if row else None


def create_share(analysis_id: str) -> str:
    """공유 링크 토큰을 만든다. 이미 있으면 같은 토큰을 돌려준다. 토큰은 추측할 수 없는 무작위 문자열이다."""
    existing = get_share_token(analysis_id)
    if existing:
        return existing
    token = secrets.token_urlsafe(16)
    with _connect() as (conn, p):
        conn.execute(
            f"INSERT INTO shares (token, analysis_id, created_at) VALUES ({p}, {p}, {p})",
            (token, analysis_id, datetime.now(timezone.utc).isoformat()),
        )
    return token


def delete_share(analysis_id: str) -> None:
    with _connect() as (conn, p):
        conn.execute(f"DELETE FROM shares WHERE analysis_id = {p}", (analysis_id,))


def get_shared(token: str):
    """공유 링크로 연 결과. (분석 결과, 저장 시각) 또는 None (없거나 공유를 중지한 링크)."""
    with _connect() as (conn, p):
        row = conn.execute(
            f"SELECT a.result_json, a.created_at, a.id FROM shares s JOIN analyses a ON a.id = s.analysis_id "
            f"WHERE s.token = {p}",
            (token,),
        ).fetchone()
    if row is None:
        return None
    return AnalysisResponse.model_validate_json(row["result_json"]), row["created_at"]


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
            where, params = "a.is_public = 1", ()
        else:
            where, params = f"a.client_id = {p}", (client_id,)
        tiebreak = "a.seq" if _database_url() else "a.rowid"
        rows = conn.execute(
            f"SELECT a.id, a.url, a.verdict, a.created_at, o.masked_name FROM analyses a "
            f"LEFT JOIN owners o ON o.analysis_id = a.id WHERE {where} "
            f"ORDER BY a.created_at DESC, {tiebreak} DESC LIMIT {p}",
            (*params, limit),
        ).fetchall()

    return [
        AnalysisSummary(
            id=row["id"], url=row["url"], verdict=row["verdict"], created_at=row["created_at"],
            owner_name=row["masked_name"],
        )
        for row in rows
    ]


def save_owner(analysis_id: str, masked_name: str | None, secret_hash: str | None) -> None:
    with _connect() as (conn, p):
        conn.execute(
            f"INSERT INTO owners (analysis_id, masked_name, secret_hash) VALUES ({p}, {p}, {p})",
            (analysis_id, masked_name, secret_hash),
        )


def get_owner_secret(analysis_id: str) -> str | None:
    """공개 결과의 식별 암호 해시. 공개가 아니거나 없으면 None (비공개 결과 삭제는 아직 지원하지 않음)."""
    with _connect() as (conn, p):
        row = conn.execute(
            f"SELECT o.secret_hash FROM owners o JOIN analyses a ON a.id = o.analysis_id "
            f"WHERE o.analysis_id = {p} AND a.is_public = 1",
            (analysis_id,),
        ).fetchone()
    return row["secret_hash"] if row else None


def delete_analysis(analysis_id: str) -> None:
    """분석 결과와 연결된 리포트, 공유 링크, 요청자 정보를 함께 지운다."""
    with _connect() as (conn, p):
        for table, column in (("reports", "analysis_id"), ("shares", "analysis_id"),
                              ("owners", "analysis_id"), ("analyses", "id")):
            conn.execute(f"DELETE FROM {table} WHERE {column} = {p}", (analysis_id,))
