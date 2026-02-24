from __future__ import annotations

import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "email_finder.db"
DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
VALID_RESULTS = {"found", "not_found", "error"}
MONTH_KEY_PATTERN = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")


class Database:
    """Lightweight SQLite wrapper for lookup and provider usage workflows."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a transaction-aware SQLite connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")

        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self, schema_path: str | Path = DEFAULT_SCHEMA_PATH) -> None:
        """Create tables and indexes from schema.sql if they do not exist."""
        schema_sql = Path(schema_path).read_text(encoding="utf-8")
        with self.connection() as conn:
            conn.executescript(schema_sql)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    @staticmethod
    def _validate_result(value: str, field_name: str = "result") -> None:
        if value not in VALID_RESULTS:
            allowed = ", ".join(sorted(VALID_RESULTS))
            raise ValueError(f"{field_name} must be one of: {allowed}")

    @staticmethod
    def _validate_month_key(month_key: str) -> None:
        if not MONTH_KEY_PATTERN.match(month_key):
            raise ValueError("month_key must be in YYYY-MM format (e.g. 2026-02)")

    def get_lookup_by_linkedin_url(self, linkedin_url: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM lookups WHERE linkedin_url = ?;",
                (linkedin_url,),
            ).fetchone()
        return self._row_to_dict(row)

    def list_recent_lookups(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return recent lookup rows sorted by most-recent update."""
        if limit < 1:
            raise ValueError("limit must be >= 1")

        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM lookups
                ORDER BY updated_at DESC, id DESC
                LIMIT ?;
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def update_lookup_sync_status(self, linkedin_url: str, sync_status: str) -> None:
        """Update sync status field for an existing lookup record."""
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE lookups
                SET hubspot_status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE linkedin_url = ?;
                """,
                (sync_status, linkedin_url),
            )

    def update_lookup_hubspot_status(self, linkedin_url: str, hubspot_status: str) -> None:
        """
        Backward-compatible alias.

        Preferred name is update_lookup_sync_status.
        """
        self.update_lookup_sync_status(linkedin_url, hubspot_status)

    def upsert_lookup(
        self,
        linkedin_url: str,
        status: str,
        email: str | None = None,
        full_name: str | None = None,
        company: str | None = None,
        job_title: str | None = None,
        provider: str | None = None,
        confidence: float | None = None,
        hubspot_status: str | None = None,
    ) -> int:
        """Insert or update one lookup row by unique linkedin_url and return its id."""
        self._validate_result(status, field_name="status")

        query = """
        INSERT INTO lookups (
            linkedin_url, status, email, full_name, company, job_title,
            provider, confidence, hubspot_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(linkedin_url) DO UPDATE SET
            status = excluded.status,
            email = excluded.email,
            full_name = excluded.full_name,
            company = excluded.company,
            job_title = excluded.job_title,
            provider = excluded.provider,
            confidence = excluded.confidence,
            hubspot_status = excluded.hubspot_status,
            updated_at = CURRENT_TIMESTAMP;
        """
        params = (
            linkedin_url,
            status,
            email,
            full_name,
            company,
            job_title,
            provider,
            confidence,
            hubspot_status,
        )

        with self.connection() as conn:
            conn.execute(query, params)
            row = conn.execute(
                "SELECT id FROM lookups WHERE linkedin_url = ?;",
                (linkedin_url,),
            ).fetchone()

        if row is None:
            raise RuntimeError("Failed to upsert lookup row.")
        return int(row["id"])

    def insert_provider_attempt(
        self,
        lookup_id: int,
        provider: str,
        attempt_order: int,
        result: str,
        http_status: int | None = None,
        response_time_ms: int | None = None,
        error_message: str | None = None,
    ) -> int:
        """Record one provider API attempt and return the inserted attempt id."""
        if attempt_order < 1:
            raise ValueError("attempt_order must be >= 1")
        self._validate_result(result, field_name="result")

        query = """
        INSERT INTO provider_attempts (
            lookup_id, provider, attempt_order, result, http_status,
            response_time_ms, error_message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """
        params = (
            lookup_id,
            provider,
            attempt_order,
            result,
            http_status,
            response_time_ms,
            error_message,
        )

        with self.connection() as conn:
            cursor = conn.execute(query, params)
            return int(cursor.lastrowid)

    def list_provider_attempts(self, lookup_id: int) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM provider_attempts
                WHERE lookup_id = ?
                ORDER BY attempt_order ASC;
                """,
                (lookup_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_latest_provider_attempt(self, provider: str) -> dict[str, Any] | None:
        """Return the most recent provider_attempt row for a provider."""
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM provider_attempts
                WHERE provider = ?
                ORDER BY created_at DESC, id DESC
                LIMIT 1;
                """,
                (provider,),
            ).fetchone()
        return self._row_to_dict(row)

    def get_latest_provider_rate_limit_attempt(self, provider: str) -> dict[str, Any] | None:
        """Return the most recent 429 provider_attempt row for a provider."""
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM provider_attempts
                WHERE provider = ? AND http_status = 429
                ORDER BY created_at DESC, id DESC
                LIMIT 1;
                """,
                (provider,),
            ).fetchone()
        return self._row_to_dict(row)

    def upsert_provider_usage(
        self,
        provider: str,
        month_key: str,
        used_count: int = 0,
        estimated_limit: int | None = None,
        is_enabled: bool = True,
    ) -> None:
        """Set monthly usage counters for a provider (insert or overwrite)."""
        self._validate_month_key(month_key)
        if used_count < 0:
            raise ValueError("used_count must be >= 0")
        if estimated_limit is not None and estimated_limit < 0:
            raise ValueError("estimated_limit must be >= 0")

        query = """
        INSERT INTO provider_usage (
            provider, month_key, used_count, estimated_limit, is_enabled
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(provider, month_key) DO UPDATE SET
            used_count = excluded.used_count,
            estimated_limit = excluded.estimated_limit,
            is_enabled = excluded.is_enabled;
        """
        params = (
            provider,
            month_key,
            used_count,
            estimated_limit,
            int(is_enabled),
        )
        with self.connection() as conn:
            conn.execute(query, params)

    def increment_provider_usage(
        self,
        provider: str,
        month_key: str | None = None,
        increment_by: int = 1,
        estimated_limit: int | None = None,
    ) -> None:
        """Increase used_count for a provider/month, creating the row if needed."""
        target_month = month_key or self.current_month_key()
        self._validate_month_key(target_month)
        if increment_by < 0:
            raise ValueError("increment_by must be >= 0")
        if estimated_limit is not None and estimated_limit < 0:
            raise ValueError("estimated_limit must be >= 0")

        query = """
        INSERT INTO provider_usage (
            provider, month_key, used_count, estimated_limit, is_enabled
        )
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(provider, month_key) DO UPDATE SET
            used_count = provider_usage.used_count + excluded.used_count,
            estimated_limit = COALESCE(excluded.estimated_limit, provider_usage.estimated_limit);
        """
        params = (provider, target_month, increment_by, estimated_limit)
        with self.connection() as conn:
            conn.execute(query, params)

    def get_provider_usage(self, provider: str, month_key: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT provider, month_key, used_count, estimated_limit, is_enabled
                FROM provider_usage
                WHERE provider = ? AND month_key = ?;
                """,
                (provider, month_key),
            ).fetchone()
        return self._row_to_dict(row)

    def list_provider_usage(self, month_key: str) -> list[dict[str, Any]]:
        """List provider usage rows for a month."""
        self._validate_month_key(month_key)
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT provider, month_key, used_count, estimated_limit, is_enabled
                FROM provider_usage
                WHERE month_key = ?
                ORDER BY provider ASC;
                """,
                (month_key,),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def current_month_key() -> str:
        return datetime.utcnow().strftime("%Y-%m")
