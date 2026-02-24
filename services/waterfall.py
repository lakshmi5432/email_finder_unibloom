from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta
from typing import Any, Callable

from db.database import Database
from models.schemas import NormalizedProviderResponse
from services.providers import (
    ProviderHTTPError,
    ProviderRequestError,
    fetch_from_apollo,
    fetch_from_dropcontact,
    fetch_from_hunter,
)
from services.validation import validate_email_mvp


LOGGER = logging.getLogger(__name__)

CACHE_TTL_HOURS = int(os.getenv("LOOKUP_CACHE_TTL_HOURS", "24"))
RATE_LIMIT_COOLDOWN_MINUTES = int(os.getenv("PROVIDER_RATE_LIMIT_COOLDOWN_MINUTES", "30"))
REJECT_ROLE_EMAILS = os.getenv("REJECT_ROLE_EMAILS", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "y",
    "on",
}

PROVIDER_ORDER: tuple[str, ...] = ("hunter", "dropcontact", "apollo")
PROVIDER_DEFAULT_LIMITS: dict[str, int | None] = {
    "hunter": int(os.getenv("HUNTER_MONTHLY_LIMIT", "25")),
    "dropcontact": int(os.getenv("DROPCONTACT_MONTHLY_LIMIT", "100")),
    "apollo": int(os.getenv("APOLLO_MONTHLY_LIMIT", "100")),
}


ProviderCallable = Callable[..., NormalizedProviderResponse | None]
PROVIDER_CONNECTORS: dict[str, ProviderCallable] = {
    "hunter": fetch_from_hunter,
    "dropcontact": fetch_from_dropcontact,
    "apollo": fetch_from_apollo,
}


def _parse_sqlite_timestamp(raw_value: str | None) -> datetime | None:
    if not raw_value:
        return None
    try:
        return datetime.strptime(raw_value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _is_recent_lookup(lookup_row: dict[str, Any], ttl_hours: int) -> bool:
    updated_at = _parse_sqlite_timestamp(lookup_row.get("updated_at"))
    if updated_at is None:
        updated_at = _parse_sqlite_timestamp(lookup_row.get("created_at"))
    if updated_at is None:
        return False
    return datetime.utcnow() - updated_at <= timedelta(hours=ttl_hours)


def _confidence_to_percent(value: Any) -> int | None:
    if value is None:
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None

    if numeric <= 1:
        numeric *= 100
    numeric = max(0, min(100, numeric))
    return int(round(numeric))


def _confidence_to_db_fraction(value: int | None) -> float | None:
    if value is None:
        return None
    return max(0.0, min(1.0, value / 100.0))


def _lookup_row_to_result(lookup_row: dict[str, Any], cache_hit: bool) -> dict[str, Any]:
    return {
        "linkedin_url": lookup_row.get("linkedin_url"),
        "status": lookup_row.get("status", "not_found"),
        "email": lookup_row.get("email"),
        "full_name": lookup_row.get("full_name"),
        "company": lookup_row.get("company"),
        "job_title": lookup_row.get("job_title"),
        "provider": lookup_row.get("provider"),
        "confidence": _confidence_to_percent(lookup_row.get("confidence")),
        "email_status": "unknown",
        "raw": {},
        "cache_hit": cache_hit,
    }


def _empty_result(linkedin_url: str, cache_hit: bool = False) -> dict[str, Any]:
    return {
        "linkedin_url": linkedin_url,
        "status": "not_found",
        "email": None,
        "full_name": None,
        "company": None,
        "job_title": None,
        "provider": None,
        "confidence": None,
        "email_status": "unknown",
        "raw": {},
        "cache_hit": cache_hit,
    }


def _is_provider_in_cooldown(
    db: Database,
    provider: str,
    cooldown_minutes: int,
) -> bool:
    latest_attempt = db.get_latest_provider_rate_limit_attempt(provider)
    if not latest_attempt:
        return False

    created_at = _parse_sqlite_timestamp(latest_attempt.get("created_at"))
    if created_at is None:
        return False

    return datetime.utcnow() - created_at < timedelta(minutes=cooldown_minutes)


def _ensure_provider_usage_row(db: Database, provider: str, month_key: str) -> dict[str, Any]:
    usage = db.get_provider_usage(provider, month_key)
    if usage is not None:
        return usage

    db.upsert_provider_usage(
        provider=provider,
        month_key=month_key,
        used_count=0,
        estimated_limit=PROVIDER_DEFAULT_LIMITS.get(provider),
        is_enabled=True,
    )
    created_usage = db.get_provider_usage(provider, month_key)
    if created_usage is None:
        raise RuntimeError(f"Failed to initialize usage row for provider: {provider}")
    return created_usage


def _connector_for(provider: str) -> ProviderCallable:
    connector = PROVIDER_CONNECTORS.get(provider)
    if connector is None:
        raise KeyError(f"No connector configured for provider: {provider}")
    return connector


def _emit_event(event_callback: Callable[[str], None] | None, message: str) -> None:
    if event_callback is None:
        return
    event_callback(message)


def _provider_display_name(provider: str) -> str:
    return provider[:1].upper() + provider[1:]


def run_email_waterfall(
    linkedin_url: str,
    *,
    force_refresh: bool = False,
    event_callback: Callable[[str], None] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """
    Lookup engine:
    1) checks cache
    2) runs providers in order with guardrails
    3) stores attempts/final result
    4) returns normalized final output
    """
    db = Database()
    db.init_db()
    started_at = time.perf_counter()
    LOGGER.info(
        "waterfall_start request_id=%s linkedin_url=%s force_refresh=%s",
        request_id,
        linkedin_url,
        force_refresh,
    )

    existing_lookup = db.get_lookup_by_linkedin_url(linkedin_url)
    if (
        not force_refresh
        and existing_lookup
        and existing_lookup.get("status") == "found"
        and _is_recent_lookup(existing_lookup, CACHE_TTL_HOURS)
    ):
        cached_result = _lookup_row_to_result(existing_lookup, cache_hit=True)
        cached_result["source"] = "cache"
        LOGGER.info(
            "waterfall_cache_hit request_id=%s linkedin_url=%s email=%s",
            request_id,
            linkedin_url,
            cached_result.get("email"),
        )
        _emit_event(event_callback, "Cached result found. Using saved email.")
        return cached_result

    if existing_lookup and existing_lookup.get("id") is not None:
        lookup_id = int(existing_lookup["id"])
    else:
        lookup_id = db.upsert_lookup(linkedin_url=linkedin_url, status="not_found")

    month_key = db.current_month_key()
    previous_attempts = db.list_provider_attempts(lookup_id)
    attempt_order = len(previous_attempts) + 1
    found_result: NormalizedProviderResponse | None = None

    for provider in PROVIDER_ORDER:
        provider_name = _provider_display_name(provider)
        usage = _ensure_provider_usage_row(db, provider, month_key)
        is_enabled = bool(usage.get("is_enabled", 1))
        used_count = int(usage.get("used_count", 0))
        estimated_limit_raw = usage.get("estimated_limit")
        estimated_limit = int(estimated_limit_raw) if estimated_limit_raw is not None else None

        if not is_enabled:
            LOGGER.info(
                "provider_skipped request_id=%s provider=%s reason=disabled",
                request_id,
                provider,
            )
            _emit_event(event_callback, f"{provider_name}: skipped (disabled)")
            db.insert_provider_attempt(
                lookup_id=lookup_id,
                provider=provider,
                attempt_order=attempt_order,
                result="error",
                response_time_ms=0,
                error_message="skipped: provider disabled",
            )
            attempt_order += 1
            continue

        if estimated_limit is not None and used_count >= estimated_limit:
            LOGGER.info(
                "provider_skipped request_id=%s provider=%s reason=monthly_limit used=%s limit=%s",
                request_id,
                provider,
                used_count,
                estimated_limit,
            )
            _emit_event(event_callback, f"{provider_name}: skipped (limit reached)")
            db.insert_provider_attempt(
                lookup_id=lookup_id,
                provider=provider,
                attempt_order=attempt_order,
                result="error",
                response_time_ms=0,
                error_message="skipped: monthly limit reached",
            )
            attempt_order += 1
            continue

        if _is_provider_in_cooldown(db, provider, RATE_LIMIT_COOLDOWN_MINUTES):
            LOGGER.info(
                "provider_skipped request_id=%s provider=%s reason=cooldown",
                request_id,
                provider,
            )
            _emit_event(event_callback, f"{provider_name}: skipped (cooldown)")
            db.insert_provider_attempt(
                lookup_id=lookup_id,
                provider=provider,
                attempt_order=attempt_order,
                result="error",
                response_time_ms=0,
                error_message="skipped: provider cooldown active",
            )
            attempt_order += 1
            continue

        connector = _connector_for(provider)
        _emit_event(event_callback, f"Trying {provider_name}...")
        LOGGER.info(
            "provider_request_start request_id=%s provider=%s attempt_order=%s",
            request_id,
            provider,
            attempt_order,
        )
        start_time = time.perf_counter()
        try:
            provider_result = connector(
                linkedin_url,
                raise_on_http_error=True,
            )
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)

            db.increment_provider_usage(
                provider=provider,
                month_key=month_key,
                increment_by=1,
                estimated_limit=estimated_limit,
            )

            if provider_result and provider_result.email:
                validation_result = validate_email_mvp(
                    provider_result.email,
                    reject_role_accounts=REJECT_ROLE_EMAILS,
                )
                if not validation_result.is_valid:
                    LOGGER.info(
                        "provider_response request_id=%s provider=%s http_status=200 result=invalid_email reason=%s elapsed_ms=%s",
                        request_id,
                        provider,
                        validation_result.reason,
                        elapsed_ms,
                    )
                    _emit_event(event_callback, f"{provider_name}: no result")
                    db.insert_provider_attempt(
                        lookup_id=lookup_id,
                        provider=provider,
                        attempt_order=attempt_order,
                        result="not_found",
                        http_status=200,
                        response_time_ms=elapsed_ms,
                        error_message=f"invalid_email: {validation_result.reason}",
                    )
                    continue

                provider_result = provider_result.model_copy(
                    update={"email": validation_result.normalized_email}
                )
                found_result = provider_result
                LOGGER.info(
                    "provider_response request_id=%s provider=%s http_status=200 result=found elapsed_ms=%s email=%s",
                    request_id,
                    provider,
                    elapsed_ms,
                    provider_result.email,
                )
                _emit_event(event_callback, f"{provider_name}: found email")
                db.insert_provider_attempt(
                    lookup_id=lookup_id,
                    provider=provider,
                    attempt_order=attempt_order,
                    result="found",
                    http_status=200,
                    response_time_ms=elapsed_ms,
                )
                break

            LOGGER.info(
                "provider_response request_id=%s provider=%s http_status=200 result=not_found elapsed_ms=%s",
                request_id,
                provider,
                elapsed_ms,
            )
            _emit_event(event_callback, f"{provider_name}: no result")
            db.insert_provider_attempt(
                lookup_id=lookup_id,
                provider=provider,
                attempt_order=attempt_order,
                result="not_found",
                http_status=200,
                response_time_ms=elapsed_ms,
                error_message="no email returned",
            )
        except ProviderHTTPError as exc:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            LOGGER.warning(
                "provider_response request_id=%s provider=%s http_status=%s result=error elapsed_ms=%s error=%s",
                request_id,
                provider,
                exc.status_code,
                elapsed_ms,
                exc,
            )
            _emit_event(event_callback, f"{provider_name}: error ({exc.status_code})")
            db.increment_provider_usage(
                provider=provider,
                month_key=month_key,
                increment_by=1,
                estimated_limit=estimated_limit,
            )
            db.insert_provider_attempt(
                lookup_id=lookup_id,
                provider=provider,
                attempt_order=attempt_order,
                result="error",
                http_status=exc.status_code,
                response_time_ms=elapsed_ms,
                error_message=str(exc),
            )
        except ProviderRequestError as exc:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            LOGGER.warning(
                "provider_response request_id=%s provider=%s http_status=%s result=request_error elapsed_ms=%s error=%s",
                request_id,
                provider,
                None,
                elapsed_ms,
                exc,
            )
            _emit_event(event_callback, f"{provider_name}: error")
            db.insert_provider_attempt(
                lookup_id=lookup_id,
                provider=provider,
                attempt_order=attempt_order,
                result="error",
                response_time_ms=elapsed_ms,
                error_message=f"request_error: {exc}",
            )
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            LOGGER.exception(
                "provider_response request_id=%s provider=%s http_status=%s result=unexpected_error elapsed_ms=%s",
                request_id,
                provider,
                None,
                elapsed_ms,
            )
            _emit_event(event_callback, f"{provider_name}: error")
            db.insert_provider_attempt(
                lookup_id=lookup_id,
                provider=provider,
                attempt_order=attempt_order,
                result="error",
                response_time_ms=elapsed_ms,
                error_message=f"unexpected_error: {exc}",
            )
        finally:
            attempt_order += 1

    preserved_hubspot_status = existing_lookup.get("hubspot_status") if existing_lookup else None

    if found_result is not None:
        db.upsert_lookup(
            linkedin_url=linkedin_url,
            status="found",
            email=found_result.email,
            full_name=found_result.full_name,
            company=found_result.company,
            job_title=found_result.job_title,
            provider=found_result.provider,
            confidence=_confidence_to_db_fraction(found_result.confidence),
            hubspot_status=preserved_hubspot_status,
        )
        output = found_result.model_dump()
        output["status"] = "found"
        output["cache_hit"] = False
        output["source"] = "providers"
        elapsed_total_ms = int((time.perf_counter() - started_at) * 1000)
        LOGGER.info(
            "waterfall_end request_id=%s linkedin_url=%s status=found provider=%s elapsed_ms=%s",
            request_id,
            linkedin_url,
            found_result.provider,
            elapsed_total_ms,
        )
        return output

    db.upsert_lookup(
        linkedin_url=linkedin_url,
        status="not_found",
        email=None,
        full_name=None,
        company=None,
        job_title=None,
        provider=None,
        confidence=None,
        hubspot_status=preserved_hubspot_status,
    )
    result = _empty_result(linkedin_url=linkedin_url, cache_hit=False)
    result["source"] = "providers"
    elapsed_total_ms = int((time.perf_counter() - started_at) * 1000)
    LOGGER.info(
        "waterfall_end request_id=%s linkedin_url=%s status=not_found provider=%s elapsed_ms=%s",
        request_id,
        linkedin_url,
        None,
        elapsed_total_ms,
    )
    return result
