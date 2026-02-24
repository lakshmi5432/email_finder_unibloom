from __future__ import annotations

from datetime import datetime, timedelta
import logging
import os
from typing import Any
from uuid import uuid4

import streamlit as st
from dotenv import load_dotenv

from db.database import Database
# from services.hubspot import create_or_update_contact  # disabled: replaced by Google Sheets flow
from services.google_sheets import append_contact_to_google_sheet
from services.linkedin_utils import LinkedInURLValidationError, normalize_linkedin_profile_url
from services.waterfall import (
    CACHE_TTL_HOURS,
    PROVIDER_DEFAULT_LIMITS,
    PROVIDER_ORDER,
    RATE_LIMIT_COOLDOWN_MINUTES,
    run_email_waterfall,
)
from utils.logging_utils import configure_logging


load_dotenv()
configure_logging()
st.set_page_config(page_title="LinkedIn Email Finder")

LOGGER = logging.getLogger(__name__)

db = Database()
db.init_db()


def _init_session_state() -> None:
    defaults: dict[str, Any] = {
        "last_result": None,
        "last_error": None,
        "sheet_result": None,
        "auto_save_sheet": False,
        "last_lookup_url": None,
        "lookup_messages": [],
        "current_request_id": None,
        "batch_results": [],
        "batch_summary": None,
        "batch_last_file_name": None,
        "batch_force_refresh": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _parse_sqlite_timestamp(raw_value: str | None) -> datetime | None:
    if not raw_value:
        return None
    try:
        return datetime.strptime(raw_value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


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


def _is_recent_lookup_row(lookup_row: dict[str, Any], ttl_hours: int) -> bool:
    updated_at = _parse_sqlite_timestamp(lookup_row.get("updated_at"))
    if updated_at is None:
        updated_at = _parse_sqlite_timestamp(lookup_row.get("created_at"))
    if updated_at is None:
        return False
    return datetime.utcnow() - updated_at <= timedelta(hours=ttl_hours)


def _ensure_provider_usage_rows(month_key: str) -> None:
    for provider in PROVIDER_ORDER:
        usage = db.get_provider_usage(provider, month_key)
        if usage is None:
            db.upsert_provider_usage(
                provider=provider,
                month_key=month_key,
                used_count=0,
                estimated_limit=PROVIDER_DEFAULT_LIMITS.get(provider),
                is_enabled=True,
            )


def _provider_cooldown_label(provider: str) -> str:
    latest_429 = db.get_latest_provider_rate_limit_attempt(provider)
    if not latest_429:
        return "no"

    created_at = _parse_sqlite_timestamp(latest_429.get("created_at"))
    if not created_at:
        return "no"

    elapsed = datetime.utcnow() - created_at
    cooldown = timedelta(minutes=RATE_LIMIT_COOLDOWN_MINUTES)
    if elapsed >= cooldown:
        return "no"

    remaining_minutes = max(1, int((cooldown - elapsed).total_seconds() // 60))
    return f"yes ({remaining_minutes}m left)"


def _provider_status_rows(month_key: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    key_by_provider = {
        "hunter": "HUNTER_API_KEY",
        "dropcontact": "DROPCONTACT_API_KEY",
        "apollo": "APOLLO_API_KEY",
    }
    for provider in PROVIDER_ORDER:
        usage = db.get_provider_usage(provider, month_key) or {}
        used_count = int(usage.get("used_count", 0))
        estimated_limit = usage.get("estimated_limit")
        is_enabled = bool(usage.get("is_enabled", 1))

        if estimated_limit is None:
            credits_left: int | str = "unlimited"
            limit_display: int | str = "unlimited"
        else:
            limit_value = int(estimated_limit)
            credits_left = max(limit_value - used_count, 0)
            limit_display = limit_value

        rows.append(
            {
                "provider": provider,
                "enabled": "enabled" if is_enabled else "disabled",
                "used_count": used_count,
                "estimated_limit": limit_display,
                "credits_left": credits_left,
                "cooldown_active": _provider_cooldown_label(provider),
                "api_key": "set"
                if str(os.getenv(key_by_provider.get(provider, ""), "")).strip()
                else "missing",
            }
        )
    return rows


def _history_rows(limit: int = 20) -> list[dict[str, Any]]:
    rows = db.list_recent_lookups(limit=limit)
    output: list[dict[str, Any]] = []
    for row in rows:
        output.append(
            {
                "updated_at": row.get("updated_at"),
                "linkedin_url": row.get("linkedin_url"),
                "status": row.get("status"),
                "email": row.get("email"),
                "provider": row.get("provider"),
                "confidence": _confidence_to_percent(row.get("confidence")),
                "sync_status": row.get("hubspot_status") or "",
            }
        )
    return output


def _cached_lookup_result(lookup_row: dict[str, Any]) -> dict[str, Any]:
    status = str(lookup_row.get("status") or "not_found")
    if status not in {"found", "not_found", "error"}:
        status = "not_found"

    return {
        "linkedin_url": lookup_row.get("linkedin_url"),
        "status": status,
        "email": lookup_row.get("email"),
        "full_name": lookup_row.get("full_name"),
        "company": lookup_row.get("company"),
        "job_title": lookup_row.get("job_title"),
        "provider": lookup_row.get("provider"),
        "confidence": _confidence_to_percent(lookup_row.get("confidence")),
        "email_status": "unknown",
        "raw": {},
        "cache_hit": True,
        "source": "cache_db",
    }


# def _sync_to_hubspot(...):
#     pass  # disabled for now because HubSpot token is unavailable


def _parse_bulk_linkedin_urls(uploaded_file: Any) -> list[str]:
    raw_bytes = uploaded_file.getvalue()
    if not raw_bytes:
        return []

    content = raw_bytes.decode("utf-8-sig", errors="replace")
    parsed_urls: list[str] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        candidate = line
        for delimiter in (",", "\t", ";"):
            if delimiter in candidate:
                candidate = candidate.split(delimiter, 1)[0].strip()
                break

        candidate = candidate.strip().strip('"').strip("'")
        if not candidate:
            continue

        header_like = candidate.lower().replace("_", " ").strip()
        if header_like in {"linkedin", "linkedin url", "linkedin profile url", "url"}:
            continue

        parsed_urls.append(candidate)

    return parsed_urls


def _save_to_google_sheet(result: dict[str, Any], *, request_id: str | None = None) -> dict[str, Any]:
    payload = {
        "email": result.get("email"),
        "full_name": result.get("full_name"),
        "job_title": result.get("job_title"),
        "company": result.get("company"),
        "linkedin_url": result.get("linkedin_url"),
        "provider": result.get("provider"),
        "confidence": result.get("confidence"),
    }
    LOGGER.info(
        "sheet_write_start request_id=%s linkedin_url=%s email=%s provider=%s",
        request_id,
        payload.get("linkedin_url"),
        payload.get("email"),
        payload.get("provider"),
    )
    response = append_contact_to_google_sheet(payload, request_id=request_id)
    LOGGER.info(
        "sheet_write_end request_id=%s success=%s status=%s sheet_id=%s worksheet=%s",
        request_id,
        response.get("success"),
        response.get("status"),
        response.get("sheet_id"),
        response.get("worksheet"),
    )

    linkedin_url = result.get("linkedin_url")
    if linkedin_url:
        if response.get("success"):
            db.update_lookup_sync_status(linkedin_url, "sheet_saved")
        else:
            db.update_lookup_sync_status(
                linkedin_url,
                str(response.get("status") or "sheet_error"),
            )
    return response


_init_session_state()
month_key = db.current_month_key()
_ensure_provider_usage_rows(month_key)

st.title("LinkedIn URL -> Waterfall -> Google Sheets")
st.write(
    "Use single lookup or bulk upload: normalize LinkedIn profile URLs, run waterfall providers, and save found emails to Google Sheets."
)

st.subheader("LinkedIn URL Input")
with st.form("lookup_form", clear_on_submit=False):
    raw_linkedin_url = st.text_input(
        "LinkedIn profile URL",
        key="linkedin_input",
        placeholder="https://www.linkedin.com/in/username/",
    )
    force_refresh = st.checkbox(
        "Force refresh (ignore cache and re-run providers)",
        value=False,
    )
    run_lookup = st.form_submit_button("Find Email", type="primary")

if run_lookup:
    st.session_state["last_error"] = None
    st.session_state["sheet_result"] = None
    st.session_state["lookup_messages"] = []
    request_id = uuid4().hex[:8]
    st.session_state["current_request_id"] = request_id
    progress_placeholder = st.empty()

    def push_message(message: str) -> None:
        st.session_state["lookup_messages"].append(message)
        try:
            progress_placeholder.markdown(
                "\n".join(f"- {line}" for line in st.session_state["lookup_messages"])
            )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            LOGGER.warning(
                "lookup_progress_render_error request_id=%s error_type=%s",
                request_id,
                type(exc).__name__,
            )

    LOGGER.info(
        "lookup_request_start request_id=%s raw_url=%s force_refresh=%s",
        request_id,
        raw_linkedin_url,
        force_refresh,
    )

    try:
        normalized_url = normalize_linkedin_profile_url(raw_linkedin_url)
    except LinkedInURLValidationError as exc:
        st.session_state["last_result"] = None
        st.session_state["last_error"] = "Invalid LinkedIn URL"
        push_message("Invalid LinkedIn URL")
        LOGGER.warning("lookup_invalid_linkedin_url request_id=%s error=%s", request_id, exc)
    else:
        st.session_state["last_lookup_url"] = normalized_url
        LOGGER.info("lookup_normalized_url request_id=%s linkedin_url=%s", request_id, normalized_url)
        cached_lookup = db.get_lookup_by_linkedin_url(normalized_url)
        if (
            cached_lookup
            and not force_refresh
            and str(cached_lookup.get("status") or "") in {"found", "not_found", "error"}
            and _is_recent_lookup_row(cached_lookup, CACHE_TTL_HOURS)
        ):
            st.session_state["last_result"] = _cached_lookup_result(cached_lookup)
            cached_status = st.session_state["last_result"].get("status")
            if cached_status == "found":
                push_message("Cached result found. Using saved email.")
            elif cached_status == "not_found":
                push_message("Cached lookup: no email found.")
            else:
                push_message("Cached lookup: previous error.")
            LOGGER.info(
                "lookup_cache_hit request_id=%s linkedin_url=%s status=%s",
                request_id,
                normalized_url,
                cached_status,
            )
        else:
            try:
                with st.spinner("Running provider waterfall..."):
                    st.session_state["last_result"] = run_email_waterfall(
                        normalized_url,
                        force_refresh=force_refresh,
                        event_callback=push_message,
                        request_id=request_id,
                    )
            except Exception as exc:
                st.session_state["last_result"] = None
                st.session_state["last_error"] = "Lookup failed. Check Provider Status and app logs."
                push_message("Lookup failed")
                LOGGER.exception(
                    "lookup_request_failed request_id=%s linkedin_url=%s error=%s",
                    request_id,
                    normalized_url,
                    exc,
                )

            if (
                st.session_state.get("auto_save_sheet")
                and st.session_state["last_result"]
                and st.session_state["last_result"].get("status") == "found"
            ):
                with st.spinner("Saving to Google Sheets..."):
                    st.session_state["sheet_result"] = _save_to_google_sheet(
                        st.session_state["last_result"],
                        request_id=request_id,
                    )
                if st.session_state["sheet_result"].get("success"):
                    push_message("Saved to Google Sheets")

    LOGGER.info(
        "lookup_request_end request_id=%s status=%s email=%s source=%s",
        request_id,
        (st.session_state.get("last_result") or {}).get("status"),
        (st.session_state.get("last_result") or {}).get("email"),
        (st.session_state.get("last_result") or {}).get("source"),
    )

st.subheader("Result Panel")
if st.session_state.get("last_error"):
    st.error(st.session_state["last_error"])
elif not st.session_state.get("last_result"):
    st.info("No lookup yet. Enter a LinkedIn URL and click Find Email.")
else:
    result = st.session_state["last_result"]
    if result.get("status") == "found":
        st.success(f"Email found: {result.get('email')}")
    else:
        st.warning("No email found from providers.")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Provider", result.get("provider") or "-")
    col2.metric("Confidence", str(result.get("confidence") or "-"))
    col3.metric("Cache Hit", "yes" if result.get("cache_hit") else "no")
    col4.metric("Source", result.get("source") or "providers")

    with st.expander("Raw Result"):
        st.json(result)

if st.session_state.get("lookup_messages"):
    st.caption("Lookup progress")
    for message in st.session_state["lookup_messages"]:
        st.write(f"- {message}")

st.subheader("Save to Google Sheets")
st.toggle(
    "Auto-save successful lookups to Google Sheets",
    key="auto_save_sheet",
)

current_result = st.session_state.get("last_result")
if current_result and current_result.get("status") == "found":
    if st.button("Save Current Result to Google Sheets"):
        with st.spinner("Saving to Google Sheets..."):
            st.session_state["sheet_result"] = _save_to_google_sheet(
                current_result,
                request_id=st.session_state.get("current_request_id"),
            )
        if st.session_state["sheet_result"].get("success"):
            st.session_state["lookup_messages"].append("Saved to Google Sheets")
else:
    st.caption("Run a successful lookup to enable save.")

sheet_result = st.session_state.get("sheet_result")
if sheet_result:
    message = sheet_result.get("message") or "Google Sheets request completed."
    if sheet_result.get("success"):
        st.success("Saved to Google Sheets")
        if message != "Saved to Google Sheets":
            st.caption(message)
    elif sheet_result.get("status") == "skipped":
        st.warning(message)
    else:
        st.error(message)

    if sheet_result.get("sheet_id"):
        st.caption(
            f"Sheet: {sheet_result.get('sheet_id')} | Worksheet: {sheet_result.get('worksheet')}"
        )

st.subheader("Bulk Upload (One LinkedIn URL Per Row)")
uploaded_file = st.file_uploader(
    "Upload .txt or .csv file",
    type=["txt", "csv"],
    help="File format: one LinkedIn profile URL per row.",
)
st.checkbox(
    "Force refresh for bulk (ignore cache and re-run providers)",
    key="batch_force_refresh",
)

parsed_bulk_urls: list[str] = []
if uploaded_file is not None:
    parsed_bulk_urls = _parse_bulk_linkedin_urls(uploaded_file)
    st.caption(f"Parsed rows: {len(parsed_bulk_urls)} from `{uploaded_file.name}`")

if st.button("Run Bulk Lookup + Save to Google Sheets", type="primary"):
    st.session_state["batch_results"] = []
    st.session_state["batch_summary"] = None
    st.session_state["batch_last_file_name"] = uploaded_file.name if uploaded_file else None

    if uploaded_file is None:
        st.warning("Upload a file first.")
    elif not parsed_bulk_urls:
        st.warning("No rows found. Please upload a file with one LinkedIn URL per row.")
    else:
        batch_request_id = uuid4().hex[:8]
        force_batch_refresh = bool(st.session_state.get("batch_force_refresh"))
        LOGGER.info(
            "bulk_lookup_start request_id=%s file_name=%s rows=%s force_refresh=%s",
            batch_request_id,
            uploaded_file.name,
            len(parsed_bulk_urls),
            force_batch_refresh,
        )

        progress_bar = st.progress(0.0)
        progress_text = st.empty()
        seen_normalized_urls: set[str] = set()
        batch_rows: list[dict[str, Any]] = []

        invalid_count = 0
        duplicate_count = 0
        found_count = 0
        not_found_count = 0
        lookup_error_count = 0
        sheet_saved_count = 0
        sheet_failed_count = 0

        total_rows = len(parsed_bulk_urls)

        for index, input_url in enumerate(parsed_bulk_urls, start=1):
            progress_text.info(f"Processing row {index} of {total_rows}")
            row_request_id = f"{batch_request_id}-{index}"

            try:
                normalized_url = normalize_linkedin_profile_url(input_url)
            except LinkedInURLValidationError:
                invalid_count += 1
                batch_rows.append(
                    {
                        "row": index,
                        "input_url": input_url,
                        "normalized_url": "",
                        "lookup_status": "invalid_url",
                        "email": "",
                        "provider": "",
                        "saved_to_sheet": "no",
                        "note": "Invalid LinkedIn URL",
                    }
                )
                progress_bar.progress(index / total_rows)
                continue

            if normalized_url in seen_normalized_urls:
                duplicate_count += 1
                batch_rows.append(
                    {
                        "row": index,
                        "input_url": input_url,
                        "normalized_url": normalized_url,
                        "lookup_status": "duplicate_skipped",
                        "email": "",
                        "provider": "",
                        "saved_to_sheet": "no",
                        "note": "Duplicate normalized URL in uploaded file",
                    }
                )
                progress_bar.progress(index / total_rows)
                continue

            seen_normalized_urls.add(normalized_url)

            try:
                lookup_result = run_email_waterfall(
                    normalized_url,
                    force_refresh=force_batch_refresh,
                    request_id=row_request_id,
                )
            except Exception as exc:
                lookup_error_count += 1
                LOGGER.exception(
                    "bulk_lookup_row_error request_id=%s row=%s linkedin_url=%s",
                    batch_request_id,
                    index,
                    normalized_url,
                )
                batch_rows.append(
                    {
                        "row": index,
                        "input_url": input_url,
                        "normalized_url": normalized_url,
                        "lookup_status": "error",
                        "email": "",
                        "provider": "",
                        "saved_to_sheet": "no",
                        "note": str(exc),
                    }
                )
                progress_bar.progress(index / total_rows)
                continue

            lookup_status = str(lookup_result.get("status") or "not_found")
            email = str(lookup_result.get("email") or "")
            provider = str(lookup_result.get("provider") or "")
            note = ""
            saved_to_sheet = "no"

            if lookup_status == "found" and email:
                found_count += 1
                sheet_response = _save_to_google_sheet(
                    lookup_result,
                    request_id=row_request_id,
                )
                if sheet_response.get("success"):
                    sheet_saved_count += 1
                    saved_to_sheet = "yes"
                    note = "Saved to Google Sheets"
                else:
                    sheet_failed_count += 1
                    note = str(sheet_response.get("message") or "Google Sheets write failed")
            elif lookup_status == "not_found":
                not_found_count += 1
                note = "No email found"
            else:
                lookup_error_count += 1
                note = "Lookup error"

            batch_rows.append(
                {
                    "row": index,
                    "input_url": input_url,
                    "normalized_url": normalized_url,
                    "lookup_status": lookup_status,
                    "email": email,
                    "provider": provider,
                    "saved_to_sheet": saved_to_sheet,
                    "note": note,
                }
            )
            progress_bar.progress(index / total_rows)

        progress_text.success(f"Bulk run completed. Processed {total_rows} row(s).")

        unique_valid_rows = len(seen_normalized_urls)
        summary = {
            "file_name": uploaded_file.name,
            "total_rows": total_rows,
            "unique_valid_rows": unique_valid_rows,
            "invalid_rows": invalid_count,
            "duplicate_rows": duplicate_count,
            "found_emails": found_count,
            "not_found": not_found_count,
            "lookup_errors": lookup_error_count,
            "sheet_saved": sheet_saved_count,
            "sheet_failed": sheet_failed_count,
        }

        st.session_state["batch_results"] = batch_rows
        st.session_state["batch_summary"] = summary
        st.session_state["batch_last_file_name"] = uploaded_file.name

        LOGGER.info(
            "bulk_lookup_end request_id=%s file_name=%s total_rows=%s unique_valid=%s invalid=%s duplicates=%s found=%s not_found=%s lookup_errors=%s sheet_saved=%s sheet_failed=%s",
            batch_request_id,
            uploaded_file.name,
            total_rows,
            unique_valid_rows,
            invalid_count,
            duplicate_count,
            found_count,
            not_found_count,
            lookup_error_count,
            sheet_saved_count,
            sheet_failed_count,
        )

batch_summary = st.session_state.get("batch_summary")
if batch_summary:
    st.caption(f"Last batch file: `{batch_summary.get('file_name')}`")
    metric_cols = st.columns(5)
    metric_cols[0].metric("Rows", str(batch_summary.get("total_rows", 0)))
    metric_cols[1].metric("Found", str(batch_summary.get("found_emails", 0)))
    metric_cols[2].metric("Saved", str(batch_summary.get("sheet_saved", 0)))
    metric_cols[3].metric("Invalid", str(batch_summary.get("invalid_rows", 0)))
    metric_cols[4].metric("Duplicates", str(batch_summary.get("duplicate_rows", 0)))

batch_results = st.session_state.get("batch_results") or []
if batch_results:
    st.dataframe(batch_results, width="stretch", hide_index=True)

st.subheader("History / Recent Lookups")
history_rows = _history_rows(limit=20)
if history_rows:
    st.dataframe(history_rows, width="stretch", hide_index=True)
else:
    st.info("No lookup history yet.")

st.subheader("Provider Status")
status_rows = _provider_status_rows(month_key)
st.dataframe(status_rows, width="stretch", hide_index=True)
st.caption(f"Current usage month: {month_key}")
st.caption(f"Provider cooldown window: {RATE_LIMIT_COOLDOWN_MINUTES} minutes")
