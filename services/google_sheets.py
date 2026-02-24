from __future__ import annotations

import ast
import json
import logging
import os
from typing import Any

try:
    import gspread
    from gspread.exceptions import APIError, SpreadsheetNotFound, WorksheetNotFound
    from google.oauth2 import service_account
except Exception as exc:  # pragma: no cover - defensive import guard
    gspread = None  # type: ignore[assignment]
    APIError = Exception  # type: ignore[assignment]
    SpreadsheetNotFound = Exception  # type: ignore[assignment]
    WorksheetNotFound = Exception  # type: ignore[assignment]
    service_account = None  # type: ignore[assignment]
    _GOOGLE_IMPORT_ERROR: Exception | None = exc
else:
    _GOOGLE_IMPORT_ERROR = None


LOGGER = logging.getLogger(__name__)

GOOGLE_SHEETS_SCOPES = ("https://www.googleapis.com/auth/spreadsheets",)
DEFAULT_WORKSHEET_NAME = "Sheet1"
HEADERS = [
    "First name",
    "Last name",
    "Email Address",
    "Company",
    "Role in company",
    "LinkedIn URL",
]
LEGACY_HEADERS = [
    "First name",
    "Last name",
    "Email Address",
    "Company",
    "Role in company",
]


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _split_name(
    full_name: str | None,
    explicit_first_name: str | None,
    explicit_last_name: str | None,
) -> tuple[str, str]:
    first_name = _as_text(explicit_first_name)
    last_name = _as_text(explicit_last_name)
    if first_name or last_name:
        return first_name, last_name

    name = _as_text(full_name)
    if not name:
        return "", ""

    parts = name.split()
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], " ".join(parts[1:])


def _extract_company_name(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, dict):
        for key in ("name", "company_name", "organization_name", "company", "legal_name"):
            candidate = _as_text(value.get(key))
            if candidate:
                return candidate
        return ""

    if isinstance(value, list):
        for item in value:
            candidate = _extract_company_name(item)
            if candidate:
                return candidate
        return ""

    text = _as_text(value)
    if not text:
        return ""

    # Handle legacy rows where a Python dict string was persisted.
    if text.startswith("{") and text.endswith("}"):
        try:
            parsed = ast.literal_eval(text)
        except (SyntaxError, ValueError):
            return text
        extracted = _extract_company_name(parsed)
        return extracted or text

    return text


def _build_client() -> gspread.Client:
    if _GOOGLE_IMPORT_ERROR is not None or gspread is None or service_account is None:
        raise RuntimeError(
            "Google Sheets dependencies are missing. Install requirements.txt (gspread, google-auth)."
        ) from _GOOGLE_IMPORT_ERROR

    credentials_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    credentials_file = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")

    if credentials_json:
        try:
            info = json.loads(credentials_json)
        except json.JSONDecodeError as exc:
            raise ValueError("GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON.") from exc
        credentials = service_account.Credentials.from_service_account_info(
            info,
            scopes=GOOGLE_SHEETS_SCOPES,
        )
        return gspread.authorize(credentials)

    if credentials_file:
        credentials = service_account.Credentials.from_service_account_file(
            credentials_file,
            scopes=GOOGLE_SHEETS_SCOPES,
        )
        return gspread.authorize(credentials)

    raise ValueError(
        "Missing Google credentials. Set GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_SERVICE_ACCOUNT_FILE."
    )


def _service_account_email_hint() -> str:
    credentials_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    credentials_file = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")

    if credentials_json:
        try:
            info = json.loads(credentials_json)
        except Exception:
            return ""
        return _as_text(info.get("client_email"))

    if credentials_file:
        try:
            with open(credentials_file, "r", encoding="utf-8") as handle:
                info = json.load(handle)
        except Exception:
            return ""
        return _as_text(info.get("client_email"))

    return ""


def _get_or_create_worksheet(
    client: gspread.Client,
    sheet_id: str,
    worksheet_name: str,
) -> gspread.Worksheet:
    spreadsheet = client.open_by_key(sheet_id)
    try:
        return spreadsheet.worksheet(worksheet_name)
    except WorksheetNotFound:
        return spreadsheet.add_worksheet(title=worksheet_name, rows=1000, cols=10)


def _ensure_headers(worksheet: gspread.Worksheet) -> None:
    first_row = worksheet.row_values(1)
    if not first_row:
        worksheet.update("A1:F1", [HEADERS])
        return

    if first_row[: len(HEADERS)] == HEADERS:
        return

    # Upgrade older 5-column header in place to avoid duplicate header rows.
    if first_row[: len(LEGACY_HEADERS)] == LEGACY_HEADERS:
        worksheet.update("A1:F1", [HEADERS])
        return

    worksheet.insert_row(HEADERS, 1)


def append_contact_to_google_sheet(
    contact_data: dict[str, Any],
    *,
    sheet_id: str | None = None,
    worksheet_name: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """
    Save one contact row to Google Sheets.

    Expected columns:
    - First name
    - Last name
    - Email Address
    - Company
    - Role in company
    - LinkedIn URL
    """
    target_sheet_id = _as_text(sheet_id) or _as_text(os.getenv("GOOGLE_SHEET_ID"))
    target_worksheet = _as_text(worksheet_name) or _as_text(
        os.getenv("GOOGLE_WORKSHEET_NAME")
    )
    if not target_worksheet:
        target_worksheet = DEFAULT_WORKSHEET_NAME

    if not target_sheet_id:
        return {
            "success": False,
            "status": "skipped",
            "message": "Missing GOOGLE_SHEET_ID.",
            "sheet_id": None,
            "worksheet": target_worksheet,
        }

    if not isinstance(contact_data, dict):
        return {
            "success": False,
            "status": "error",
            "message": "contact_data must be a dictionary.",
            "sheet_id": target_sheet_id,
            "worksheet": target_worksheet,
        }

    email = _as_text(contact_data.get("email"))
    if not email:
        return {
            "success": False,
            "status": "skipped",
            "message": "Email is required to save into Google Sheets.",
            "sheet_id": target_sheet_id,
            "worksheet": target_worksheet,
        }

    first_name, last_name = _split_name(
        full_name=_as_text(contact_data.get("full_name")),
        explicit_first_name=_as_text(contact_data.get("first_name"))
        or _as_text(contact_data.get("firstname")),
        explicit_last_name=_as_text(contact_data.get("last_name"))
        or _as_text(contact_data.get("lastname")),
    )

    row = [
        first_name,
        last_name,
        email,
        _extract_company_name(contact_data.get("company")),
        _as_text(contact_data.get("job_title")) or _as_text(contact_data.get("role_in_company")),
        _as_text(contact_data.get("linkedin_url")),
    ]

    LOGGER.info(
        "google_sheet_write_start request_id=%s sheet_id=%s worksheet=%s email=%s",
        request_id,
        target_sheet_id,
        target_worksheet,
        email,
    )

    try:
        client = _build_client()
        worksheet = _get_or_create_worksheet(
            client=client,
            sheet_id=target_sheet_id,
            worksheet_name=target_worksheet,
        )
        _ensure_headers(worksheet)
        worksheet.append_row(row, value_input_option="USER_ENTERED")
    except SpreadsheetNotFound:
        service_account_email = _service_account_email_hint()
        message = (
            "Google Sheets write failed: spreadsheet not found or not shared with this service "
            "account. Share the sheet with Editor access."
        )
        if service_account_email:
            message += f" Service account: {service_account_email}"
        LOGGER.warning(
            "google_sheet_write_error request_id=%s sheet_id=%s worksheet=%s error_type=%s message=%s",
            request_id,
            target_sheet_id,
            target_worksheet,
            "SpreadsheetNotFound",
            message,
        )
        return {
            "success": False,
            "status": "error",
            "message": message,
            "sheet_id": target_sheet_id,
            "worksheet": target_worksheet,
        }
    except APIError as exc:
        LOGGER.exception(
            "google_sheet_write_api_error request_id=%s sheet_id=%s worksheet=%s",
            request_id,
            target_sheet_id,
            target_worksheet,
        )
        return {
            "success": False,
            "status": "error",
            "message": f"Google Sheets API error: {repr(exc)}",
            "sheet_id": target_sheet_id,
            "worksheet": target_worksheet,
        }
    except Exception as exc:
        LOGGER.exception(
            "google_sheet_write_error request_id=%s sheet_id=%s worksheet=%s error_type=%s",
            request_id,
            target_sheet_id,
            target_worksheet,
            type(exc).__name__,
        )
        return {
            "success": False,
            "status": "error",
            "message": f"Google Sheets write failed: {type(exc).__name__}: {repr(exc)}",
            "sheet_id": target_sheet_id,
            "worksheet": target_worksheet,
        }

    LOGGER.info(
        "google_sheet_write_end request_id=%s success=%s sheet_id=%s worksheet=%s",
        request_id,
        True,
        target_sheet_id,
        target_worksheet,
    )
    return {
        "success": True,
        "status": "saved",
        "message": "Saved to Google Sheets.",
        "sheet_id": target_sheet_id,
        "worksheet": target_worksheet,
    }
