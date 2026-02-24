from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
from typing import Any

import requests


LOGGER = logging.getLogger(__name__)

HUBSPOT_BASE_URL = "https://api.hubapi.com"
HUBSPOT_TIMEOUT_SECONDS = int(os.getenv("HUBSPOT_TIMEOUT_SECONDS", "10"))

STANDARD_FIELDS = {"email", "firstname", "lastname", "jobtitle", "company"}
CUSTOM_FIELDS = {
    "linkedin_profile_url",
    "email_found_by_provider",
    "email_enrichment_confidence",
    "email_enriched_at",
}


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _to_confidence_number(value: Any) -> int | None:
    if value is None:
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    numeric = max(0.0, min(100.0, numeric))
    return int(round(numeric))


def _split_name(
    full_name: str | None,
    explicit_firstname: str | None,
    explicit_lastname: str | None,
) -> tuple[str | None, str | None]:
    first = _as_text(explicit_firstname)
    last = _as_text(explicit_lastname)
    if first or last:
        return first, last

    name = _as_text(full_name)
    if not name:
        return None, None

    parts = name.split()
    if len(parts) == 1:
        return parts[0], None
    return parts[0], " ".join(parts[1:])


def _to_hubspot_datetime_millis(value: Any) -> str:
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 10_000_000_000:  # already milliseconds
            return str(int(numeric))
        return str(int(numeric * 1000))

    if isinstance(value, str):
        raw = value.strip()
        if raw:
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                return str(int(dt.timestamp() * 1000))
            except ValueError:
                pass

    now_utc = datetime.now(timezone.utc)
    return str(int(now_utc.timestamp() * 1000))


def _hubspot_headers(access_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _extract_error_message(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip() or "Unknown HubSpot error"

    if not isinstance(payload, dict):
        return "Unknown HubSpot error"

    message = _as_text(payload.get("message"))
    if message:
        return message
    category = _as_text(payload.get("category"))
    if category:
        return category
    return "Unknown HubSpot error"


def _response_has_custom_field_error(response: requests.Response) -> bool:
    if response.status_code != 400:
        return False
    message = _extract_error_message(response).lower()
    return any(field in message for field in CUSTOM_FIELDS)


def _search_contact_id_by_email(
    email: str,
    *,
    headers: dict[str, str],
    timeout_seconds: int,
) -> tuple[str | None, dict[str, Any] | None]:
    url = f"{HUBSPOT_BASE_URL}/crm/v3/objects/contacts/search"
    payload = {
        "filterGroups": [
            {
                "filters": [
                    {
                        "propertyName": "email",
                        "operator": "EQ",
                        "value": email,
                    }
                ]
            }
        ],
        "limit": 1,
        "properties": ["email"],
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=timeout_seconds)
    except requests.RequestException as exc:
        LOGGER.warning("hubspot_search_error email=%s error=%s", email, exc)
        return None, {
            "success": False,
            "status": "error",
            "http_status": None,
            "message": f"HubSpot search request failed: {exc}",
            "contact_id": None,
        }

    LOGGER.info("hubspot_search_response email=%s http_status=%s", email, response.status_code)

    if response.status_code != 200:
        return None, {
            "success": False,
            "status": "error",
            "http_status": response.status_code,
            "message": _extract_error_message(response),
            "contact_id": None,
        }

    try:
        body = response.json()
    except ValueError:
        return None, {
            "success": False,
            "status": "error",
            "http_status": response.status_code,
            "message": "HubSpot returned non-JSON response for contact search.",
            "contact_id": None,
        }

    if not isinstance(body, dict):
        return None, None

    results = body.get("results")
    if not isinstance(results, list) or not results:
        return None, None

    first = results[0]
    if not isinstance(first, dict):
        return None, None

    return _as_text(first.get("id")), None


def _upsert_via_create_or_update(
    *,
    contact_id: str | None,
    headers: dict[str, str],
    properties: dict[str, Any],
    timeout_seconds: int,
) -> requests.Response:
    payload = {"properties": properties}
    if contact_id:
        url = f"{HUBSPOT_BASE_URL}/crm/v3/objects/contacts/{contact_id}"
        return requests.patch(url, headers=headers, json=payload, timeout=timeout_seconds)

    url = f"{HUBSPOT_BASE_URL}/crm/v3/objects/contacts"
    return requests.post(url, headers=headers, json=payload, timeout=timeout_seconds)


def _build_contact_properties(contact_data: dict[str, Any]) -> dict[str, Any]:
    first_name, last_name = _split_name(
        full_name=_as_text(contact_data.get("full_name")),
        explicit_firstname=_as_text(contact_data.get("firstname")),
        explicit_lastname=_as_text(contact_data.get("lastname")),
    )
    confidence = _to_confidence_number(contact_data.get("confidence"))

    properties: dict[str, Any] = {
        "email": _as_text(contact_data.get("email")),
        "firstname": first_name,
        "lastname": last_name,
        "jobtitle": _as_text(contact_data.get("job_title"))
        or _as_text(contact_data.get("jobtitle")),
        "company": _as_text(contact_data.get("company")),
        "linkedin_profile_url": _as_text(contact_data.get("linkedin_url"))
        or _as_text(contact_data.get("linkedin_profile_url")),
        "email_found_by_provider": _as_text(contact_data.get("provider"))
        or _as_text(contact_data.get("email_found_by_provider")),
        "email_enrichment_confidence": confidence,
        "email_enriched_at": _to_hubspot_datetime_millis(contact_data.get("email_enriched_at")),
    }
    return {key: value for key, value in properties.items() if value is not None}


def create_or_update_contact(
    contact_data: dict[str, Any],
    *,
    access_token: str | None = None,
    timeout_seconds: int = HUBSPOT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """
    Create or update a HubSpot contact by email.

    Mapped fields:
    - Standard: email, firstname, lastname, jobtitle, company
    - Custom: linkedin_profile_url, email_found_by_provider,
      email_enrichment_confidence, email_enriched_at
    """
    token = _as_text(access_token) or _as_text(os.getenv("HUBSPOT_ACCESS_TOKEN"))
    if not token:
        return {
            "success": False,
            "status": "skipped",
            "http_status": None,
            "message": "Missing HUBSPOT_ACCESS_TOKEN.",
            "contact_id": None,
        }

    if not isinstance(contact_data, dict):
        return {
            "success": False,
            "status": "error",
            "http_status": None,
            "message": "contact_data must be a dictionary.",
            "contact_id": None,
        }

    properties = _build_contact_properties(contact_data)
    email = _as_text(properties.get("email"))
    if not email:
        return {
            "success": False,
            "status": "skipped",
            "http_status": None,
            "message": "Email is required to create/update HubSpot contact.",
            "contact_id": None,
        }

    headers = _hubspot_headers(token)
    contact_id, search_error = _search_contact_id_by_email(
        email=email,
        headers=headers,
        timeout_seconds=timeout_seconds,
    )
    if search_error is not None:
        return search_error

    operation = "updated" if contact_id else "created"
    try:
        response = _upsert_via_create_or_update(
            contact_id=contact_id,
            headers=headers,
            properties=properties,
            timeout_seconds=timeout_seconds,
        )
    except requests.RequestException as exc:
        LOGGER.warning(
            "hubspot_upsert_error operation=%s contact_id=%s error=%s",
            operation,
            contact_id,
            exc,
        )
        return {
            "success": False,
            "status": "error",
            "http_status": None,
            "message": f"HubSpot {operation} request failed: {exc}",
            "contact_id": contact_id,
        }
    LOGGER.info(
        "hubspot_upsert_response operation=%s contact_id=%s http_status=%s",
        operation,
        contact_id,
        response.status_code,
    )

    used_fallback = False
    if _response_has_custom_field_error(response):
        LOGGER.warning(
            "HubSpot custom property error detected; retrying with standard properties only."
        )
        standard_only = {k: v for k, v in properties.items() if k in STANDARD_FIELDS}
        try:
            response = _upsert_via_create_or_update(
                contact_id=contact_id,
                headers=headers,
                properties=standard_only,
                timeout_seconds=timeout_seconds,
            )
            used_fallback = True
        except requests.RequestException as exc:
            return {
                "success": False,
                "status": "error",
                "http_status": None,
                "message": f"HubSpot fallback {operation} request failed: {exc}",
                "contact_id": contact_id,
            }

    if response.status_code not in {200, 201}:
        return {
            "success": False,
            "status": "error",
            "http_status": response.status_code,
            "message": _extract_error_message(response),
            "contact_id": contact_id,
        }

    try:
        body = response.json()
    except ValueError:
        body = {}

    response_contact_id = _as_text(body.get("id")) if isinstance(body, dict) else None
    final_contact_id = response_contact_id or contact_id

    message = f"Contact {operation} in HubSpot."
    if used_fallback:
        message += " Custom properties were skipped because they are not available in HubSpot."

    return {
        "success": True,
        "status": operation,
        "http_status": response.status_code,
        "message": message,
        "contact_id": final_contact_id,
    }
