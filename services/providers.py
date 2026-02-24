from __future__ import annotations

import logging
import os
import time
from typing import Any
from urllib.parse import urlsplit

import requests

from models.schemas import EmailStatus, NormalizedProviderResponse


LOGGER = logging.getLogger(__name__)

HUNTER_EMAIL_FINDER_ENDPOINT = "https://api.hunter.io/v2/email-finder"
DROPCONTACT_ENRICH_CREATE_ENDPOINT = "https://api.dropcontact.com/v1/enrich/all"
DROPCONTACT_ENRICH_FETCH_ENDPOINT = "https://api.dropcontact.com/v1/enrich/all/{request_id}"
APOLLO_PEOPLE_MATCH_ENDPOINT = "https://api.apollo.io/api/v1/people/match"

DEFAULT_TIMEOUT_SECONDS = 10

_EMAIL_PATHS = (
    "email",
    "work_email",
    "email_address",
    "person.email",
    "person.work_email",
    "data.email",
    "data.work_email",
    "data.email_address",
    "result.email",
    "emails.0.value",
    "emails.0.email",
    "email.0.email",
    "person_emails.0.email",
)
_FULL_NAME_PATHS = ("full_name", "name", "person.full_name", "person.name", "data.full_name")
_FIRST_NAME_PATHS = ("first_name", "person.first_name", "data.first_name")
_LAST_NAME_PATHS = ("last_name", "person.last_name", "data.last_name")
_COMPANY_PATHS = (
    "company",
    "company_name",
    "organization",
    "organization_name",
    "person.company",
    "person.organization.name",
    "employment.company",
    "data.company",
    "data.organization",
)
_JOB_TITLE_PATHS = (
    "job_title",
    "position",
    "title",
    "headline",
    "job",
    "person.job_title",
    "person.title",
    "employment.title",
    "data.job_title",
    "data.position",
)
_CONFIDENCE_PATHS = ("confidence", "score", "email_confidence", "data.confidence", "data.score")
_EMAIL_STATUS_PATHS = (
    "email_status",
    "verification.status",
    "email_verification",
    "data.email_status",
    "data.verification.status",
    "status",
)

_EMAIL_STATUS_MAP: dict[str, EmailStatus] = {
    "verified": "verified",
    "valid": "verified",
    "deliverable": "verified",
    "nominative": "verified",
    "nominative@pro": "verified",
    "unverified": "unverified",
    "unknown": "unknown",
    "accept_all": "accept_all",
    "catch_all": "accept_all",
    "catch_all@pro": "accept_all",
    "risky": "risky",
    "generic": "risky",
    "generic@pro": "risky",
    "invalid": "invalid",
    "undeliverable": "invalid",
    "not_found": "unknown",
}


class ProviderHTTPError(Exception):
    """Raised when provider responds with an HTTP error code."""

    def __init__(self, provider: str, status_code: int, message: str | None = None) -> None:
        self.provider = provider
        self.status_code = status_code
        super().__init__(message or f"{provider} returned HTTP {status_code}")


class ProviderRequestError(Exception):
    """Raised when request could not reach the provider."""

    def __init__(self, provider: str, message: str) -> None:
        self.provider = provider
        super().__init__(message)


def _as_clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _normalize_company_name(value: Any) -> str | None:
    """
    Providers can return company as a string or nested object.
    Normalize to a single readable company name.
    """
    if value is None:
        return None

    if isinstance(value, dict):
        for key in ("name", "company_name", "organization_name", "company", "legal_name"):
            candidate = _as_clean_text(value.get(key))
            if candidate:
                return candidate

        nested_company = value.get("organization")
        if nested_company is not None:
            nested_name = _normalize_company_name(nested_company)
            if nested_name:
                return nested_name

        return None

    if isinstance(value, list):
        for item in value:
            candidate = _normalize_company_name(item)
            if candidate:
                return candidate
        return None

    return _as_clean_text(value)


def _get_nested(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
            continue

        if isinstance(current, list):
            if not part.isdigit():
                return None
            index = int(part)
            if index < 0 or index >= len(current):
                return None
            current = current[index]
            continue

        return None
    return current


def _pick_first(data: dict[str, Any], paths: tuple[str, ...]) -> Any:
    for path in paths:
        value = _get_nested(data, path)
        if value not in (None, ""):
            return value
    return None


def _normalize_confidence(value: Any) -> int | None:
    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip().replace("%", "")
        if not value:
            return None

    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None

    if confidence <= 1:
        confidence *= 100

    confidence = max(0, min(100, confidence))
    return int(round(confidence))


def _normalize_email_status(value: Any) -> EmailStatus:
    text = _as_clean_text(value)
    if not text:
        return "unknown"
    key = text.lower().replace("-", "_").replace(" ", "_")
    return _EMAIL_STATUS_MAP.get(key, "unknown")


def _safe_json(response: requests.Response) -> dict[str, Any] | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _is_handled_http_error(provider: str, response: requests.Response) -> bool:
    status = response.status_code
    if status == 401:
        LOGGER.warning("%s authentication failed (401). Check API key.", provider)
        return True
    if status == 429:
        LOGGER.warning("%s rate limit reached (429). Try again later.", provider)
        return True
    if status >= 500:
        LOGGER.warning("%s server error (%s).", provider, status)
        return True
    if status >= 400:
        LOGGER.warning("%s request failed (%s).", provider, status)
        return True
    return False


def _extract_linkedin_handle(linkedin_url: str) -> str | None:
    parsed = urlsplit(linkedin_url)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) >= 2 and parts[0].lower() == "in":
        return parts[1]
    return None


def _dropcontact_email_candidate(
    email_items: list[Any],
) -> tuple[str | None, EmailStatus, int | None]:
    ranking: dict[str, tuple[int, EmailStatus, int]] = {
        "nominative@pro": (5, "verified", 95),
        "nominative": (4, "verified", 90),
        "catch_all@pro": (3, "accept_all", 75),
        "catch_all": (3, "accept_all", 70),
        "generic@pro": (2, "risky", 65),
        "generic": (1, "risky", 55),
        "invalid": (0, "invalid", 0),
    }

    best: tuple[int, str | None, EmailStatus, int | None] = (-1, None, "unknown", None)
    for item in email_items:
        if not isinstance(item, dict):
            continue

        email = _as_clean_text(item.get("email"))
        if not email:
            continue

        qualification = _as_clean_text(item.get("qualification"))
        normalized = qualification.lower() if qualification else "unknown"
        rank, status, confidence = ranking.get(normalized, (1, "unknown", 50))
        if rank > best[0]:
            best = (rank, email, status, confidence)

    return best[1], best[2], best[3]


def normalize_provider_response(
    provider: str,
    linkedin_url: str,
    raw_response: dict[str, Any] | None,
) -> NormalizedProviderResponse:
    """
    Convert any provider-specific payload into the app's standard response shape.
    """
    raw = raw_response or {}

    email = _as_clean_text(_pick_first(raw, _EMAIL_PATHS))
    full_name = _as_clean_text(_pick_first(raw, _FULL_NAME_PATHS))
    first_name = _as_clean_text(_pick_first(raw, _FIRST_NAME_PATHS))
    last_name = _as_clean_text(_pick_first(raw, _LAST_NAME_PATHS))

    if not full_name and (first_name or last_name):
        full_name = " ".join(part for part in (first_name, last_name) if part)

    company_value = _pick_first(raw, _COMPANY_PATHS)

    return NormalizedProviderResponse(
        linkedin_url=linkedin_url,
        email=email,
        full_name=full_name,
        company=_normalize_company_name(company_value),
        job_title=_as_clean_text(_pick_first(raw, _JOB_TITLE_PATHS)),
        provider=provider,
        confidence=_normalize_confidence(_pick_first(raw, _CONFIDENCE_PATHS)),
        email_status=_normalize_email_status(_pick_first(raw, _EMAIL_STATUS_PATHS)),
        raw=raw,
    )


def fetch_from_hunter(
    linkedin_url: str,
    *,
    linkedin_handle: str | None = None,
    api_key: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    raise_on_http_error: bool = False,
) -> NormalizedProviderResponse | None:
    """
    Hunter Email Finder connector using LinkedIn handle.
    """
    token = _as_clean_text(api_key) or _as_clean_text(os.getenv("HUNTER_API_KEY"))
    if not token:
        LOGGER.info("HUNTER_API_KEY is not set; skipping Hunter connector.")
        return None

    handle = _as_clean_text(linkedin_handle) or _extract_linkedin_handle(linkedin_url)
    if not handle:
        LOGGER.info("Hunter connector skipped because LinkedIn handle could not be parsed.")
        return None

    params = {
        "api_key": token,
        "linkedin_handle": handle,
    }

    try:
        response = requests.get(
            HUNTER_EMAIL_FINDER_ENDPOINT,
            params=params,
            timeout=timeout_seconds,
        )
    except requests.RequestException as exc:
        if raise_on_http_error:
            raise ProviderRequestError("hunter", str(exc)) from exc
        LOGGER.warning("Hunter request error: %s", exc)
        return None

    if response.status_code >= 400:
        if raise_on_http_error:
            raise ProviderHTTPError(
                "hunter",
                response.status_code,
                f"hunter returned HTTP {response.status_code}",
            )
        _is_handled_http_error("hunter", response)
        return None

    payload = _safe_json(response)
    if payload is None:
        LOGGER.warning("Hunter returned a non-JSON response.")
        return None

    normalized = normalize_provider_response(
        provider="hunter",
        linkedin_url=linkedin_url,
        raw_response=payload,
    )
    if not normalized.email:
        return None
    return normalized


def fetch_from_dropcontact(
    linkedin_url: str,
    *,
    api_key: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_polls: int = 3,
    poll_interval_seconds: float = 2.0,
    raise_on_http_error: bool = False,
) -> NormalizedProviderResponse | None:
    """
    Dropcontact enrichment connector with polling.
    """
    token = _as_clean_text(api_key) or _as_clean_text(os.getenv("DROPCONTACT_API_KEY"))
    if not token:
        LOGGER.info("DROPCONTACT_API_KEY is not set; skipping Dropcontact connector.")
        return None

    headers = {
        "X-Access-Token": token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:
        create_response = requests.post(
            DROPCONTACT_ENRICH_CREATE_ENDPOINT,
            headers=headers,
            json={"data": [{"linkedin": linkedin_url}]},
            timeout=timeout_seconds,
        )
    except requests.RequestException as exc:
        if raise_on_http_error:
            raise ProviderRequestError("dropcontact", str(exc)) from exc
        LOGGER.warning("Dropcontact create request error: %s", exc)
        return None

    if create_response.status_code >= 400:
        if raise_on_http_error:
            raise ProviderHTTPError(
                "dropcontact",
                create_response.status_code,
                f"dropcontact returned HTTP {create_response.status_code}",
            )
        _is_handled_http_error("dropcontact", create_response)
        return None

    create_payload = _safe_json(create_response)
    if create_payload is None:
        LOGGER.warning("Dropcontact create endpoint returned non-JSON response.")
        return None

    request_id = _as_clean_text(create_payload.get("request_id"))
    if not request_id:
        LOGGER.warning("Dropcontact response did not include request_id.")
        return None

    for poll_index in range(max_polls):
        try:
            poll_response = requests.get(
                DROPCONTACT_ENRICH_FETCH_ENDPOINT.format(request_id=request_id),
                headers=headers,
                params={"forceResults": "true"},
                timeout=timeout_seconds,
            )
        except requests.RequestException as exc:
            if raise_on_http_error:
                raise ProviderRequestError("dropcontact", str(exc)) from exc
            LOGGER.warning("Dropcontact poll request error: %s", exc)
            return None

        if poll_response.status_code >= 400:
            if raise_on_http_error:
                raise ProviderHTTPError(
                    "dropcontact",
                    poll_response.status_code,
                    f"dropcontact returned HTTP {poll_response.status_code}",
                )
            _is_handled_http_error("dropcontact", poll_response)
            return None

        poll_payload = _safe_json(poll_response)
        if poll_payload is None:
            LOGGER.warning("Dropcontact poll returned non-JSON response.")
            return None

        reason = _as_clean_text(poll_payload.get("reason")) or ""
        if (
            poll_payload.get("success") is False
            and "not ready yet" in reason.lower()
            and poll_index < max_polls - 1
        ):
            time.sleep(poll_interval_seconds)
            continue

        data_items = poll_payload.get("data")
        if not isinstance(data_items, list) or not data_items:
            if poll_index < max_polls - 1:
                time.sleep(poll_interval_seconds)
                continue
            return None

        first_item = data_items[0]
        if not isinstance(first_item, dict):
            return None

        candidate_email, email_status, confidence = _dropcontact_email_candidate(
            first_item.get("email") if isinstance(first_item.get("email"), list) else []
        )

        normalized_payload = dict(first_item)
        if candidate_email:
            normalized_payload["email"] = candidate_email
            normalized_payload["email_status"] = email_status
            normalized_payload["confidence"] = confidence

        normalized = normalize_provider_response(
            provider="dropcontact",
            linkedin_url=linkedin_url,
            raw_response=normalized_payload,
        )
        if not normalized.email:
            return None
        return normalized

    return None


def fetch_from_apollo(
    linkedin_url: str,
    *,
    api_key: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    raise_on_http_error: bool = False,
) -> NormalizedProviderResponse | None:
    """
    Apollo People Match connector using linkedin_url enrichment input.
    """
    token = _as_clean_text(api_key) or _as_clean_text(os.getenv("APOLLO_API_KEY"))
    if not token:
        LOGGER.info("APOLLO_API_KEY is not set; skipping Apollo connector.")
        return None

    headers = {
        "X-Api-Key": token,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = {
        "linkedin_url": linkedin_url,
        "reveal_personal_emails": False,
    }

    try:
        response = requests.post(
            APOLLO_PEOPLE_MATCH_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=timeout_seconds,
        )
    except requests.RequestException as exc:
        if raise_on_http_error:
            raise ProviderRequestError("apollo", str(exc)) from exc
        LOGGER.warning("Apollo request error: %s", exc)
        return None

    if response.status_code >= 400:
        if raise_on_http_error:
            raise ProviderHTTPError(
                "apollo",
                response.status_code,
                f"apollo returned HTTP {response.status_code}",
            )
        _is_handled_http_error("apollo", response)
        return None

    response_payload = _safe_json(response)
    if response_payload is None:
        LOGGER.warning("Apollo returned non-JSON response.")
        return None

    candidate: dict[str, Any] = response_payload
    person = response_payload.get("person")
    if isinstance(person, dict):
        candidate = person
    else:
        matches = response_payload.get("matches")
        if isinstance(matches, list) and matches and isinstance(matches[0], dict):
            candidate = matches[0]

    normalized = normalize_provider_response(
        provider="apollo",
        linkedin_url=linkedin_url,
        raw_response=candidate,
    )
    if not normalized.email:
        return None
    return normalized
