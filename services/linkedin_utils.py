from __future__ import annotations

import re
from urllib.parse import urlsplit


_ALLOWED_HOSTS = {"linkedin.com", "www.linkedin.com"}
_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_%]*$")


class LinkedInURLValidationError(ValueError):
    """Raised when a LinkedIn profile URL cannot be normalized."""


def normalize_linkedin_profile_url(raw_url: str) -> str:
    """
    Validate and normalize a LinkedIn profile URL.

    Accepted input: linkedin.com/in/<username> (with or without scheme/query).
    Canonical output: https://www.linkedin.com/in/<username>/
    """
    value = (raw_url or "").strip()
    if not value:
        raise LinkedInURLValidationError("Please enter a LinkedIn profile URL.")

    # Accept inputs like linkedin.com/in/username by adding a default scheme.
    if not value.lower().startswith(("http://", "https://")):
        value = f"https://{value}"

    parsed = urlsplit(value)

    if parsed.scheme not in {"http", "https"}:
        raise LinkedInURLValidationError("LinkedIn URL must start with http:// or https://.")

    host = (parsed.hostname or "").lower().strip()
    if host not in _ALLOWED_HOSTS:
        raise LinkedInURLValidationError(
            "Use a valid LinkedIn profile URL like https://www.linkedin.com/in/username/"
        )

    # Split path and remove empty segments to avoid duplicate slashes.
    parts = [segment for segment in parsed.path.split("/") if segment]
    if len(parts) < 2 or parts[0].lower() != "in":
        raise LinkedInURLValidationError("Only LinkedIn profile URLs are allowed (/in/...).")

    username = parts[1].strip().rstrip(".,;:!?")
    if not username:
        raise LinkedInURLValidationError("LinkedIn profile username is missing in the URL.")

    if not _USERNAME_PATTERN.match(username):
        raise LinkedInURLValidationError(
            "LinkedIn profile username has invalid characters."
        )

    return f"https://www.linkedin.com/in/{username}/"
