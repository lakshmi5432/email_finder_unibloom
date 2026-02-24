from __future__ import annotations

from dataclasses import dataclass
import re


_LOCAL_PATTERN = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

ROLE_LOCAL_PARTS = {
    "admin",
    "billing",
    "careers",
    "contact",
    "hello",
    "help",
    "info",
    "jobs",
    "legal",
    "marketing",
    "news",
    "noreply",
    "no-reply",
    "press",
    "privacy",
    "sales",
    "security",
    "support",
    "team",
}


@dataclass(frozen=True)
class EmailValidationResult:
    is_valid: bool
    normalized_email: str | None
    reason: str | None = None


def validate_email_mvp(
    email: str | None,
    *,
    reject_role_accounts: bool = True,
) -> EmailValidationResult:
    """
    MVP email validation:
    - must contain one '@'
    - must have a valid-looking domain and TLD
    - optionally reject role-based local parts
    """
    value = (email or "").strip().lower()
    if not value:
        return EmailValidationResult(False, None, "empty_email")

    if value.count("@") != 1:
        return EmailValidationResult(False, None, "invalid_at_symbol_count")

    local_part, domain = value.split("@", 1)
    if not local_part or not domain:
        return EmailValidationResult(False, None, "missing_local_or_domain")

    if local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
        return EmailValidationResult(False, None, "invalid_local_part")

    if not _LOCAL_PATTERN.match(local_part):
        return EmailValidationResult(False, None, "invalid_local_part_chars")

    if "." not in domain or not _DOMAIN_PATTERN.match(domain):
        return EmailValidationResult(False, None, "invalid_domain")

    tld = domain.rsplit(".", 1)[-1]
    if len(tld) < 2 or not tld.isalpha():
        return EmailValidationResult(False, None, "invalid_tld")

    if reject_role_accounts and local_part in ROLE_LOCAL_PARTS:
        return EmailValidationResult(False, None, "role_based_email")

    return EmailValidationResult(True, value, None)
