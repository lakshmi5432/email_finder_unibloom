from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


LookupStatus = Literal["found", "not_found", "error"]
AttemptResult = Literal["found", "not_found", "error"]
EmailStatus = Literal["verified", "unverified", "accept_all", "risky", "invalid", "unknown"]


class LookupPayload(BaseModel):
    linkedin_url: str
    status: LookupStatus
    email: str | None = None
    full_name: str | None = None
    company: str | None = None
    job_title: str | None = None
    provider: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    hubspot_status: str | None = None


class LookupRecord(LookupPayload):
    id: int
    created_at: str
    updated_at: str


class ProviderAttemptPayload(BaseModel):
    lookup_id: int = Field(ge=1)
    provider: str
    attempt_order: int = Field(ge=1)
    result: AttemptResult
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_time_ms: int | None = Field(default=None, ge=0)
    error_message: str | None = None


class ProviderAttemptRecord(ProviderAttemptPayload):
    id: int
    created_at: str


class ProviderUsagePayload(BaseModel):
    provider: str
    month_key: str = Field(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")
    used_count: int = Field(default=0, ge=0)
    estimated_limit: int | None = Field(default=None, ge=0)
    is_enabled: bool = True


class NormalizedProviderResponse(BaseModel):
    """
    App-wide internal response schema for all provider outputs.

    Every provider adapter should return this shape before handing data to the
    rest of the app.
    """

    linkedin_url: str
    email: str | None = None
    full_name: str | None = None
    company: str | None = None
    job_title: str | None = None
    provider: str
    confidence: int | None = Field(default=None, ge=0, le=100)
    email_status: EmailStatus = "unknown"
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def lookup_status(self) -> LookupStatus:
        return "found" if self.email else "not_found"
