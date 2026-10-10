from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Layer(StrEnum):
    REQUEST = "request"
    NETWORK = "network"
    GATEWAY = "gateway"
    CREDENTIALS = "credentials"
    PROVIDER = "provider"
    UNKNOWN = "unknown"


class CompletionVerdict(StrEnum):
    COMPLETED = "COMPLETED"
    NOT_COMPLETED = "NOT_COMPLETED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ConfidenceBand(StrEnum):
    HIGH = "HIGH"
    MED = "MED"
    LOW = "LOW"
    INCONCLUSIVE = "INCONCLUSIVE"


class ActionKind(StrEnum):
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    DO_NOT_RETRY = "do_not_retry"
    CHECK_THEN_RETRY = "check_then_retry"
    FIX_REQUEST = "fix_request"
    FIX_CREDENTIALS = "fix_credentials"
    WAIT = "wait"
    ESCALATE = "escalate"


class FailureCase(BaseModel):
    """Normalised, redacted representation of a failed API call."""

    method: str
    url: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body_sample: str | None = None
    status: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_sample: str | None = None
    error_class: str | None = None
    elapsed_ms: float | None = None
    idempotent: bool | None = None
    has_idempotency_key: bool = False

    @field_validator("method")
    @classmethod
    def upper_method(cls, v: str) -> str:
        return v.upper()


class Evidence(BaseModel):
    """A single piece of evidence produced by one probe."""

    probe: str
    layer: Layer
    finding: str
    supports: list[str] = Field(default_factory=list)
    contradicts: list[str] = Field(default_factory=list)
    strength: float = 0.5
    raw: dict[str, Any] | None = None

    @field_validator("strength")
    @classmethod
    def clamp_strength(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


class Hypothesis(BaseModel):
    """A candidate explanation for the failure."""

    id: str
    layer: Layer
    cause: str
    confidence: float
    band: ConfidenceBand
    evidence: list[Evidence] = Field(default_factory=list)

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


class RecoveryAction(BaseModel):
    """Safe, reviewable recovery step for the top hypothesis."""

    kind: ActionKind
    safe: bool
    explanation: str
    patch: str | None = None
    commands: list[str] = Field(default_factory=list)


class Diagnosis(BaseModel):
    """The complete output of a layers run."""

    case: FailureCase
    top: Hypothesis | None = None
    alternatives: list[Hypothesis] = Field(default_factory=list)
    completion: CompletionVerdict = CompletionVerdict.UNKNOWN
    action: RecoveryAction
    probes_run: list[str] = Field(default_factory=list)
    probes_skipped: list[str] = Field(default_factory=list)
    limits: list[str] = Field(default_factory=list)


class ProbeResult(BaseModel):
    """Raw result returned by a single probe."""

    probe: str
    ok: bool
    evidence: list[Evidence] = Field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None
    raw: dict[str, Any] | None = None
