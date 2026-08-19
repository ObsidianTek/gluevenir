"""Private deterministic policy for the bounded Gluevenir Bio scenarios."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from gluevenir._ports import MemoryOperation

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_POLICY_VERSION = "bio-demo-v1"
_INTERNAL_AUDIENCES = frozenset(
    {"internal-clinical", "internal-program-lead", "internal-research"}
)
_EXTERNAL_AUDIENCES = frozenset({"partner-alpha-synthetic", "partner-beta-synthetic"})
_PURPOSES = frozenset(
    {"partner_status", "program_status", "research_review", "safety_review"}
)
_DATA_CLASSES = frozenset(
    {
        "EXTERNAL_APPROVED",
        "IP_CONFIDENTIAL",
        "MNPI_CANDIDATE",
        "PHI_CANDIDATE",
        "PII",
        "SECRET",
    }
)
_DEFERRABLE_CONTEXT = frozenset(
    {"destination", "partner_authorization", "recipient", "session_intent"}
)
_EXTERNAL_OPERATIONS = frozenset(
    {MemoryOperation.RECALL, MemoryOperation.SHARE, MemoryOperation.USE}
)


class _Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MODIFY = "MODIFY"
    STEP_UP = "STEP_UP"
    DEFER = "DEFER"


class _Destination(StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"


class _ReasonCode(StrEnum):
    INTERNAL_POLICY_ALLOW = "INTERNAL_POLICY_ALLOW"
    EXTERNAL_APPROVED_ALLOW = "EXTERNAL_APPROVED_ALLOW"
    EXACT_APPROVED_DERIVATIVE = "EXACT_APPROVED_DERIVATIVE"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    REQUIRED_CONTEXT_MISSING = "REQUIRED_CONTEXT_MISSING"
    IDENTITY_DENIED = "IDENTITY_DENIED"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    POLICY_VERSION_INVALID = "POLICY_VERSION_INVALID"
    EXTERNAL_ACTION_DENIED = "EXTERNAL_ACTION_DENIED"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    PENDING_CAPACITY = "PENDING_CAPACITY"
    PENDING_TIMEOUT = "PENDING_TIMEOUT"
    PENDING_REJECTED = "PENDING_REJECTED"
    PENDING_UNRESOLVED = "PENDING_UNRESOLVED"
    PENDING_ARGUMENTS_MISMATCH = "PENDING_ARGUMENTS_MISMATCH"


def _uuid(name: str, value: object) -> UUID:
    if not isinstance(value, UUID):
        raise TypeError(f"{name} must be a UUID")
    return value


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    normalized = value.strip()
    if not _IDENTIFIER_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a bounded identifier")
    return normalized


def _sha256(name: str, value: object) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def _aware(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


@dataclass(frozen=True, slots=True)
class _PolicyAction:
    operation: MemoryOperation
    tenant_id: UUID
    program_id: UUID
    actor_role: str
    purpose: str
    audience: str
    destination: _Destination
    policy_version: str
    requested_memory_ids: tuple[UUID, ...]
    data_classes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.operation, MemoryOperation):
            raise TypeError("operation must be a MemoryOperation")
        _uuid("tenant_id", self.tenant_id)
        _uuid("program_id", self.program_id)
        object.__setattr__(
            self, "actor_role", _identifier("actor_role", self.actor_role)
        )
        purpose = _identifier("purpose", self.purpose)
        audience = _identifier("audience", self.audience)
        if purpose not in _PURPOSES:
            raise ValueError("purpose is not allowlisted")
        if audience not in _INTERNAL_AUDIENCES | _EXTERNAL_AUDIENCES:
            raise ValueError("audience is not allowlisted")
        object.__setattr__(self, "purpose", purpose)
        object.__setattr__(self, "audience", audience)
        if not isinstance(self.destination, _Destination):
            raise TypeError("destination must be a _Destination")
        object.__setattr__(
            self,
            "policy_version",
            _identifier("policy_version", self.policy_version),
        )
        if not isinstance(self.requested_memory_ids, tuple):
            raise TypeError("requested_memory_ids must be a tuple")
        if len(self.requested_memory_ids) > 5:
            raise ValueError("requested_memory_ids must contain at most five IDs")
        for value in self.requested_memory_ids:
            _uuid("requested_memory_id", value)
        if len(set(self.requested_memory_ids)) != len(self.requested_memory_ids):
            raise ValueError("requested_memory_ids must not contain duplicates")
        if not isinstance(self.data_classes, tuple):
            raise TypeError("data_classes must be a tuple")
        if len(self.data_classes) > 8:
            raise ValueError("data_classes must contain at most eight labels")
        if any(type(value) is not str for value in self.data_classes):
            raise TypeError("data_classes values must be strings")
        if set(self.data_classes) - _DATA_CLASSES:
            raise ValueError("data_classes contains an unsupported label")
        if len(set(self.data_classes)) != len(self.data_classes):
            raise ValueError("data_classes must not contain duplicates")


@dataclass(frozen=True, slots=True)
class _ApprovedDerivative:
    approval_id: UUID
    tenant_id: UUID
    program_id: UUID
    source_memory_id: UUID
    derivative_memory_id: UUID
    source_sha256: str
    derivative_sha256: str
    purpose: str
    audience: str
    policy_version: str
    reviewed_at: datetime
    expires_at: datetime
    source_active: bool
    derivative_active: bool
    reviewed_by: str
    reviewer_role: str

    def __post_init__(self) -> None:
        for name in (
            "approval_id",
            "tenant_id",
            "program_id",
            "source_memory_id",
            "derivative_memory_id",
        ):
            _uuid(name, getattr(self, name))
        if self.source_memory_id == self.derivative_memory_id:
            raise ValueError("source and derivative memory IDs must differ")
        _sha256("source_sha256", self.source_sha256)
        _sha256("derivative_sha256", self.derivative_sha256)
        purpose = _identifier("purpose", self.purpose)
        audience = _identifier("audience", self.audience)
        if purpose not in _PURPOSES:
            raise ValueError("purpose is not allowlisted")
        if audience not in _EXTERNAL_AUDIENCES:
            raise ValueError("approved derivative audience must be external")
        object.__setattr__(self, "purpose", purpose)
        object.__setattr__(self, "audience", audience)
        object.__setattr__(
            self,
            "policy_version",
            _identifier("policy_version", self.policy_version),
        )
        _aware("reviewed_at", self.reviewed_at)
        _aware("expires_at", self.expires_at)
        if self.expires_at <= self.reviewed_at:
            raise ValueError("approval expiry must be after its review")
        for name in ("source_active", "derivative_active"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a bool")
        object.__setattr__(
            self,
            "reviewed_by",
            _identifier("reviewed_by", self.reviewed_by),
        )
        object.__setattr__(
            self,
            "reviewer_role",
            _identifier("reviewer_role", self.reviewer_role),
        )


@dataclass(frozen=True, slots=True)
class _PolicyFacts:
    now: datetime
    policy_available: bool
    identity_authorized: bool
    missing_context: tuple[str, ...] = ()
    approved_derivative: _ApprovedDerivative | None = None
    human_review_allowed: bool = False

    def __post_init__(self) -> None:
        _aware("now", self.now)
        for name in ("policy_available", "identity_authorized", "human_review_allowed"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a bool")
        if not isinstance(self.missing_context, tuple):
            raise TypeError("missing_context must be a tuple")
        if set(self.missing_context) - _DEFERRABLE_CONTEXT:
            raise ValueError("missing_context contains an unsupported field")
        if len(set(self.missing_context)) != len(self.missing_context):
            raise ValueError("missing_context must not contain duplicates")
        if self.approved_derivative is not None and not isinstance(
            self.approved_derivative, _ApprovedDerivative
        ):
            raise TypeError("approved_derivative has an invalid type")


@dataclass(frozen=True, slots=True)
class _PolicyDecision:
    decision: _Decision
    reason_code: _ReasonCode
    executable_memory_ids: tuple[UUID, ...] = ()
    executable_content_sha256: tuple[str, ...] = ()
    missing_context: tuple[str, ...] = ()
    approval_resolution_id: UUID | None = None
    resolution_actor_id: str | None = None
    resolution_actor_role: str | None = None
    model_prompt_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.decision, _Decision):
            raise TypeError("decision must be a _Decision")
        if not isinstance(self.reason_code, _ReasonCode):
            raise TypeError("reason_code must be a _ReasonCode")
        if not isinstance(self.executable_memory_ids, tuple):
            raise TypeError("executable_memory_ids must be a tuple")
        for value in self.executable_memory_ids:
            _uuid("executable_memory_id", value)
        if not isinstance(self.executable_content_sha256, tuple):
            raise TypeError("executable_content_sha256 must be a tuple")
        for value in self.executable_content_sha256:
            _sha256("executable content hash", value)
        if self.model_prompt_sha256 is not None:
            _sha256("model prompt hash", self.model_prompt_sha256)
            if self.decision not in {_Decision.ALLOW, _Decision.MODIFY}:
                raise ValueError("only executable decisions can bind a model prompt")
        if self.executable_content_sha256 and len(
            self.executable_content_sha256
        ) != len(self.executable_memory_ids):
            raise ValueError("executable IDs and content hashes must agree")
        if not isinstance(self.missing_context, tuple):
            raise TypeError("missing_context must be a tuple")
        if self.decision in {_Decision.DENY, _Decision.STEP_UP, _Decision.DEFER}:
            if self.executable_memory_ids or self.executable_content_sha256:
                raise ValueError("non-executable decisions cannot include memory data")
        if self.decision == _Decision.MODIFY and not self.executable_content_sha256:
            raise ValueError("MODIFY requires exact content hashes")
        if self.decision != _Decision.DEFER and self.missing_context:
            raise ValueError("only DEFER can include missing context")
        if self.decision == _Decision.DEFER and not self.missing_context:
            raise ValueError("DEFER requires bounded missing context")
        if self.approval_resolution_id is not None:
            _uuid("approval_resolution_id", self.approval_resolution_id)
            if self.decision != _Decision.MODIFY:
                raise ValueError("only MODIFY can bind an approval resolution")
        if self.decision == _Decision.MODIFY and self.approval_resolution_id is None:
            raise ValueError("MODIFY requires an approval resolution ID")
        resolution_actor = (self.resolution_actor_id, self.resolution_actor_role)
        if any(value is not None for value in resolution_actor):
            if not all(value is not None for value in resolution_actor):
                raise ValueError("resolution actor identity must be complete")
            _identifier("resolution_actor_id", self.resolution_actor_id)
            _identifier("resolution_actor_role", self.resolution_actor_role)
            if self.approval_resolution_id is None:
                raise ValueError("resolution actor requires an approval resolution")
        if self.approval_resolution_id is not None and not all(
            value is not None for value in resolution_actor
        ):
            raise ValueError("approval resolution requires reviewer identity")


class _BioDemoPolicy:
    """Deterministic five-outcome policy; it never calls a model."""

    def evaluate(
        self,
        action: _PolicyAction,
        facts: _PolicyFacts,
    ) -> _PolicyDecision:
        if not isinstance(action, _PolicyAction):
            raise TypeError("action must be a _PolicyAction")
        if not isinstance(facts, _PolicyFacts):
            raise TypeError("facts must be _PolicyFacts")
        if not facts.policy_available:
            return _deny(_ReasonCode.POLICY_UNAVAILABLE)
        if action.policy_version != _POLICY_VERSION:
            return _deny(_ReasonCode.POLICY_VERSION_INVALID)
        if not facts.identity_authorized:
            return _deny(_ReasonCode.IDENTITY_DENIED)
        if facts.missing_context:
            return _PolicyDecision(
                _Decision.DEFER,
                _ReasonCode.REQUIRED_CONTEXT_MISSING,
                missing_context=tuple(sorted(facts.missing_context)),
            )
        if action.destination == _Destination.INTERNAL:
            if action.audience not in _INTERNAL_AUDIENCES:
                return _deny(_ReasonCode.IDENTITY_DENIED)
            return _PolicyDecision(
                _Decision.ALLOW,
                _ReasonCode.INTERNAL_POLICY_ALLOW,
                executable_memory_ids=action.requested_memory_ids,
            )
        if (
            action.operation not in _EXTERNAL_OPERATIONS
            or action.audience not in _EXTERNAL_AUDIENCES
        ):
            return _deny(_ReasonCode.EXTERNAL_ACTION_DENIED)

        if action.data_classes == ("EXTERNAL_APPROVED",):
            return _PolicyDecision(
                _Decision.ALLOW,
                _ReasonCode.EXTERNAL_APPROVED_ALLOW,
                executable_memory_ids=action.requested_memory_ids,
            )

        approval = facts.approved_derivative
        if approval is not None:
            if not _approval_matches(action, facts.now, approval):
                return _deny(_ReasonCode.APPROVAL_INVALID)
            return _PolicyDecision(
                _Decision.MODIFY,
                _ReasonCode.EXACT_APPROVED_DERIVATIVE,
                executable_memory_ids=(approval.derivative_memory_id,),
                executable_content_sha256=(approval.derivative_sha256,),
                approval_resolution_id=approval.approval_id,
                resolution_actor_id=approval.reviewed_by,
                resolution_actor_role=approval.reviewer_role,
            )

        restricted_request = bool(
            set(action.data_classes)
            & {"IP_CONFIDENTIAL", "MNPI_CANDIDATE", "PHI_CANDIDATE", "PII", "SECRET"}
        )
        if restricted_request and facts.human_review_allowed:
            return _PolicyDecision(
                _Decision.STEP_UP,
                _ReasonCode.HUMAN_APPROVAL_REQUIRED,
            )
        return _deny(_ReasonCode.EXTERNAL_ACTION_DENIED)


def _approval_matches(
    action: _PolicyAction,
    now: datetime,
    approval: _ApprovedDerivative,
) -> bool:
    return (
        approval.tenant_id == action.tenant_id
        and approval.program_id == action.program_id
        and approval.source_memory_id in action.requested_memory_ids
        and approval.source_memory_id != approval.derivative_memory_id
        and approval.purpose == action.purpose
        and approval.audience == action.audience
        and approval.policy_version == action.policy_version
        and approval.reviewed_at <= now < approval.expires_at
        and approval.source_active
        and approval.derivative_active
    )


def _deny(reason_code: _ReasonCode) -> _PolicyDecision:
    return _PolicyDecision(_Decision.DENY, reason_code)
