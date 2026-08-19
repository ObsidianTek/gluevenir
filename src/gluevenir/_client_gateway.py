"""Private adapter from the public SDK contract to the governed gateway."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from gluevenir._gateway import (
    _Clock,
    _GatewayAction,
    _GatewayResult,
    _hash_action_arguments,
    _MemoryActionGateway,
)
from gluevenir._policy import (
    _ApprovedDerivative,
    _Destination,
    _PolicyAction,
    _PolicyFacts,
)
from gluevenir._ports import MemoryContext, MemoryOperation, RecallRequest
from gluevenir._session_context import _prior_receipt_context_sha256

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class _UuidFactory(Protocol):
    def __call__(self) -> UUID: ...


class _RecallAuthority(Protocol):
    """Server-side identity/session mapping; browser values are never authority."""

    def authorize(
        self,
        *,
        context: MemoryContext,
        request: RecallRequest,
        now: datetime,
    ) -> tuple[_AuthorizedRecallContext, bool]: ...


@dataclass(frozen=True, slots=True)
class _AuthorizedRecallContext:
    """Trusted, pre-provisioned session and exact bounded demo authorization."""

    expected_public_context: MemoryContext
    tenant_id: UUID
    program_id: UUID
    session_id: UUID
    intent_id: UUID
    original_intent_sha256: str
    prior_receipt_ids: tuple[UUID, ...]
    requested_memory_ids: tuple[UUID, ...]
    data_classes: tuple[str, ...]
    destination: _Destination
    policy_version: str = "bio-demo-v1"
    missing_context: tuple[str, ...] = ()
    approved_derivative: _ApprovedDerivative | None = None
    human_review_allowed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.expected_public_context, MemoryContext):
            raise TypeError("expected_public_context must be a MemoryContext")
        for name in ("tenant_id", "program_id", "session_id", "intent_id"):
            if not isinstance(getattr(self, name), UUID):
                raise TypeError(f"{name} must be a UUID")
        if self.expected_public_context.tenant_id != str(self.tenant_id):
            raise ValueError("trusted tenant context does not match its UUID")
        if self.expected_public_context.program_id != str(self.program_id):
            raise ValueError("trusted program context does not match its UUID")
        if not isinstance(self.original_intent_sha256, str) or not _SHA256_RE.fullmatch(
            self.original_intent_sha256
        ):
            raise ValueError("original_intent_sha256 must be a SHA-256 digest")
        _prior_receipt_context_sha256(self.prior_receipt_ids)
        if type(self.human_review_allowed) is not bool:
            raise TypeError("human_review_allowed must be a bool")
        # Reuse the policy envelope as the canonical validation boundary.
        self.policy_action()
        _PolicyFacts(
            now=datetime.fromtimestamp(0, tz=UTC),
            policy_available=True,
            identity_authorized=True,
            missing_context=self.missing_context,
            approved_derivative=self.approved_derivative,
            human_review_allowed=self.human_review_allowed,
        )

    def policy_action(self) -> _PolicyAction:
        expected = self.expected_public_context
        return _PolicyAction(
            operation=MemoryOperation.RECALL,
            tenant_id=self.tenant_id,
            program_id=self.program_id,
            actor_role=expected.actor_role,
            purpose=expected.purpose,
            audience=expected.audience,
            destination=self.destination,
            policy_version=self.policy_version,
            requested_memory_ids=self.requested_memory_ids,
            data_classes=self.data_classes,
        )

    def policy_facts(self, *, now: datetime, identity_authorized: bool) -> _PolicyFacts:
        return _PolicyFacts(
            now=now,
            policy_available=True,
            identity_authorized=identity_authorized,
            missing_context=self.missing_context,
            approved_derivative=self.approved_derivative,
            human_review_allowed=self.human_review_allowed,
        )


class _StaticSyntheticRecallAuthority:
    """Exact server-side mapping for one synthetic demonstration scenario."""

    __slots__ = ("_authorization",)

    def __init__(self, authorization: _AuthorizedRecallContext) -> None:
        if not isinstance(authorization, _AuthorizedRecallContext):
            raise TypeError("authorization must be an _AuthorizedRecallContext")
        self._authorization = authorization

    def authorize(
        self,
        *,
        context: MemoryContext,
        request: RecallRequest,
        now: datetime,
    ) -> tuple[_AuthorizedRecallContext, bool]:
        if not isinstance(context, MemoryContext):
            raise TypeError("context must be a MemoryContext")
        if not isinstance(request, RecallRequest):
            raise TypeError("request must be a RecallRequest")
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise ValueError("now must be timezone aware")
        return (
            self._authorization,
            context == self._authorization.expected_public_context,
        )


class _ClientGatewayUnavailable(RuntimeError):
    """Sanitized failure before an action can enter the private gateway."""


class _GovernedRecallGateway:
    """Implement the public protocol by entering the real gateway exactly once."""

    __slots__ = ("_authority", "_clock", "_gateway", "_new_uuid")

    def __init__(
        self,
        *,
        gateway: _MemoryActionGateway,
        authority: _RecallAuthority,
        clock: _Clock,
        new_uuid: _UuidFactory,
    ) -> None:
        if not isinstance(gateway, _MemoryActionGateway):
            raise TypeError("gateway must be a _MemoryActionGateway")
        if not callable(new_uuid):
            raise TypeError("new_uuid must be callable")
        self._gateway = gateway
        self._authority = authority
        self._clock = clock
        self._new_uuid = new_uuid

    def execute(
        self,
        *,
        operation: MemoryOperation,
        payload: object,
        context: MemoryContext,
    ) -> _GatewayResult:
        if operation != MemoryOperation.RECALL:
            raise ValueError("public adapter supports only RECALL")
        if not isinstance(payload, RecallRequest):
            raise TypeError("RECALL payload must be a RecallRequest")
        if not isinstance(context, MemoryContext):
            raise TypeError("context must be a MemoryContext")
        try:
            now = self._clock.now()
            if not isinstance(now, datetime) or now.utcoffset() is None:
                raise ValueError
            authorization, identity_authorized = self._authority.authorize(
                context=context,
                request=payload,
                now=now,
            )
            if not isinstance(authorization, _AuthorizedRecallContext):
                raise TypeError
            if type(identity_authorized) is not bool:
                raise TypeError
            request_id = self._new_uuid()
            if not isinstance(request_id, UUID):
                raise TypeError
        except Exception:
            raise _ClientGatewayUnavailable(
                "server authorization failed closed"
            ) from None

        arguments = {"query": payload.query, "top_k": payload.top_k}
        expected = authorization.expected_public_context
        action = _GatewayAction(
            request_id=request_id,
            session_id=authorization.session_id,
            intent_id=authorization.intent_id,
            agent_id=expected.agent_id,
            actor_id=expected.actor_id,
            evaluated_at=now,
            action_arguments_sha256=_hash_action_arguments(arguments),
            original_intent_sha256=authorization.original_intent_sha256,
            prior_action_context_sha256=_prior_receipt_context_sha256(
                authorization.prior_receipt_ids
            ),
            policy=authorization.policy_action(),
        )
        return self._gateway.execute(
            action=action,
            action_arguments=arguments,
            facts=authorization.policy_facts(
                now=now,
                identity_authorized=identity_authorized,
            ),
        )
