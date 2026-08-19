"""Private canonical Ed25519 Recall Receipt primitives.

The signed payload contains only bounded identifiers, counts, and hashes.  Private
key material is injected by the runtime and is never generated or serialized here.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_SCHEMA_VERSION = "gluevenir.recall-receipt.v2"
_SIGNATURE_ALGORITHM = "Ed25519"
_DECISIONS = frozenset({"ALLOW", "DENY", "MODIFY", "STEP_UP", "DEFER"})
_OPERATIONS = frozenset({"REMEMBER", "RECALL", "USE", "SHARE", "REVOKE", "FORGET"})
_RESPONSE_STATUSES = frozenset({"pending", "completed", "denied", "failed"})
_DESTINATIONS = frozenset({"internal", "external"})
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_MAX_CANDIDATES = 10_000
_MAX_INCLUDED = 5
_MAX_EXCLUSION_REASONS = 16
_MAX_TOKEN_CHARACTERS = 65_536


def _identifier(name: str, value: object) -> str:
    if type(value) is not str or not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _hash(name: str, value: object) -> str:
    if type(value) is not str or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _uuid(name: str, value: object) -> UUID:
    if type(value) is not UUID:
        raise TypeError(f"{name} must be a UUID")
    return value


def _timestamp(value: datetime) -> str:
    if type(value) is not datetime or value.utcoffset() != timedelta(0):
        raise ValueError("created_at must be a timezone-aware UTC datetime")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_timestamp(value: object) -> datetime:
    if type(value) is not str or not _TIMESTAMP_RE.fullmatch(value):
        raise ValueError("created_at must use the canonical UTC timestamp format")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise ValueError("created_at is not a valid UTC timestamp") from error


def _parse_uuid(name: str, value: object) -> UUID:
    if type(value) is not str:
        raise TypeError(f"{name} must be a UUID string")
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a canonical UUID") from error
    if str(parsed) != value:
        raise ValueError(f"{name} must be a canonical UUID")
    return parsed


def _count(name: str, value: object, *, maximum: int) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= maximum:
        raise ValueError(f"{name} is outside its allowed range")
    return value


@dataclass(frozen=True, slots=True)
class _ReceiptPayload:
    """Immutable, content-safe fields covered by one receipt signature."""

    receipt_id: UUID
    request_id: UUID
    session_id: UUID
    intent_id: UUID
    tenant_id: UUID
    program_id: UUID
    operation: str
    action_arguments_sha256: str
    decision: str
    created_at: datetime
    policy_version: str
    policy_sha256: str
    prior_action_context_sha256: str
    app_version: str
    app_sha256: str
    agent_id: str
    agent_signing_key_id: str
    actor_id: str
    actor_role: str
    purpose: str
    audience: str
    destination: str
    original_intent_sha256: str
    outcome: str
    response_status: str
    reason_code: str
    candidate_count: int
    included_count: int
    exclusion_counts: tuple[tuple[str, int], ...]
    included_memory_ids: tuple[UUID, ...]
    included_content_sha256: tuple[str, ...]
    model_prompt_sha256: str | None = None
    resolution_of_receipt_id: UUID | None = None
    approval_resolution_id: UUID | None = None
    resolution_actor_id: str | None = None
    resolution_actor_role: str | None = None
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in (
            "receipt_id",
            "request_id",
            "session_id",
            "intent_id",
            "tenant_id",
            "program_id",
        ):
            _uuid(name, getattr(self, name))
        if self.resolution_of_receipt_id is not None:
            _uuid("resolution_of_receipt_id", self.resolution_of_receipt_id)
            if self.resolution_of_receipt_id == self.receipt_id:
                raise ValueError("a receipt cannot resolve itself")
        if self.approval_resolution_id is not None:
            _uuid("approval_resolution_id", self.approval_resolution_id)
            if self.decision != "MODIFY":
                raise ValueError("only MODIFY can bind an approval resolution")
        if self.decision == "MODIFY" and self.approval_resolution_id is None:
            raise ValueError("MODIFY receipts require an approval resolution ID")
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

        operation = _identifier("operation", self.operation)
        if operation not in _OPERATIONS:
            raise ValueError("operation is unsupported")
        decision = _identifier("decision", self.decision)
        if decision not in _DECISIONS:
            raise ValueError("decision must be exactly one supported decision")
        status = _identifier("response_status", self.response_status)
        if status not in _RESPONSE_STATUSES:
            raise ValueError("response_status is unsupported")
        destination = _identifier("destination", self.destination)
        if destination not in _DESTINATIONS:
            raise ValueError("destination is unsupported")

        _hash("action_arguments_sha256", self.action_arguments_sha256)
        _timestamp(self.created_at)
        for name in (
            "policy_version",
            "app_version",
            "agent_id",
            "agent_signing_key_id",
            "actor_id",
            "actor_role",
            "purpose",
            "audience",
            "outcome",
            "reason_code",
        ):
            _identifier(name, getattr(self, name))
        for name in (
            "policy_sha256",
            "prior_action_context_sha256",
            "app_sha256",
            "original_intent_sha256",
        ):
            _hash(name, getattr(self, name))
        if self.model_prompt_sha256 is not None:
            _hash("model_prompt_sha256", self.model_prompt_sha256)
            if self.response_status == "denied":
                raise ValueError("denied receipts cannot bind a model prompt")
        if self.schema_version != _SCHEMA_VERSION:
            raise ValueError("schema_version is unsupported")

        _count("candidate_count", self.candidate_count, maximum=_MAX_CANDIDATES)
        _count("included_count", self.included_count, maximum=_MAX_INCLUDED)
        if type(self.exclusion_counts) is not tuple:
            raise TypeError("exclusion_counts must be a tuple")
        if len(self.exclusion_counts) > _MAX_EXCLUSION_REASONS:
            raise ValueError("too many exclusion reasons")
        normalized_exclusions: list[tuple[str, int]] = []
        for entry in self.exclusion_counts:
            if type(entry) is not tuple or len(entry) != 2:
                raise TypeError("each exclusion count must be a two-item tuple")
            reason = _identifier("exclusion reason", entry[0])
            count = _count("exclusion count", entry[1], maximum=_MAX_CANDIDATES)
            if count == 0:
                raise ValueError("zero exclusion counts must be omitted")
            normalized_exclusions.append((reason, count))
        if normalized_exclusions != sorted(normalized_exclusions):
            raise ValueError("exclusion_counts must be sorted by reason code")
        if len({reason for reason, _ in normalized_exclusions}) != len(
            normalized_exclusions
        ):
            raise ValueError("exclusion reason codes must be unique")

        if type(self.included_memory_ids) is not tuple:
            raise TypeError("included_memory_ids must be a tuple")
        if type(self.included_content_sha256) is not tuple:
            raise TypeError("included_content_sha256 must be a tuple")
        for memory_id in self.included_memory_ids:
            _uuid("included memory ID", memory_id)
        for content_hash in self.included_content_sha256:
            _hash("included content hash", content_hash)
        if len(set(self.included_memory_ids)) != len(self.included_memory_ids):
            raise ValueError("included memory IDs must be unique")
        if not (
            len(self.included_memory_ids)
            == len(self.included_content_sha256)
            == self.included_count
        ):
            raise ValueError("included IDs, hashes, and included_count must agree")
        excluded_count = sum(count for _, count in normalized_exclusions)
        if self.candidate_count != self.included_count + excluded_count:
            raise ValueError("candidate_count must equal included plus excluded counts")

    def _as_primitive(self) -> dict[str, object]:
        return {
            "action_arguments_sha256": self.action_arguments_sha256,
            "approval_resolution_id": (
                str(self.approval_resolution_id)
                if self.approval_resolution_id is not None
                else None
            ),
            "agent_id": self.agent_id,
            "agent_signing_key_id": self.agent_signing_key_id,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "audience": self.audience,
            "app_sha256": self.app_sha256,
            "app_version": self.app_version,
            "candidate_count": self.candidate_count,
            "created_at": _timestamp(self.created_at),
            "decision": self.decision,
            "exclusion_counts": dict(self.exclusion_counts),
            "included_content_sha256": list(self.included_content_sha256),
            "included_count": self.included_count,
            "included_memory_ids": [str(value) for value in self.included_memory_ids],
            "model_prompt_sha256": self.model_prompt_sha256,
            "intent_id": str(self.intent_id),
            "operation": self.operation,
            "original_intent_sha256": self.original_intent_sha256,
            "outcome": self.outcome,
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "prior_action_context_sha256": self.prior_action_context_sha256,
            "program_id": str(self.program_id),
            "purpose": self.purpose,
            "reason_code": self.reason_code,
            "receipt_id": str(self.receipt_id),
            "request_id": str(self.request_id),
            "resolution_actor_id": self.resolution_actor_id,
            "resolution_actor_role": self.resolution_actor_role,
            "resolution_of_receipt_id": (
                str(self.resolution_of_receipt_id)
                if self.resolution_of_receipt_id is not None
                else None
            ),
            "response_status": self.response_status,
            "schema_version": self.schema_version,
            "session_id": str(self.session_id),
            "tenant_id": str(self.tenant_id),
            "destination": self.destination,
        }

    @classmethod
    def _from_primitive(cls, value: object) -> _ReceiptPayload:
        if type(value) is not dict:
            raise TypeError("receipt payload must be an object")
        expected = set(cls.__dataclass_fields__)
        if set(value) != expected:
            raise ValueError("receipt payload fields do not match the schema")
        ids = {
            name: _parse_uuid(name, value[name])
            for name in (
                "receipt_id",
                "request_id",
                "session_id",
                "intent_id",
                "tenant_id",
                "program_id",
            )
        }
        resolution_value = value["resolution_of_receipt_id"]
        resolution_id = (
            None
            if resolution_value is None
            else _parse_uuid("resolution_of_receipt_id", resolution_value)
        )
        approval_value = value["approval_resolution_id"]
        approval_id = (
            None
            if approval_value is None
            else _parse_uuid("approval_resolution_id", approval_value)
        )
        exclusions = value["exclusion_counts"]
        if type(exclusions) is not dict:
            raise TypeError("exclusion_counts must be an object")
        memory_ids = value["included_memory_ids"]
        content_hashes = value["included_content_sha256"]
        if type(memory_ids) is not list or type(content_hashes) is not list:
            raise TypeError("included IDs and hashes must be arrays")
        return cls(
            **ids,
            operation=value["operation"],
            action_arguments_sha256=value["action_arguments_sha256"],
            decision=value["decision"],
            created_at=_parse_timestamp(value["created_at"]),
            policy_version=value["policy_version"],
            policy_sha256=value["policy_sha256"],
            prior_action_context_sha256=value["prior_action_context_sha256"],
            app_version=value["app_version"],
            app_sha256=value["app_sha256"],
            agent_id=value["agent_id"],
            agent_signing_key_id=value["agent_signing_key_id"],
            actor_id=value["actor_id"],
            actor_role=value["actor_role"],
            purpose=value["purpose"],
            audience=value["audience"],
            destination=value["destination"],
            original_intent_sha256=value["original_intent_sha256"],
            outcome=value["outcome"],
            response_status=value["response_status"],
            reason_code=value["reason_code"],
            candidate_count=value["candidate_count"],
            included_count=value["included_count"],
            exclusion_counts=tuple(exclusions.items()),
            included_memory_ids=tuple(
                _parse_uuid("included memory ID", item) for item in memory_ids
            ),
            included_content_sha256=tuple(content_hashes),
            model_prompt_sha256=value["model_prompt_sha256"],
            resolution_of_receipt_id=resolution_id,
            approval_resolution_id=approval_id,
            resolution_actor_id=value["resolution_actor_id"],
            resolution_actor_role=value["resolution_actor_role"],
            schema_version=value["schema_version"],
        )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON objects must not contain duplicate keys")
        result[key] = value
    return result


def _reject_non_integer_number(value: str) -> None:
    raise ValueError(f"non-integer JSON number is forbidden: {value}")


def _strict_json(raw: bytes) -> object:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("receipt JSON must be UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_non_integer_number,
            parse_constant=_reject_non_integer_number,
        )
    except json.JSONDecodeError as error:
        raise ValueError("receipt JSON is malformed") from error
    if _canonical_json_bytes(value) != raw:
        raise ValueError("receipt JSON is not canonical")
    return value


def _validate_json_value(value: object) -> None:
    if value is None or type(value) in {int, bool}:
        return
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("JSON strings must contain valid Unicode") from error
        return
    if type(value) is list:
        for item in value:
            _validate_json_value(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("JSON object keys must be strings")
            _validate_json_value(item)
        return
    raise TypeError("canonical JSON supports only unambiguous JSON value types")


def _canonical_json_bytes(value: object) -> bytes:
    _validate_json_value(value)
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_receipt_bytes(payload: _ReceiptPayload) -> bytes:
    if type(payload) is not _ReceiptPayload:
        raise TypeError("payload must be a _ReceiptPayload")
    return _canonical_json_bytes(payload._as_primitive())


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(name: str, value: object) -> bytes:
    if type(value) is not str or not value or not _BASE64URL_RE.fullmatch(value):
        raise ValueError(f"{name} must be unpadded URL-safe base64")
    if len(value) % 4 == 1:
        raise ValueError(f"{name} has an invalid base64 length")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"{name} is not valid URL-safe base64") from error
    if _base64url_encode(decoded) != value:
        raise ValueError(f"{name} is not canonically encoded")
    return decoded


@dataclass(frozen=True, slots=True)
class _SignedReceipt:
    """A canonical payload, its SHA-256 digest, and its Ed25519 signature."""

    payload: _ReceiptPayload
    canonical_receipt_sha256: str
    signature: bytes

    def __post_init__(self) -> None:
        if type(self.payload) is not _ReceiptPayload:
            raise TypeError("payload must be a _ReceiptPayload")
        _hash("canonical_receipt_sha256", self.canonical_receipt_sha256)
        expected = hashlib.sha256(_canonical_receipt_bytes(self.payload)).hexdigest()
        if self.canonical_receipt_sha256 != expected:
            raise ValueError("canonical receipt hash does not match the payload")
        if type(self.signature) is not bytes or len(self.signature) != 64:
            raise ValueError("signature must be exactly 64 bytes")

    def public_view(self) -> dict[str, object]:
        """Return a detached, content-safe JSON view with no excluded IDs."""

        return {
            **self.payload._as_primitive(),
            "canonical_receipt_sha256": self.canonical_receipt_sha256,
            "signature": _base64url_encode(self.signature),
            "signature_algorithm": _SIGNATURE_ALGORITHM,
        }

    def to_token(self) -> str:
        """Encode the public view as stable, unpadded URL-safe base64."""

        return _base64url_encode(_canonical_json_bytes(self.public_view()))

    @classmethod
    def from_token(cls, token: object) -> _SignedReceipt:
        """Strictly decode a canonical token; signature verification is separate."""

        if type(token) is not str or len(token) > _MAX_TOKEN_CHARACTERS:
            raise ValueError("receipt token must be a bounded string")
        value = _strict_json(_base64url_decode("receipt token", token))
        if type(value) is not dict:
            raise TypeError("receipt token must contain an object")
        metadata = {
            "canonical_receipt_sha256",
            "signature",
            "signature_algorithm",
        }
        payload_fields = set(_ReceiptPayload.__dataclass_fields__)
        if set(value) != payload_fields | metadata:
            raise ValueError("receipt token fields do not match the schema")
        if value["signature_algorithm"] != _SIGNATURE_ALGORITHM:
            raise ValueError("signature algorithm is unsupported")
        payload = _ReceiptPayload._from_primitive(
            {key: item for key, item in value.items() if key in payload_fields}
        )
        signature = _base64url_decode("signature", value["signature"])
        return cls(payload, value["canonical_receipt_sha256"], signature)


class _ReceiptSigner:
    """Sign receipts with injected per-agent Ed25519 private key material."""

    __slots__ = ("__agent_id", "__key_id", "__private_key")

    def __init__(
        self,
        *,
        agent_id: str,
        key_id: str,
        private_key: Ed25519PrivateKey,
    ) -> None:
        self.__agent_id = _identifier("agent_id", agent_id)
        self.__key_id = _identifier("key_id", key_id)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        self.__private_key = private_key

    def sign(self, payload: _ReceiptPayload) -> _SignedReceipt:
        """Bind a validated payload to this configured agent/key identity."""

        if type(payload) is not _ReceiptPayload:
            raise TypeError("payload must be a _ReceiptPayload")
        if (
            payload.agent_id != self.__agent_id
            or payload.agent_signing_key_id != self.__key_id
        ):
            raise ValueError("payload agent/key identity does not match the signer")
        canonical = _canonical_receipt_bytes(payload)
        return _SignedReceipt(
            payload=payload,
            canonical_receipt_sha256=hashlib.sha256(canonical).hexdigest(),
            signature=self.__private_key.sign(canonical),
        )

    def public_key_bytes(self) -> bytes:
        """Return only the raw public verification key."""

        return self.__private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


class _ReceiptVerifier:
    """Offline verifier bound to exactly one expected agent and key ID."""

    __slots__ = ("__agent_id", "__key_id", "__public_key")

    def __init__(
        self,
        *,
        agent_id: str,
        key_id: str,
        public_key: Ed25519PublicKey,
    ) -> None:
        self.__agent_id = _identifier("agent_id", agent_id)
        self.__key_id = _identifier("key_id", key_id)
        if not isinstance(public_key, Ed25519PublicKey):
            raise TypeError("public_key must be an Ed25519PublicKey")
        self.__public_key = public_key

    @classmethod
    def from_public_key_bytes(
        cls,
        *,
        agent_id: str,
        key_id: str,
        public_key: bytes,
    ) -> _ReceiptVerifier:
        """Build an offline verifier from the published 32-byte public key."""

        if type(public_key) is not bytes or len(public_key) != 32:
            raise ValueError("public_key must be exactly 32 bytes")
        return cls(
            agent_id=agent_id,
            key_id=key_id,
            public_key=Ed25519PublicKey.from_public_bytes(public_key),
        )

    def verify(self, receipt: object) -> bool:
        """Fail closed on wrong identity, digest, type, or signature."""

        if type(receipt) is not _SignedReceipt:
            return False
        if (
            receipt.payload.agent_id != self.__agent_id
            or receipt.payload.agent_signing_key_id != self.__key_id
        ):
            return False
        canonical = _canonical_receipt_bytes(receipt.payload)
        if not hmac.compare_digest(
            hashlib.sha256(canonical).hexdigest(),
            receipt.canonical_receipt_sha256,
        ):
            return False
        try:
            self.__public_key.verify(receipt.signature, canonical)
        except (InvalidSignature, ValueError):
            return False
        return True

    def verify_token(self, token: object) -> bool:
        """Decode and verify a token without raising on attacker-controlled input."""

        try:
            receipt = _SignedReceipt.from_token(token)
        except (TypeError, ValueError):
            return False
        return self.verify(receipt)
