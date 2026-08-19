from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gluevenir._receipts import (
    _canonical_json_bytes,
    _canonical_receipt_bytes,
    _ReceiptPayload,
    _ReceiptSigner,
    _ReceiptVerifier,
    _SignedReceipt,
)

RECEIPT_ID = UUID("40000000-0000-4000-8000-000000000001")
REQUEST_ID = UUID("41000000-0000-4000-8000-000000000001")
SESSION_ID = UUID("42000000-0000-4000-8000-000000000001")
INTENT_ID = UUID("43000000-0000-4000-8000-000000000001")
TENANT_ID = UUID("10000000-0000-4000-8000-000000000001")
PROGRAM_ID = UUID("20000000-0000-4000-8000-000000000001")
MEMORY_ID = UUID("30000000-0000-4000-8000-000000000001")
OTHER_MEMORY_ID = UUID("30000000-0000-4000-8000-000000000002")
APPROVAL_ID = UUID("31000000-0000-4000-8000-000000000001")
AGENT_ID = "gluevenir-bio"
KEY_ID = "agent-key-2026-08"
CREATED_AT = datetime(2026, 8, 15, 18, 30, 45, 123456, tzinfo=UTC)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _payload(**changes: object) -> _ReceiptPayload:
    values: dict[str, object] = {
        "receipt_id": RECEIPT_ID,
        "request_id": REQUEST_ID,
        "session_id": SESSION_ID,
        "intent_id": INTENT_ID,
        "tenant_id": TENANT_ID,
        "program_id": PROGRAM_ID,
        "operation": "RECALL",
        "action_arguments_sha256": _digest("typed action envelope"),
        "decision": "ALLOW",
        "created_at": CREATED_AT,
        "policy_version": "bio-demo-v1",
        "policy_sha256": _digest("policy"),
        "prior_action_context_sha256": _digest("bounded prior context"),
        "app_version": "0.1.0",
        "app_sha256": _digest("application"),
        "agent_id": AGENT_ID,
        "agent_signing_key_id": KEY_ID,
        "actor_id": "demo-internal-lead",
        "actor_role": "program_lead",
        "purpose": "program_status",
        "audience": "internal-program-lead",
        "destination": "internal",
        "original_intent_sha256": _digest("original intent"),
        "outcome": "EXECUTED",
        "response_status": "completed",
        "reason_code": "AUTHORIZED_SCOPED_RECALL",
        "candidate_count": 3,
        "included_count": 1,
        "exclusion_counts": (("AUDIENCE_SCOPE", 1), ("ROOM_SCOPE", 1)),
        "included_memory_ids": (MEMORY_ID,),
        "included_content_sha256": (_digest("included synthetic content"),),
        "model_prompt_sha256": _digest("exact dynamic model context"),
    }
    values.update(changes)
    return _ReceiptPayload(**values)


def _signer(seed: int = 1, *, agent_id: str = AGENT_ID, key_id: str = KEY_ID):
    private_key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    return _ReceiptSigner(
        agent_id=agent_id,
        key_id=key_id,
        private_key=private_key,
    )


def _verifier(
    signer: _ReceiptSigner, *, agent_id: str = AGENT_ID, key_id: str = KEY_ID
):
    return _ReceiptVerifier.from_public_key_bytes(
        agent_id=agent_id,
        key_id=key_id,
        public_key=signer.public_key_bytes(),
    )


def _raw_token(value: object) -> str:
    raw = _canonical_json_bytes(value)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _tamper_with_valid_hash(
    receipt: _SignedReceipt, payload: _ReceiptPayload
) -> _SignedReceipt:
    canonical = _canonical_receipt_bytes(payload)
    return _SignedReceipt(
        payload=payload,
        canonical_receipt_sha256=hashlib.sha256(canonical).hexdigest(),
        signature=receipt.signature,
    )


def test_sign_verify_round_trip_is_stable_and_offline() -> None:
    signer = _signer()
    verifier = _verifier(signer)

    receipt = signer.sign(_payload())
    token = receipt.to_token()
    decoded = _SignedReceipt.from_token(token)

    assert decoded == receipt
    assert decoded.to_token() == token
    assert verifier.verify(receipt)
    assert verifier.verify_token(token)
    assert (
        receipt.canonical_receipt_sha256
        == hashlib.sha256(_canonical_receipt_bytes(receipt.payload)).hexdigest()
    )


def test_canonical_bytes_are_deterministic_utf8_sorted_and_compact() -> None:
    first = _canonical_receipt_bytes(_payload())
    second = _canonical_receipt_bytes(_payload())

    assert first == second
    assert first.decode("utf-8").startswith('{"action_arguments_sha256":')
    assert b" " not in first
    assert b"\n" not in first
    assert hashlib.sha256(first).hexdigest() == (
        "a3eac67467e7f71f76cdde1d6233ef42a80a8cc6d36a60ae328242686a7b9fab"
    )


def test_payload_and_signed_receipt_are_immutable_and_views_are_detached() -> None:
    receipt = _signer().sign(_payload())

    with pytest.raises(FrozenInstanceError):
        receipt.payload.decision = "DENY"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        receipt.signature = bytes(64)  # type: ignore[misc]

    view = receipt.public_view()
    view["decision"] = "DENY"
    assert isinstance(view["included_memory_ids"], list)
    view["included_memory_ids"].append(str(OTHER_MEMORY_ID))
    assert isinstance(view["exclusion_counts"], dict)
    view["exclusion_counts"]["OTHER"] = 99

    fresh_view = receipt.public_view()
    assert fresh_view["decision"] == "ALLOW"
    assert fresh_view["included_memory_ids"] == [str(MEMORY_ID)]
    assert "OTHER" not in fresh_view["exclusion_counts"]


def test_public_view_and_canonical_payload_are_content_safe() -> None:
    receipt = _signer().sign(_payload())
    forbidden = (
        "RAW QUERY SENTINEL",
        "RAW PROMPT SENTINEL",
        "RAW ANSWER SENTINEL",
        "RESTRICTED CONTENT SENTINEL",
        str(OTHER_MEMORY_ID),
    )
    rendered = json.dumps(receipt.public_view(), sort_keys=True)
    canonical = _canonical_receipt_bytes(receipt.payload).decode("utf-8")

    for value in forbidden:
        assert value not in rendered
        assert value not in canonical
    assert receipt.public_view()["included_memory_ids"] == [str(MEMORY_ID)]
    assert receipt.public_view()["exclusion_counts"] == {
        "AUDIENCE_SCOPE": 1,
        "ROOM_SCOPE": 1,
    }
    forbidden_keys = {
        "raw_query",
        "model_prompt",
        "answer",
        "content",
        "excluded_memory_ids",
    }
    assert forbidden_keys.isdisjoint(receipt.public_view())
    with pytest.raises(TypeError):
        _ReceiptPayload(
            **asdict(_payload()),
            raw_query="forbidden",  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("decision", "DENY"),
        ("action_arguments_sha256", _digest("mutated action")),
        ("agent_id", "other-agent"),
        ("agent_signing_key_id", "other-key"),
        ("actor_id", "other-actor"),
        ("actor_role", "external_partner"),
        ("purpose", "partner_status"),
        ("audience", "partner-alpha-synthetic"),
        ("destination", "external"),
        ("original_intent_sha256", _digest("mutated intent")),
        ("created_at", CREATED_AT + timedelta(seconds=1)),
        ("policy_sha256", _digest("mutated policy")),
        ("prior_action_context_sha256", _digest("mutated context")),
        ("outcome", "NOT_EXECUTED"),
        ("app_sha256", _digest("mutated app")),
        ("reason_code", "DIFFERENT_REASON"),
    ],
)
def test_every_security_relevant_signed_field_mutation_fails_verification(
    field: str, replacement: object
) -> None:
    signer = _signer()
    verifier = _verifier(signer)
    receipt = signer.sign(_payload())
    mutated_payload = replace(receipt.payload, **{field: replacement})
    tampered = _tamper_with_valid_hash(receipt, mutated_payload)

    assert not verifier.verify(tampered)


def test_mutating_included_id_or_content_hash_fails_verification() -> None:
    signer = _signer()
    verifier = _verifier(signer)
    receipt = signer.sign(_payload())

    changed_id = replace(receipt.payload, included_memory_ids=(OTHER_MEMORY_ID,))
    changed_hash = replace(
        receipt.payload,
        included_content_sha256=(_digest("changed included content"),),
    )

    assert not verifier.verify(_tamper_with_valid_hash(receipt, changed_id))
    assert not verifier.verify(_tamper_with_valid_hash(receipt, changed_hash))


def test_mutating_approval_resolution_id_fails_verification() -> None:
    signer = _signer()
    verifier = _verifier(signer)
    receipt = signer.sign(
        _payload(
            decision="MODIFY",
            approval_resolution_id=APPROVAL_ID,
            resolution_actor_id="human-reviewer-synthetic-01",
            resolution_actor_role="human_reviewer",
        )
    )
    changed_approval = replace(
        receipt.payload,
        approval_resolution_id=UUID("31000000-0000-4000-8000-000000000002"),
    )
    changed_reviewer = replace(
        receipt.payload,
        resolution_actor_id="other-human-reviewer",
    )
    changed_reviewer_role = replace(
        receipt.payload,
        resolution_actor_role="program_lead",
    )

    assert not verifier.verify(_tamper_with_valid_hash(receipt, changed_approval))
    assert not verifier.verify(_tamper_with_valid_hash(receipt, changed_reviewer))
    assert not verifier.verify(_tamper_with_valid_hash(receipt, changed_reviewer_role))


def test_two_agent_keys_and_identity_metadata_are_separated() -> None:
    first_signer = _signer(1)
    second_signer = _signer(2, agent_id="other-agent", key_id="other-key")
    first_verifier = _verifier(first_signer)
    second_verifier = _verifier(
        second_signer,
        agent_id="other-agent",
        key_id="other-key",
    )
    first = first_signer.sign(_payload())
    second = second_signer.sign(
        _payload(agent_id="other-agent", agent_signing_key_id="other-key")
    )

    assert first_verifier.verify(first)
    assert second_verifier.verify(second)
    assert not first_verifier.verify(second)
    assert not second_verifier.verify(first)
    assert not _verifier(first_signer, agent_id="wrong-agent").verify(first)
    assert not _verifier(first_signer, key_id="wrong-key").verify(first)
    with pytest.raises(ValueError, match="does not match"):
        first_signer.sign(_payload(agent_id="wrong-agent"))


def test_changed_signature_and_stale_hash_fail_closed() -> None:
    signer = _signer()
    verifier = _verifier(signer)
    receipt = signer.sign(_payload())
    changed_signature = bytes([receipt.signature[0] ^ 1]) + receipt.signature[1:]
    invalid_signature = _SignedReceipt(
        receipt.payload,
        receipt.canonical_receipt_sha256,
        changed_signature,
    )

    assert not verifier.verify(invalid_signature)
    assert not verifier.verify(object())
    with pytest.raises(ValueError, match="does not match"):
        _SignedReceipt(receipt.payload, _digest("stale"), receipt.signature)


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"decision": "allow"}, ValueError),
        ({"decision": "ALLOW,DENY"}, ValueError),
        ({"operation": "QUERY"}, ValueError),
        ({"response_status": "success"}, ValueError),
        ({"candidate_count": True}, TypeError),
        ({"included_count": True}, TypeError),
        ({"created_at": datetime(2026, 8, 15)}, ValueError),
        ({"action_arguments_sha256": "A" * 64}, ValueError),
        ({"schema_version": "v2"}, ValueError),
        ({"exclusion_counts": {"ROOM_SCOPE": 2}}, TypeError),
        (
            {"exclusion_counts": (("ROOM_SCOPE", 1), ("AUDIENCE_SCOPE", 1))},
            ValueError,
        ),
        ({"exclusion_counts": (("ROOM_SCOPE", 0),)}, ValueError),
        ({"included_memory_ids": [MEMORY_ID]}, TypeError),
        ({"included_content_sha256": [_digest("included")]}, TypeError),
        ({"included_memory_ids": (MEMORY_ID, MEMORY_ID)}, ValueError),
        ({"candidate_count": 4}, ValueError),
        ({"included_count": 2}, ValueError),
        ({"resolution_of_receipt_id": RECEIPT_ID}, ValueError),
    ],
)
def test_payload_rejects_invalid_or_ambiguous_values(
    changes: dict[str, object], error: type[Exception]
) -> None:
    with pytest.raises(error):
        _payload(**changes)


def test_decoder_rejects_malformed_noncanonical_or_ambiguous_encodings() -> None:
    receipt = _signer().sign(_payload())
    view = receipt.public_view()

    assert not _verifier(_signer()).verify_token(receipt.to_token() + "=")
    with pytest.raises(ValueError):
        _SignedReceipt.from_token(receipt.to_token() + "=")
    with pytest.raises(ValueError):
        _SignedReceipt.from_token("abc+")
    with pytest.raises(ValueError, match="duplicate"):
        duplicate = b'{"x":1,"x":2}'
        _SignedReceipt.from_token(
            base64.urlsafe_b64encode(duplicate).rstrip(b"=").decode("ascii")
        )
    with pytest.raises(ValueError, match="non-integer"):
        nan = b'{"x":NaN}'
        _SignedReceipt.from_token(
            base64.urlsafe_b64encode(nan).rstrip(b"=").decode("ascii")
        )
    with pytest.raises(ValueError, match="non-integer"):
        floating = b'{"x":1.5}'
        _SignedReceipt.from_token(
            base64.urlsafe_b64encode(floating).rstrip(b"=").decode("ascii")
        )
    with pytest.raises(ValueError, match="valid Unicode"):
        surrogate = b'{"x":"\\ud800"}'
        _SignedReceipt.from_token(
            base64.urlsafe_b64encode(surrogate).rstrip(b"=").decode("ascii")
        )
    with pytest.raises(ValueError, match="not canonical"):
        spaced = json.dumps(view, sort_keys=True).encode("utf-8")
        _SignedReceipt.from_token(
            base64.urlsafe_b64encode(spaced).rstrip(b"=").decode("ascii")
        )

    ambiguous = dict(view)
    ambiguous["candidate_count"] = True
    with pytest.raises(TypeError):
        _SignedReceipt.from_token(_raw_token(ambiguous))


def test_decoder_rejects_unknown_fields_wrong_algorithm_and_bad_signature() -> None:
    receipt = _signer().sign(_payload())
    view = receipt.public_view()

    extra = dict(view)
    extra["raw_query"] = "must never be accepted"
    with pytest.raises(ValueError, match="fields"):
        _SignedReceipt.from_token(_raw_token(extra))

    wrong_algorithm = dict(view)
    wrong_algorithm["signature_algorithm"] = "none"
    with pytest.raises(ValueError, match="algorithm"):
        _SignedReceipt.from_token(_raw_token(wrong_algorithm))

    bad_signature = dict(view)
    bad_signature["signature"] = "AA"
    with pytest.raises(ValueError, match="64 bytes"):
        _SignedReceipt.from_token(_raw_token(bad_signature))


def test_signer_exposes_only_public_key_and_requires_injected_ed25519_key() -> None:
    signer = _signer()

    assert len(signer.public_key_bytes()) == 32
    assert "private" not in repr(signer).casefold()
    with pytest.raises(TypeError):
        _ReceiptSigner(
            agent_id=AGENT_ID,
            key_id=KEY_ID,
            private_key=bytes(32),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        _ReceiptVerifier.from_public_key_bytes(
            agent_id=AGENT_ID,
            key_id=KEY_ID,
            public_key=bytes(31),
        )
