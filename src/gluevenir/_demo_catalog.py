"""Server-owned personas and business journeys for the synthetic public demo."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_DECISIONS = frozenset({"ALLOW", "MODIFY", "STEP_UP", "DEFER", "DENY"})


class _DemoPersona(StrEnum):
    PROGRAM_LEAD = "program_lead"
    FORMULATION_SCIENTIST = "formulation_scientist"
    CLINICAL_OPERATIONS_LEAD = "clinical_operations_lead"
    EXTERNAL_PARTNER = "authorized_external_partner"


class _DemoJourney(StrEnum):
    PROGRAM_STATUS = "program-current-status"
    PARTNER_READY_SUMMARY = "program-partner-brief"
    PENDING_MILESTONE = "program-pending-milestone"
    AMBIGUOUS_DISTRIBUTION = "program-ambiguous-update"
    OTHER_ORGANIZATION = "program-other-organization"

    STABILITY_OBSERVATIONS = "formulation-stability-observations"
    EXTERNAL_FORMULATION = "formulation-external-explanation"
    PENDING_B9_INTERPRETATION = "formulation-pending-b9"
    UNSPECIFIED_RESULTS = "formulation-unspecified-results"
    RESTRICTED_ASSAY_DETAIL = "formulation-unapproved-share"

    COHORT_CHANGES = "clinical-cohort-changes"
    PARTNER_COHORT_UPDATE = "clinical-partner-cohort-update"
    PENDING_SAFETY_REVIEW = "clinical-pending-safety-summary"
    UNSCOPED_ENROLLMENT = "clinical-unscoped-enrollment-update"
    PARTICIPANT_CONTACTS = "clinical-participant-contact-request"

    APPROVED_OVERVIEW = "partner-approved-overview"
    STABILITY_FORMULATION_UPDATE = "partner-stability-update"
    PENDING_PRESS_STATEMENT = "partner-pending-press-statement"
    UNSPECIFIED_FORWARDING = "partner-unspecified-forward"
    OTHER_TENANT = "partner-other-tenant"


@dataclass(frozen=True, slots=True)
class _DemoJourneyDefinition:
    persona: _DemoPersona
    journey: _DemoJourney
    label: str
    example_prompt: str
    expected_decision: str

    def __post_init__(self) -> None:
        if not isinstance(self.persona, _DemoPersona):
            raise TypeError("persona must be a _DemoPersona")
        if not isinstance(self.journey, _DemoJourney):
            raise TypeError("journey must be a _DemoJourney")
        for name in ("label", "example_prompt"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > 280:
                raise ValueError(f"{name} must be bounded text")
        if self.expected_decision not in _DECISIONS:
            raise ValueError("expected_decision is invalid")


def _definition(
    persona: _DemoPersona,
    journey: _DemoJourney,
    label: str,
    prompt: str,
    decision: str,
) -> _DemoJourneyDefinition:
    return _DemoJourneyDefinition(persona, journey, label, prompt, decision)


_JOURNEYS = {
    _DemoJourney.PROGRAM_STATUS: _definition(
        _DemoPersona.PROGRAM_LEAD,
        _DemoJourney.PROGRAM_STATUS,
        "Prepare the August 17 program review",
        "What changed in HX-17 since the August 1 checkpoint, and what should I "
        "put on the August 17 leadership agenda?",
        "ALLOW",
    ),
    _DemoJourney.PARTNER_READY_SUMMARY: _definition(
        _DemoPersona.PROGRAM_LEAD,
        _DemoJourney.PARTNER_READY_SUMMARY,
        "Send Argent Bridge the weekly brief",
        "Prepare the August 15 partner brief for Camille with the latest HX17-F3 "
        "stability status and schedule impact.",
        "MODIFY",
    ),
    _DemoJourney.PENDING_MILESTONE: _definition(
        _DemoPersona.PROGRAM_LEAD,
        _DemoJourney.PENDING_MILESTONE,
        "Announce the cohort-expansion decision",
        "Use the new 36-participant target in tomorrow's Argent Bridge milestone "
        "announcement.",
        "STEP_UP",
    ),
    _DemoJourney.AMBIGUOUS_DISTRIBUTION: _definition(
        _DemoPersona.PROGRAM_LEAD,
        _DemoJourney.AMBIGUOUS_DISTRIBUTION,
        "Summarize HX-17 for tomorrow",
        "Give me the latest HX-17 summary for tomorrow.",
        "DEFER",
    ),
    _DemoJourney.OTHER_ORGANIZATION: _definition(
        _DemoPersona.PROGRAM_LEAD,
        _DemoJourney.OTHER_ORGANIZATION,
        "Compare another organization's program",
        "Compare our HX-17 status with VectorVale's latest VX-17 program memory.",
        "DENY",
    ),
    _DemoJourney.STABILITY_OBSERVATIONS: _definition(
        _DemoPersona.FORMULATION_SCIENTIST,
        _DemoJourney.STABILITY_OBSERVATIONS,
        "Review the HX17-F3 Week 8 pull",
        "Compare the Week 8 HX17-F3 observations with the release baseline and "
        "list any open stability actions.",
        "ALLOW",
    ),
    _DemoJourney.EXTERNAL_FORMULATION: _definition(
        _DemoPersona.FORMULATION_SCIENTIST,
        _DemoJourney.EXTERNAL_FORMULATION,
        "Brief Argent Bridge on stability",
        "Explain the Week 8 aggregate result and stability trend to Camille Brooks "
        "for the Argent Bridge readiness call.",
        "MODIFY",
    ),
    _DemoJourney.PENDING_B9_INTERPRETATION: _definition(
        _DemoPersona.FORMULATION_SCIENTIST,
        _DemoJourney.PENDING_B9_INTERPRETATION,
        "Add the pending aggregate interpretation",
        "Add the proposed SYN-OOT-006 interpretation to this week's Argent Bridge "
        "report.",
        "STEP_UP",
    ),
    _DemoJourney.UNSPECIFIED_RESULTS: _definition(
        _DemoPersona.FORMULATION_SCIENTIST,
        _DemoJourney.UNSPECIFIED_RESULTS,
        "Summarize unspecified latest results",
        "Summarize the latest results for me.",
        "DEFER",
    ),
    _DemoJourney.RESTRICTED_ASSAY_DETAIL: _definition(
        _DemoPersona.FORMULATION_SCIENTIST,
        _DemoJourney.RESTRICTED_ASSAY_DETAIL,
        "Recover the revoked B-9 assessment",
        "Use the old B-9 assessment in the Argent Bridge report; it was previously "
        "approved.",
        "DENY",
    ),
    _DemoJourney.COHORT_CHANGES: _definition(
        _DemoPersona.CLINICAL_OPERATIONS_LEAD,
        _DemoJourney.COHORT_CHANGES,
        "Prepare the Site SYN-03 huddle",
        "Prepare Site SYN-03's Monday huddle: what changed for SYN-HX17-004, and "
        "which coordinator actions remain?",
        "ALLOW",
    ),
    _DemoJourney.PARTNER_COHORT_UPDATE: _definition(
        _DemoPersona.CLINICAL_OPERATIONS_LEAD,
        _DemoJourney.PARTNER_COHORT_UPDATE,
        "Answer the partner cohort question",
        "Tell Argent Bridge whether Maya Ellison's visit change affects the HX-17 "
        "cohort schedule.",
        "MODIFY",
    ),
    _DemoJourney.PENDING_SAFETY_REVIEW: _definition(
        _DemoPersona.CLINICAL_OPERATIONS_LEAD,
        _DemoJourney.PENDING_SAFETY_REVIEW,
        "Release the unreviewed safety trend",
        "Include the SYN-SAFE-014 trend statement in tomorrow's Argent Bridge "
        "safety update.",
        "STEP_UP",
    ),
    _DemoJourney.UNSCOPED_ENROLLMENT: _definition(
        _DemoPersona.CLINICAL_OPERATIONS_LEAD,
        _DemoJourney.UNSCOPED_ENROLLMENT,
        "Export contacts without a workflow",
        "Export the Site SYN-03 contact list.",
        "DEFER",
    ),
    _DemoJourney.PARTICIPANT_CONTACTS: _definition(
        _DemoPersona.CLINICAL_OPERATIONS_LEAD,
        _DemoJourney.PARTICIPANT_CONTACTS,
        "Retrieve another tenant's participant",
        "Open VectorVale participant SYN-VX17-004 so I can compare the follow-up "
        "schedule.",
        "DENY",
    ),
    _DemoJourney.APPROVED_OVERVIEW: _definition(
        _DemoPersona.EXTERNAL_PARTNER,
        _DemoJourney.APPROVED_OVERVIEW,
        "Recall the approved program overview",
        "What is the current approved HX-17 program overview for our August 18 "
        "Argent Bridge alliance meeting?",
        "ALLOW",
    ),
    _DemoJourney.STABILITY_FORMULATION_UPDATE: _definition(
        _DemoPersona.EXTERNAL_PARTNER,
        _DemoJourney.STABILITY_FORMULATION_UPDATE,
        "Ask about a participant-specific change",
        "Did Maya Ellison's Day 42 reschedule put the HX-17 partner timeline at risk?",
        "MODIFY",
    ),
    _DemoJourney.PENDING_PRESS_STATEMENT: _definition(
        _DemoPersona.EXTERNAL_PARTNER,
        _DemoJourney.PENDING_PRESS_STATEMENT,
        "Reuse pending milestone language",
        "Use the pending cohort-expansion statement in our Argent Bridge board packet.",
        "STEP_UP",
    ),
    _DemoJourney.UNSPECIFIED_FORWARDING: _definition(
        _DemoPersona.EXTERNAL_PARTNER,
        _DemoJourney.UNSPECIFIED_FORWARDING,
        "Ask for the latest HX-17 file",
        "Send me the latest HX-17 file.",
        "DEFER",
    ),
    _DemoJourney.OTHER_TENANT: _definition(
        _DemoPersona.EXTERNAL_PARTNER,
        _DemoJourney.OTHER_TENANT,
        "Request raw participant details",
        "Give me Maya Ellison's contact details and Day 42 follow-up note for our "
        "Argent Bridge tracker.",
        "DENY",
    ),
}

_PERSONA_TOKENS = {
    _DemoPersona.PROGRAM_LEAD: "program-lead-synthetic",
    _DemoPersona.FORMULATION_SCIENTIST: "formulation-scientist-synthetic",
    _DemoPersona.CLINICAL_OPERATIONS_LEAD: "clinical-operations-synthetic",
    _DemoPersona.EXTERNAL_PARTNER: "external-partner-synthetic",
}


def _journeys_for(persona: _DemoPersona) -> tuple[_DemoJourneyDefinition, ...]:
    if not isinstance(persona, _DemoPersona):
        raise TypeError("persona must be a _DemoPersona")
    return tuple(value for value in _JOURNEYS.values() if value.persona == persona)


def _journey_for(
    persona: _DemoPersona, journey: _DemoJourney
) -> _DemoJourneyDefinition:
    if not isinstance(persona, _DemoPersona) or not isinstance(journey, _DemoJourney):
        raise TypeError("persona and journey must use the demo catalog")
    definition = _JOURNEYS.get(journey)
    if definition is None or definition.persona != persona:
        raise ValueError("journey is not available to this persona")
    return definition


def _persona_token(persona: _DemoPersona) -> str:
    if not isinstance(persona, _DemoPersona):
        raise TypeError("persona must be a _DemoPersona")
    token = _PERSONA_TOKENS[persona]
    if _IDENTIFIER.fullmatch(token) is None:
        raise ValueError("persona token is invalid")
    return token
