"""Credential-free, content-safe sensitive-data scanning.

The labels in this module are project-defined policy candidates. They are not
legal, clinical, or securities classifications, and deterministic detection is
necessarily imperfect. Raw input and matched substrings are deliberately absent
from every returned finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

_MAX_SCAN_CHARACTERS = 2_000
_MAX_FINDINGS_PER_LABEL = 255
_DETERMINISTIC_DETECTOR_ID = "deterministic-patterns-v1"
_SUPPLIED_LABEL_DETECTOR_ID = "caller-supplied-v1"
_DETECTOR_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


class _CandidateLabel(StrEnum):
    """Project-defined candidates; none is a legal classification."""

    PII = "PII"
    PHI_CANDIDATE = "PHI_CANDIDATE"
    IP_CONFIDENTIAL = "IP_CONFIDENTIAL"
    MNPI_CANDIDATE = "MNPI_CANDIDATE"
    SECRET = "SECRET"


class _ScanVerdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class _ScanReason(StrEnum):
    """Allowlisted, content-free reason codes for gateway decisions."""

    POLICY_SCAN_ALLOWED = "POLICY_SCAN_ALLOWED"
    PUBLIC_WRITE_PII_CANDIDATE = "PUBLIC_WRITE_PII_CANDIDATE"
    PUBLIC_WRITE_SECRET_CANDIDATE = "PUBLIC_WRITE_SECRET_CANDIDATE"
    EXTERNAL_OUTPUT_RESTRICTED_CANDIDATE = "EXTERNAL_OUTPUT_RESTRICTED_CANDIDATE"
    INTERNAL_OUTPUT_RESTRICTED_CANDIDATE = "INTERNAL_OUTPUT_RESTRICTED_CANDIDATE"
    DETECTOR_RESULT_TRUNCATED = "DETECTOR_RESULT_TRUNCATED"
    DETECTOR_UNAVAILABLE = "DETECTOR_UNAVAILABLE"


@dataclass(frozen=True, slots=True, repr=False)
class _ScanInput:
    """Bounded text plus sensitivity that automation may not lower."""

    text: str = field(repr=False)
    supplied_labels: tuple[_CandidateLabel, ...] = ()

    def __post_init__(self) -> None:
        if type(self.text) is not str:
            raise TypeError("text must be a string")
        if not self.text.strip():
            raise ValueError("text must not be empty")
        if len(self.text) > _MAX_SCAN_CHARACTERS:
            raise ValueError("text exceeds the scanner limit")
        if type(self.supplied_labels) is not tuple:
            raise TypeError("supplied_labels must be a tuple")
        if any(type(label) is not _CandidateLabel for label in self.supplied_labels):
            raise TypeError("supplied_labels contains an unsupported label")
        if len(set(self.supplied_labels)) != len(self.supplied_labels):
            raise ValueError("supplied_labels must not contain duplicates")
        object.__setattr__(
            self,
            "supplied_labels",
            tuple(sorted(self.supplied_labels, key=lambda label: label.value)),
        )

    def __repr__(self) -> str:
        labels = tuple(label.value for label in self.supplied_labels)
        return f"_ScanInput(text=<redacted>, supplied_labels={labels!r})"


@dataclass(frozen=True, slots=True)
class _FindingSummary:
    """A content-safe aggregate; positions and match strings are omitted."""

    label: _CandidateLabel
    detector_id: str
    count: int

    def __post_init__(self) -> None:
        if type(self.label) is not _CandidateLabel:
            raise TypeError("label must be a supported candidate label")
        if (
            type(self.detector_id) is not str
            or _DETECTOR_ID_RE.fullmatch(self.detector_id) is None
        ):
            raise ValueError("detector_id is invalid")
        if type(self.count) is not int:
            raise TypeError("count must be an integer")
        if not 1 <= self.count <= _MAX_FINDINGS_PER_LABEL:
            raise ValueError("count is outside the supported range")


@dataclass(frozen=True, slots=True)
class _DetectionResult:
    findings: tuple[_FindingSummary, ...]
    truncated: bool = False

    def __post_init__(self) -> None:
        if type(self.findings) is not tuple:
            raise TypeError("findings must be a tuple")
        if any(type(item) is not _FindingSummary for item in self.findings):
            raise TypeError("findings contains an invalid summary")
        if len(self.findings) > len(_CandidateLabel) * 2:
            raise ValueError("findings exceeds the bounded result size")
        keys = tuple((item.label.value, item.detector_id) for item in self.findings)
        if len(set(keys)) != len(keys):
            raise ValueError("findings must not contain duplicate summaries")
        if keys != tuple(sorted(keys)):
            raise ValueError("findings must be in canonical order")
        if type(self.truncated) is not bool:
            raise TypeError("truncated must be a boolean")

    @property
    def labels(self) -> tuple[_CandidateLabel, ...]:
        return tuple(
            sorted({item.label for item in self.findings}, key=lambda item: item.value)
        )


@dataclass(frozen=True, slots=True)
class _PolicyScanResult:
    """Fail-closed result consumed by the Memory Action Gateway."""

    verdict: _ScanVerdict
    reason_codes: tuple[_ScanReason, ...]
    detection: _DetectionResult

    def __post_init__(self) -> None:
        if type(self.verdict) is not _ScanVerdict:
            raise TypeError("verdict must be a supported scan verdict")
        if type(self.reason_codes) is not tuple or not self.reason_codes:
            raise ValueError("reason_codes must be a non-empty tuple")
        if any(type(reason) is not _ScanReason for reason in self.reason_codes):
            raise TypeError("reason_codes contains an unsupported reason")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("reason_codes must not contain duplicates")
        if self.reason_codes != tuple(
            sorted(self.reason_codes, key=lambda reason: reason.value)
        ):
            raise ValueError("reason_codes must be in canonical order")
        if type(self.detection) is not _DetectionResult:
            raise TypeError("detection must be a detection result")
        if self.verdict is _ScanVerdict.ALLOW and self.reason_codes != (
            _ScanReason.POLICY_SCAN_ALLOWED,
        ):
            raise ValueError("an allowed scan must use the allowed reason code")
        if self.verdict is _ScanVerdict.ALLOW and self.detection.truncated:
            raise ValueError("a truncated scan cannot be allowed")
        if self.verdict is _ScanVerdict.DENY and _ScanReason.POLICY_SCAN_ALLOWED in (
            self.reason_codes
        ):
            raise ValueError("a denied scan cannot use the allowed reason code")

    @property
    def is_allowed(self) -> bool:
        return self.verdict is _ScanVerdict.ALLOW


class _DetectorPort(Protocol):
    def detect(self, subject: _ScanInput) -> _DetectionResult: ...


def _compile(*expressions: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(expression, re.IGNORECASE) for expression in expressions)


_PATTERNS: dict[_CandidateLabel, tuple[re.Pattern[str], ...]] = {
    _CandidateLabel.PII: _compile(
        r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
        r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
        r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+",
        r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ]"
        r"(?!0000)\d{4}(?!\d)",
        r"(?<!\w)(?:\+?1[ .-]?)?\(?[2-9]\d{2}\)?[ .-]"
        r"[2-9]\d{2}[ .-]\d{4}(?!\w)",
        r"\b(?:SUBJ(?:ECT)?|PATIENT)[-_ ][A-Z0-9]{3,12}\b",
    ),
    _CandidateLabel.IP_CONFIDENTIAL: _compile(
        r"\b(?:trade secret|patent[- ]candidate|internal codename|"
        r"confidential (?:assay|formulation|process|protocol))\b",
        r"\bHX-\d{2}-(?:FORMULA|ASSAY|SALT|PROCESS)-[A-Z0-9-]{2,24}\b",
    ),
    _CandidateLabel.MNPI_CANDIDATE: _compile(
        r"\b(?:material nonpublic|unannounced (?:acquisition|merger)|"
        r"pre[- ]release earnings|not yet public)\b",
    ),
    _CandidateLabel.SECRET: _compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bgh[oprsu]_[A-Z0-9]{20,255}\b",
        r"\bsk-[A-Z0-9_-]{20,255}\b",
        r"\bBearer[ \t]+[A-Z0-9._~+/-]{12,255}=*",
        r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|"
        r"secret)[ \t]*[:=][ \t]*['\"]?[A-Z0-9_./+=-]{12,255}",
    ),
}

_SUBJECT_ID_PATTERN = re.compile(
    r"\b(?:SUBJ(?:ECT)?|PATIENT)[-_ ][A-Z0-9]{3,12}\b", re.IGNORECASE
)
_HEALTH_TERM_PATTERN = re.compile(
    r"\b(?:adverse event|diagnosis|dose|symptom|treatment)\b", re.IGNORECASE
)


class _DeterministicDetector:
    """Small exact-pattern detector with no credentials, models, or network."""

    def detect(self, subject: _ScanInput) -> _DetectionResult:
        if type(subject) is not _ScanInput:
            raise TypeError("subject must be a scan input")

        counts: dict[_CandidateLabel, int] = {}
        truncated = False
        for label, patterns in _PATTERNS.items():
            spans = {
                match.span()
                for pattern in patterns
                for match in pattern.finditer(subject.text)
            }
            if spans:
                counts[label] = min(len(spans), _MAX_FINDINGS_PER_LABEL)
                truncated |= len(spans) > _MAX_FINDINGS_PER_LABEL

        phi_spans = _phi_candidate_spans(subject.text)
        if phi_spans:
            counts[_CandidateLabel.PHI_CANDIDATE] = min(
                len(phi_spans), _MAX_FINDINGS_PER_LABEL
            )
            truncated |= len(phi_spans) > _MAX_FINDINGS_PER_LABEL

        findings = [
            _FindingSummary(label, _DETERMINISTIC_DETECTOR_ID, count)
            for label, count in counts.items()
        ]
        findings.extend(
            _FindingSummary(label, _SUPPLIED_LABEL_DETECTOR_ID, 1)
            for label in subject.supplied_labels
        )
        return _DetectionResult(
            findings=tuple(
                sorted(
                    findings,
                    key=lambda item: (item.label.value, item.detector_id),
                )
            ),
            truncated=truncated,
        )


class _ContentScanner:
    """Apply bounded public-write and external-output policy to detections."""

    def __init__(self, detector: _DetectorPort | None = None) -> None:
        self._detector = _DeterministicDetector() if detector is None else detector

    def scan_public_demo_write(self, subject: _ScanInput) -> _PolicyScanResult:
        return self._scan(
            subject,
            blocked_labels=frozenset({_CandidateLabel.PII, _CandidateLabel.SECRET}),
            reasons_by_label={
                _CandidateLabel.PII: _ScanReason.PUBLIC_WRITE_PII_CANDIDATE,
                _CandidateLabel.SECRET: _ScanReason.PUBLIC_WRITE_SECRET_CANDIDATE,
            },
        )

    def scan_external_output(self, subject: _ScanInput) -> _PolicyScanResult:
        return self._scan(
            subject,
            blocked_labels=frozenset(_CandidateLabel),
            reasons_by_label=dict.fromkeys(
                _CandidateLabel,
                _ScanReason.EXTERNAL_OUTPUT_RESTRICTED_CANDIDATE,
            ),
        )

    def scan_internal_output(self, subject: _ScanInput) -> _PolicyScanResult:
        """Block direct identifiers, clinical candidates, and secrets in demo UI."""

        blocked = frozenset(
            {
                _CandidateLabel.PII,
                _CandidateLabel.PHI_CANDIDATE,
                _CandidateLabel.SECRET,
            }
        )
        return self._scan(
            subject,
            blocked_labels=blocked,
            reasons_by_label=dict.fromkeys(
                blocked,
                _ScanReason.INTERNAL_OUTPUT_RESTRICTED_CANDIDATE,
            ),
        )

    def _scan(
        self,
        subject: _ScanInput,
        *,
        blocked_labels: frozenset[_CandidateLabel],
        reasons_by_label: dict[_CandidateLabel, _ScanReason],
    ) -> _PolicyScanResult:
        if type(subject) is not _ScanInput:
            raise TypeError("subject must be a scan input")
        try:
            detection = self._detector.detect(subject)
            if type(detection) is not _DetectionResult:
                raise TypeError("detector returned an invalid result")
        except Exception:
            return _denied_result(
                _empty_detection(),
                (_ScanReason.DETECTOR_UNAVAILABLE,),
            )

        reasons = {
            reasons_by_label[label]
            for label in detection.labels
            if label in blocked_labels
        }
        if detection.truncated:
            reasons.add(_ScanReason.DETECTOR_RESULT_TRUNCATED)
        if reasons:
            return _denied_result(detection, tuple(reasons))
        return _PolicyScanResult(
            verdict=_ScanVerdict.ALLOW,
            reason_codes=(_ScanReason.POLICY_SCAN_ALLOWED,),
            detection=detection,
        )


def _phi_candidate_spans(text: str) -> set[tuple[int, int]]:
    subject_spans = tuple(match.span() for match in _SUBJECT_ID_PATTERN.finditer(text))
    health_spans = tuple(match.span() for match in _HEALTH_TERM_PATTERN.finditer(text))
    candidates: set[tuple[int, int]] = set()
    for subject_start, subject_end in subject_spans:
        for health_start, health_end in health_spans:
            if max(subject_start, health_start) - min(subject_end, health_end) <= 120:
                candidates.add(
                    (min(subject_start, health_start), max(subject_end, health_end))
                )
    return candidates


def _empty_detection() -> _DetectionResult:
    return _DetectionResult(findings=())


def _denied_result(
    detection: _DetectionResult,
    reasons: tuple[_ScanReason, ...],
) -> _PolicyScanResult:
    return _PolicyScanResult(
        verdict=_ScanVerdict.DENY,
        reason_codes=tuple(sorted(set(reasons), key=lambda reason: reason.value)),
        detection=detection,
    )
