"""Content-safe adapter for an injected Microsoft Presidio analyzer.

Presidio entity types are normalized to Gluevenir's project-defined policy
candidates.  Those candidates are not legal, clinical, or securities
classifications.  The adapter deliberately consumes only ``entity_type`` and
``score`` from analyzer results; match text, positions, recognizer explanations,
and raw result objects are never retained or returned.

The Presidio dependency is optional.  Runtime composition supplies an
analyzer-like object, while offline tests use a deterministic fake.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from typing import Protocol

from gluevenir._detectors import (
    _MAX_FINDINGS_PER_LABEL,
    _SUPPLIED_LABEL_DETECTOR_ID,
    _CandidateLabel,
    _DetectionResult,
    _FindingSummary,
    _ScanInput,
)

_PRESIDIO_DETECTOR_ID = "microsoft-presidio-v1"
_COMPOSITE_DETECTOR_ID = "patterns-presidio-v1"
_DEFAULT_SCORE_THRESHOLD = 0.5
_MAX_ANALYZER_RESULTS = len(_CandidateLabel) * _MAX_FINDINGS_PER_LABEL
_LANGUAGE_RE = re.compile(r"[a-z]{2}(?:-[A-Z]{2})?\Z")

# The standard Presidio categories below are limited to direct identifiers.
# Custom recognizers can emit the project labels named on the right.  Broad
# categories such as DATE_TIME and LOCATION are intentionally absent because
# treating them as sensitive by themselves would make the demo unusable.
_ENTITY_LABELS: dict[str, _CandidateLabel] = {
    "API_KEY": _CandidateLabel.SECRET,
    "AWS_ACCESS_KEY": _CandidateLabel.SECRET,
    "CREDIT_CARD": _CandidateLabel.PII,
    "CRYPTO": _CandidateLabel.PII,
    "EMAIL_ADDRESS": _CandidateLabel.PII,
    "IBAN_CODE": _CandidateLabel.PII,
    "IP_ADDRESS": _CandidateLabel.PII,
    "IP_CONFIDENTIAL": _CandidateLabel.IP_CONFIDENTIAL,
    "MEDICAL_LICENSE": _CandidateLabel.PII,
    "MNPI_CANDIDATE": _CandidateLabel.MNPI_CANDIDATE,
    "NRP": _CandidateLabel.PII,
    "PASSWORD": _CandidateLabel.SECRET,
    "PATIENT_IDENTIFIER": _CandidateLabel.PII,
    "PERSON": _CandidateLabel.PII,
    "PHI_CANDIDATE": _CandidateLabel.PHI_CANDIDATE,
    "PHONE_NUMBER": _CandidateLabel.PII,
    "SECRET": _CandidateLabel.SECRET,
    "UK_NHS": _CandidateLabel.PII,
    "URL": _CandidateLabel.PII,
    "US_BANK_NUMBER": _CandidateLabel.PII,
    "US_DRIVER_LICENSE": _CandidateLabel.PII,
    "US_ITIN": _CandidateLabel.PII,
    "US_PASSPORT": _CandidateLabel.PII,
    "US_SSN": _CandidateLabel.PII,
}


class _AnalyzerLike(Protocol):
    def analyze(
        self,
        *,
        text: str,
        language: str,
        entities: list[str],
        score_threshold: float,
    ) -> object: ...


class _PresidioAdapterError(RuntimeError):
    """Sanitized adapter failure that never includes analyzer-controlled data."""


class _PresidioDetector:
    """Normalize bounded Presidio analysis into Gluevenir detector summaries."""

    __slots__ = ("_analyzer", "_language", "_score_threshold")

    def __init__(
        self,
        analyzer: _AnalyzerLike,
        *,
        language: str = "en",
        score_threshold: float = _DEFAULT_SCORE_THRESHOLD,
    ) -> None:
        if not callable(getattr(analyzer, "analyze", None)):
            raise TypeError("analyzer must provide an analyze method")
        if type(language) is not str or _LANGUAGE_RE.fullmatch(language) is None:
            raise ValueError("language is invalid")
        if isinstance(score_threshold, bool) or not isinstance(
            score_threshold, (int, float)
        ):
            raise TypeError("score_threshold must be numeric")
        normalized_threshold = float(score_threshold)
        if (
            not math.isfinite(normalized_threshold)
            or not 0 <= normalized_threshold <= 1
        ):
            raise ValueError("score_threshold must be between zero and one")
        self._analyzer = analyzer
        self._language = language
        self._score_threshold = normalized_threshold

    def __repr__(self) -> str:
        return (
            "_PresidioDetector(analyzer=<redacted>, "
            f"language={self._language!r}, score_threshold={self._score_threshold!r})"
        )

    def detect(self, subject: _ScanInput) -> _DetectionResult:
        if type(subject) is not _ScanInput:
            raise TypeError("subject must be a scan input")

        try:
            raw_results = self._analyzer.analyze(
                text=subject.text,
                language=self._language,
                entities=sorted(_ENTITY_LABELS),
                score_threshold=self._score_threshold,
            )
        except Exception:
            raise _PresidioAdapterError("presidio analyzer unavailable") from None

        try:
            return self._normalize(raw_results, subject.supplied_labels)
        except _PresidioAdapterError:
            raise
        except Exception:
            raise _PresidioAdapterError(
                "presidio analyzer returned invalid data"
            ) from None

    def _normalize(
        self,
        raw_results: object,
        supplied_labels: tuple[_CandidateLabel, ...],
    ) -> _DetectionResult:
        if not isinstance(raw_results, Sequence) or isinstance(
            raw_results, (str, bytes, bytearray)
        ):
            raise _PresidioAdapterError("presidio analyzer returned invalid data")

        truncated = len(raw_results) > _MAX_ANALYZER_RESULTS
        counts: dict[_CandidateLabel, int] = {}
        for result in raw_results[:_MAX_ANALYZER_RESULTS]:
            entity_type = getattr(result, "entity_type", None)
            score = getattr(result, "score", None)
            if type(entity_type) is not str:
                raise _PresidioAdapterError("presidio analyzer returned invalid data")
            normalized_entity = entity_type.strip().upper()
            label = _ENTITY_LABELS.get(normalized_entity)
            if label is None:
                raise _PresidioAdapterError("presidio analyzer returned invalid data")
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise _PresidioAdapterError("presidio analyzer returned invalid data")
            normalized_score = float(score)
            if not math.isfinite(normalized_score) or not 0 <= normalized_score <= 1:
                raise _PresidioAdapterError("presidio analyzer returned invalid data")
            if normalized_score < self._score_threshold:
                continue
            previous = counts.get(label, 0)
            counts[label] = min(previous + 1, _MAX_FINDINGS_PER_LABEL)
            truncated |= previous >= _MAX_FINDINGS_PER_LABEL

        findings = [
            _FindingSummary(label, _PRESIDIO_DETECTOR_ID, count)
            for label, count in counts.items()
        ]
        findings.extend(
            _FindingSummary(label, _SUPPLIED_LABEL_DETECTOR_ID, 1)
            for label in supplied_labels
        )
        return _DetectionResult(
            findings=tuple(
                sorted(findings, key=lambda item: (item.label.value, item.detector_id))
            ),
            truncated=truncated,
        )


class _CompositeDetector:
    """Combine independent detectors without duplicating supplied sensitivity."""

    __slots__ = ("_detectors",)

    def __init__(self, detectors: tuple[object, ...]) -> None:
        if type(detectors) is not tuple or not detectors:
            raise ValueError("detectors must be a non-empty tuple")
        if any(
            not callable(getattr(detector, "detect", None)) for detector in detectors
        ):
            raise TypeError("each detector must provide a detect method")
        self._detectors = detectors

    def detect(self, subject: _ScanInput) -> _DetectionResult:
        if type(subject) is not _ScanInput:
            raise TypeError("subject must be a scan input")

        detector_subject = _ScanInput(subject.text)
        counts: dict[_CandidateLabel, int] = {}
        truncated = False
        for detector in self._detectors:
            result = detector.detect(detector_subject)  # type: ignore[attr-defined]
            if type(result) is not _DetectionResult:
                raise _PresidioAdapterError("detector returned invalid data")
            truncated |= result.truncated
            for finding in result.findings:
                previous = counts.get(finding.label, 0)
                counts[finding.label] = min(
                    previous + finding.count, _MAX_FINDINGS_PER_LABEL
                )
                truncated |= previous + finding.count > _MAX_FINDINGS_PER_LABEL

        findings = [
            _FindingSummary(label, _COMPOSITE_DETECTOR_ID, count)
            for label, count in counts.items()
        ]
        findings.extend(
            _FindingSummary(label, _SUPPLIED_LABEL_DETECTOR_ID, 1)
            for label in subject.supplied_labels
        )
        return _DetectionResult(
            findings=tuple(
                sorted(findings, key=lambda item: (item.label.value, item.detector_id))
            ),
            truncated=truncated,
        )


def _create_presidio_analyzer() -> object:
    """Create the pinned English Presidio engine without decision-process logs."""

    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
    )
    return AnalyzerEngine(
        nlp_engine=provider.create_engine(),
        supported_languages=["en"],
        log_decision_process=False,
    )
