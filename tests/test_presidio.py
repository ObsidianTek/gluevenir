from __future__ import annotations

from dataclasses import dataclass

import pytest

from gluevenir._detectors import (
    _CandidateLabel,
    _ContentScanner,
    _DetectionResult,
    _DeterministicDetector,
    _ScanInput,
    _ScanReason,
    _ScanVerdict,
)
from gluevenir._presidio import (
    _CompositeDetector,
    _create_presidio_analyzer,
    _PresidioAdapterError,
    _PresidioDetector,
)


@dataclass(slots=True)
class _FakeResult:
    entity_type: object
    score: object


class _FakeAnalyzer:
    def __init__(self, results: object) -> None:
        self.results = results
        self.calls: list[dict[str, object]] = []

    def analyze(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return self.results


def _summary(result: _DetectionResult) -> dict[tuple[str, str], int]:
    return {
        (finding.label.value, finding.detector_id): finding.count
        for finding in result.findings
    }


def test_normalizes_allowlisted_entities_and_confidence_without_raw_fields() -> None:
    class ResultWithDangerousFields:
        entity_type = "EMAIL_ADDRESS"
        score = 0.91

        @property
        def text(self) -> str:
            raise AssertionError("raw match must not be accessed")

        @property
        def start(self) -> int:
            raise AssertionError("offset must not be accessed")

        @property
        def end(self) -> int:
            raise AssertionError("offset must not be accessed")

        @property
        def analysis_explanation(self) -> object:
            raise AssertionError("recognizer explanation must not be accessed")

    sentinel = "presidio.sentinel@example.test"
    analyzer = _FakeAnalyzer(
        [
            ResultWithDangerousFields(),
            _FakeResult("person", 0.49),
            _FakeResult("PHI_CANDIDATE", 0.75),
            _FakeResult("API_KEY", 1),
        ]
    )
    result = _PresidioDetector(analyzer).detect(_ScanInput(sentinel))

    assert result.labels == (
        _CandidateLabel.PHI_CANDIDATE,
        _CandidateLabel.PII,
        _CandidateLabel.SECRET,
    )
    assert _summary(result) == {
        ("PHI_CANDIDATE", "microsoft-presidio-v1"): 1,
        ("PII", "microsoft-presidio-v1"): 1,
        ("SECRET", "microsoft-presidio-v1"): 1,
    }
    assert sentinel not in repr(result)
    assert analyzer.calls == [
        {
            "text": sentinel,
            "language": "en",
            "entities": sorted(analyzer.calls[0]["entities"]),
            "score_threshold": 0.5,
        }
    ]
    assert "DATE_TIME" not in analyzer.calls[0]["entities"]
    assert "LOCATION" not in analyzer.calls[0]["entities"]


def test_supplied_labels_are_monotonic_and_canonically_ordered() -> None:
    analyzer = _FakeAnalyzer(
        [
            _FakeResult("US_SSN", 0.9),
            _FakeResult("IP_CONFIDENTIAL", 0.8),
            _FakeResult("MNPI_CANDIDATE", 0.85),
            _FakeResult("EMAIL_ADDRESS", 0.7),
        ]
    )
    subject = _ScanInput(
        "Synthetic input",
        supplied_labels=(
            _CandidateLabel.SECRET,
            _CandidateLabel.IP_CONFIDENTIAL,
        ),
    )

    first = _PresidioDetector(analyzer).detect(subject)
    second = _PresidioDetector(analyzer).detect(subject)

    assert first == second
    assert first.labels == (
        _CandidateLabel.IP_CONFIDENTIAL,
        _CandidateLabel.MNPI_CANDIDATE,
        _CandidateLabel.PII,
        _CandidateLabel.SECRET,
    )
    assert tuple(
        (finding.label.value, finding.detector_id) for finding in first.findings
    ) == tuple(
        sorted((finding.label.value, finding.detector_id) for finding in first.findings)
    )
    assert _summary(first)[("IP_CONFIDENTIAL", "caller-supplied-v1")] == 1
    assert _summary(first)[("SECRET", "caller-supplied-v1")] == 1


@pytest.mark.parametrize(
    "results",
    [
        None,
        "not a result sequence",
        [_FakeResult("UNSUPPORTED_ENTITY", 0.9)],
        [_FakeResult("PERSON", "high")],
        [_FakeResult("PERSON", True)],
        [_FakeResult("PERSON", float("nan"))],
        [_FakeResult("PERSON", 1.1)],
        [_FakeResult(None, 0.9)],
    ],
)
def test_malformed_or_unsupported_results_fail_closed(results: object) -> None:
    detector = _PresidioDetector(_FakeAnalyzer(results))
    scanner = _ContentScanner(detector)

    scan = scanner.scan_external_output(_ScanInput("Safe-looking output"))

    assert scan.verdict is _ScanVerdict.DENY
    assert scan.reason_codes == (_ScanReason.DETECTOR_UNAVAILABLE,)
    assert scan.detection == _DetectionResult(findings=())


def test_analyzer_outage_and_exception_payload_are_sanitized() -> None:
    sentinel = "raw.person@example.test"

    class RaisingAnalyzer:
        def analyze(self, **kwargs: object) -> object:
            raise RuntimeError(f"service failed while analyzing {sentinel}")

    detector = _PresidioDetector(RaisingAnalyzer())
    with pytest.raises(_PresidioAdapterError) as caught:
        detector.detect(_ScanInput(sentinel))

    assert sentinel not in str(caught.value)
    assert sentinel not in repr(caught.value)
    scan = _ContentScanner(detector).scan_public_demo_write(_ScanInput(sentinel))
    assert scan.verdict is _ScanVerdict.DENY
    assert scan.reason_codes == (_ScanReason.DETECTOR_UNAVAILABLE,)
    assert sentinel not in repr(scan)


def test_adapter_repr_never_exposes_analyzer_repr() -> None:
    sentinel = "analyzer-config-secret"

    class SensitiveReprAnalyzer(_FakeAnalyzer):
        def __repr__(self) -> str:
            return sentinel

    detector = _PresidioDetector(SensitiveReprAnalyzer([]))

    assert sentinel not in repr(detector)
    assert "analyzer=<redacted>" in repr(detector)


def test_truncated_result_set_is_content_safe_and_scanner_denies() -> None:
    results = [_FakeResult("PERSON", 0.9) for _ in range(1_276)]
    detector = _PresidioDetector(_FakeAnalyzer(results))
    detection = detector.detect(_ScanInput("Synthetic input"))
    scan = _ContentScanner(detector).scan_public_demo_write(
        _ScanInput("Synthetic input")
    )

    assert detection.truncated is True
    assert detection.findings[0].count == 255
    assert scan.verdict is _ScanVerdict.DENY
    assert _ScanReason.DETECTOR_RESULT_TRUNCATED in scan.reason_codes


def test_adapter_and_constructor_reject_invalid_or_unbounded_inputs() -> None:
    analyzer = _FakeAnalyzer([])
    detector = _PresidioDetector(analyzer)

    with pytest.raises(TypeError):
        detector.detect("raw")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        detector.detect(_ScanInput("x" * 2_001))
    with pytest.raises(TypeError):
        _PresidioDetector(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _PresidioDetector(analyzer, language="english")
    with pytest.raises(ValueError):
        _PresidioDetector(analyzer, score_threshold=float("inf"))


def test_composite_detector_merges_patterns_and_presidio_once() -> None:
    subject = _ScanInput(
        "Contact synthetic.person@example.test with password=synthetic-secret-123",
        supplied_labels=(_CandidateLabel.PHI_CANDIDATE,),
    )
    detector = _CompositeDetector(
        (
            _DeterministicDetector(),
            _PresidioDetector(_FakeAnalyzer([_FakeResult("EMAIL_ADDRESS", 0.9)])),
        )
    )

    result = detector.detect(subject)

    assert result.labels == (
        _CandidateLabel.PHI_CANDIDATE,
        _CandidateLabel.PII,
        _CandidateLabel.SECRET,
    )
    assert _summary(result) == {
        ("PHI_CANDIDATE", "caller-supplied-v1"): 1,
        ("PII", "patterns-presidio-v1"): 2,
        ("SECRET", "patterns-presidio-v1"): 1,
    }


def test_pinned_presidio_factory_detects_a_synthetic_person_name() -> None:
    detector = _PresidioDetector(_create_presidio_analyzer())

    result = detector.detect(_ScanInput("Jordan Kim prepared the synthetic record."))

    assert _CandidateLabel.PII in result.labels
