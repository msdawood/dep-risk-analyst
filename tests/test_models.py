from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from dep_risk.models import Confidence, DataGap, PackageFacts, Rating, RiskReport, Source


def _build_report(
    *,
    rating: Rating = Rating.MEDIUM,
    confidence: Confidence = Confidence.MEDIUM,
    data_gaps: list[DataGap] | None = None,
) -> RiskReport:
    return RiskReport(
        package="requests",
        version="2.31.0",
        rating=rating,
        score=25,
        confidence=confidence,
        technical_summary="No critical issues found.",
        executive_summary="The package appears suitable for use.",
        data_gaps=data_gaps if data_gaps is not None else [],
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _data_gap() -> DataGap:
    return DataGap(source=Source.PYPI, reason="Package metadata was unavailable.")


def test_missing_package_source_requires_a_matching_gap() -> None:
    gaps = (
        DataGap(source=Source.GITHUB, reason="Repository metadata was unavailable."),
        DataGap(source=Source.OSV, reason="Vulnerability data was unavailable."),
    )

    with pytest.raises(ValidationError, match="pypi is missing but no data gap was recorded"):
        PackageFacts(package="requests", gaps=gaps)


def test_missing_package_sources_are_valid_when_all_have_gaps() -> None:
    gaps = tuple(DataGap(source=source, reason="Source data was unavailable.") for source in Source)

    facts = PackageFacts(package="requests", gaps=gaps)

    assert facts.gaps == gaps


def test_valid_report_builds() -> None:
    report = _build_report()

    assert report.package == "requests"
    assert report.rating is Rating.MEDIUM


def test_low_rating_with_data_gap_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        _build_report(rating=Rating.LOW, data_gaps=[_data_gap()])


def test_high_confidence_with_data_gap_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        _build_report(confidence=Confidence.HIGH, data_gaps=[_data_gap()])


def test_unknown_extra_field_is_rejected() -> None:
    report_data = _build_report().model_dump()
    report_data["unknown"] = "unexpected"

    with pytest.raises(ValidationError):
        RiskReport.model_validate(report_data)


def test_frozen_report_rejects_assignment() -> None:
    report = _build_report()

    with pytest.raises(ValidationError):
        field_name = "score"
        setattr(report, field_name, 30)


def test_report_json_round_trip_preserves_equality() -> None:
    report = _build_report()

    restored = RiskReport.model_validate_json(report.model_dump_json())

    assert restored == report
