import pytest

from dep_risk.issues import Issue, unique_issues
from dep_risk.models import Vulnerability


def _vuln(
    id: str,
    aliases: list[str] | None = None,
    severity: str | None = None,
    fixed_in: list[str] | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=id,
        aliases=aliases or [],
        summary=None,
        severity=severity,
        fixed_in=fixed_in or [],
    )


def _pyyaml_records() -> list[Vulnerability]:
    # Shape of the real OSV response for pyyaml 5.3: 4 records, 2 underlying flaws.
    return [
        _vuln("GHSA-6757-jp84-gxfx", ["CVE-2020-1747", "PYSEC-2020-96"], "CRITICAL", ["5.3.1"]),
        _vuln("GHSA-8q59-q68h-6hv4", ["CVE-2020-14343", "PYSEC-2021-142"], "CRITICAL", ["5.4"]),
        _vuln("PYSEC-2020-96", ["CVE-2020-1747", "GHSA-6757-jp84-gxfx"], None, ["5.3.1"]),
        _vuln("PYSEC-2021-142", ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"], None, ["5.4"]),
    ]


def test_real_pyyaml_records_collapse_to_two_critical_issues() -> None:
    issues = unique_issues(_pyyaml_records())

    assert sorted(issues, key=lambda i: i.ids) == [
        Issue(("CVE-2020-14343", "GHSA-8q59-q68h-6hv4", "PYSEC-2021-142"), "CRITICAL", ("5.4",)),
        Issue(("CVE-2020-1747", "GHSA-6757-jp84-gxfx", "PYSEC-2020-96"), "CRITICAL", ("5.3.1",)),
    ]


def test_result_does_not_depend_on_input_order() -> None:
    records = _pyyaml_records()

    forward = set(unique_issues(records))
    backward = set(unique_issues(list(reversed(records))))

    assert forward == backward


def test_chain_merges_even_when_the_middle_record_is_absent() -> None:
    # A lists B, C lists B, there is no record for B itself.
    issues = unique_issues([_vuln("A", ["B"], "LOW"), _vuln("C", ["B"], "HIGH", ["2.0"])])

    assert issues == [Issue(("A", "B", "C"), "HIGH", ("2.0",))]


def test_merged_issue_takes_the_highest_known_severity() -> None:
    records = [_vuln("A", ["B"], None), _vuln("B", ["A"], "HIGH"), _vuln("C", ["A"], "MODERATE")]

    (issue,) = unique_issues(records)

    assert issue.severity == "HIGH"


def test_unrelated_records_stay_separate_and_unknown_severity_stays_unknown() -> None:
    issues = unique_issues([_vuln("A", ["B"], None), _vuln("C", ["D"], "HIGH")])

    assert {(i.ids, i.severity) for i in issues} == {
        (("A", "B"), None),
        (("C", "D"), "HIGH"),
    }


def test_unrecognised_severity_labels_are_ignored() -> None:
    (issue,) = unique_issues([_vuln("A", [], "banana")])

    assert issue.severity is None


def test_fixed_versions_are_merged_without_duplicates_in_first_seen_order() -> None:
    records = [_vuln("A", ["B"], None, ["1.0.1"]), _vuln("B", ["A"], None, ["1.0.1", "1.1.0"])]

    (issue,) = unique_issues(records)

    assert issue.fixed_in == ("1.0.1", "1.1.0")


@pytest.mark.parametrize("records", [[], [_vuln("A")]])
def test_trivial_inputs(records: list[Vulnerability]) -> None:
    assert len(unique_issues(records)) == len(records)
