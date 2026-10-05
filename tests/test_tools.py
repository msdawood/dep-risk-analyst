import json
from typing import Any

from langchain_core.tools import BaseTool

from dep_risk.errors import SourceUnavailableError
from dep_risk.models import DataGap, Source
from dep_risk.tools import Collector, build_tools, facts_from_collector
from fakes import _Fake, _github, _osv, _pypi


def _tools(
    pypi: Any = None, osv: Any = None, github: Any = None
) -> tuple[dict[str, BaseTool], Collector, _Fake, _Fake]:
    collector = Collector()
    osv_fake, gh_fake = osv or _Fake(_osv()), github or _Fake(_github())
    tools = build_tools("demo", collector, pypi or _Fake(_pypi()), osv_fake, gh_fake)  # type: ignore[arg-type]
    return {t.name: t for t in tools}, collector, osv_fake, gh_fake


async def test_osv_before_pypi_is_refused_and_records_nothing() -> None:
    tools, collector, osv, _ = _tools()

    out = json.loads(await tools["get_osv_vulnerabilities"].ainvoke({"package": "demo"}))

    assert "get_pypi_metadata first" in out["error"]
    assert collector.results == {} and osv.calls == []


async def test_github_before_pypi_is_refused_and_records_nothing() -> None:
    tools, collector, _, github = _tools()

    out = json.loads(await tools["get_github_activity"].ainvoke({"package": "demo"}))

    assert "get_pypi_metadata first" in out["error"]
    assert collector.results == {} and github.calls == []


async def test_pypi_outage_makes_dependent_tools_record_gaps_without_fetching() -> None:
    pypi = _Fake(SourceUnavailableError("pypi", "HTTP 503"))
    tools, collector, osv, github = _tools(pypi=pypi)

    await tools["get_pypi_metadata"].ainvoke({"package": "demo"})
    await tools["get_osv_vulnerabilities"].ainvoke({"package": "demo"})
    await tools["get_github_activity"].ainvoke({"package": "demo"})

    assert all(isinstance(r, DataGap) for r in collector.results.values())
    assert set(collector.results) == {Source.PYPI, Source.OSV, Source.GITHUB}
    assert osv.calls == [] and github.calls == []
    facts = facts_from_collector("demo", collector)
    assert facts is not None and [g.source for g in facts.gaps] == [
        Source.PYPI,
        Source.OSV,
        Source.GITHUB,
    ]


async def test_missing_repository_link_is_recorded_as_a_gap() -> None:
    tools, collector, _, github = _tools(pypi=_Fake(_pypi(repository_url=None)))

    await tools["get_pypi_metadata"].ainvoke({"package": "demo"})
    out = json.loads(await tools["get_github_activity"].ainvoke({"package": "demo"}))

    assert "no GitHub repository linked" in out["error"] and "Do not estimate" in out["instruction"]
    assert github.calls == []
    assert isinstance(collector.results[Source.GITHUB], DataGap)


async def test_wrong_package_is_refused_by_every_tool() -> None:
    tools, collector, osv, github = _tools()

    for name in tools:
        out = json.loads(await tools[name].ainvoke({"package": "other"}))
        assert "demo" in out["error"]

    assert collector.results == {} and osv.calls == [] and github.calls == []


def test_incomplete_collector_gives_no_facts() -> None:
    collector = Collector()
    collector.results[Source.PYPI] = _pypi()
    assert facts_from_collector("demo", collector) is None
