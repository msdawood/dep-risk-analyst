from enum import StrEnum
from typing import Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class Rating(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Source(StrEnum):
    PYPI = "pypi"
    GITHUB = "github"
    OSV = "osv"


class PyPIFacts(BaseModel):
    name: str
    latest_version: str
    summary: str | None
    license: str | None
    requires_python: str | None
    author: str | None
    maintainer: str | None
    release_count: int | None
    latest_release_at: AwareDatetime | None
    latest_yanked: bool
    repository_url: str | None

    model_config = ConfigDict(frozen=True, extra="forbid")


class GitHubFacts(BaseModel):
    full_name: str
    archived: bool
    stars: int | None
    open_issues: int | None
    last_commit_at: AwareDatetime | None
    contributor_count: int | None

    model_config = ConfigDict(frozen=True, extra="forbid")


class Vulnerability(BaseModel):
    id: str
    aliases: list[str]
    summary: str | None
    severity: str | None
    fixed_in: list[str]

    model_config = ConfigDict(frozen=True, extra="forbid")


class OSVFacts(BaseModel):
    queried_version: str | None
    vulnerabilities: list[Vulnerability]

    model_config = ConfigDict(frozen=True, extra="forbid")


class DataGap(BaseModel):
    source: Source
    reason: str

    model_config = ConfigDict(frozen=True, extra="forbid")


class PackageFacts(BaseModel):
    package: str
    pypi: PyPIFacts | None = None
    github: GitHubFacts | None = None
    osv: OSVFacts | None = None
    gaps: tuple[DataGap, ...] = Field(default_factory=tuple)

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def _missing_source_needs_gap(self) -> Self:
        gap_sources = {g.source for g in self.gaps}
        for src, value in (
            (Source.PYPI, self.pypi),
            (Source.GITHUB, self.github),
            (Source.OSV, self.osv),
        ):
            if value is None and src not in gap_sources:
                raise ValueError(f"{src} is missing but no data gap was recorded")
        return self


class ReportNarrative(BaseModel):
    technical_summary: str
    executive_summary: str = Field(max_length=600)

    model_config = ConfigDict(frozen=True, extra="forbid")


class RiskReport(BaseModel):
    package: str
    version: str | None
    rating: Rating
    score: int = Field(ge=0, le=100)
    confidence: Confidence
    technical_summary: str
    executive_summary: str
    data_gaps: tuple[DataGap, ...] = Field(default_factory=tuple)
    generated_at: AwareDatetime

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_data_gaps(self) -> Self:
        if self.data_gaps and self.rating is Rating.LOW:
            raise ValueError("A report with data gaps cannot have a low rating.")
        if self.data_gaps and self.confidence is Confidence.HIGH:
            raise ValueError("A report with data gaps cannot have high confidence.")
        return self
