from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    name: str | None
    latest_version: str | None
    summary: str | None
    license: str | None
    requires_python: str | None
    author: str | None
    maintainer: str | None
    release_count: int | None
    latest_release_at: datetime | None
    latest_yanked: bool
    repository_url: str | None

    model_config = ConfigDict(frozen=True, extra="forbid")


class GitHubFacts(BaseModel):
    full_name: str | None
    archived: bool
    stars: int | None
    open_issues: int | None
    last_commit_at: datetime | None
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
    gaps: list[DataGap] = []

    model_config = ConfigDict(frozen=True, extra="forbid")


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
    data_gaps: list[DataGap]
    generated_at: datetime

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_data_gaps(self) -> Self:
        if self.data_gaps and self.rating is Rating.LOW:
            raise ValueError("A report with data gaps cannot have a low rating.")
        if self.data_gaps and self.confidence is Confidence.HIGH:
            raise ValueError("A report with data gaps cannot have high confidence.")
        return self
