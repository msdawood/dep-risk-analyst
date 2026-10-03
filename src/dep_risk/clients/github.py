import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import SecretStr
from tenacity.wait import wait_base

from dep_risk.clients.base import BaseClient, as_object
from dep_risk.errors import InvalidInputError, InvalidResponseError, RateLimitedError
from dep_risk.models import GitHubFacts, Source

logger = logging.getLogger(__name__)

_API_URL = "https://api.github.com/repos/{owner}/{repo}"
_API_VERSION = "2022-11-28"
_USER_AGENT = "dep-risk/0.1"  # GitHub rejects requests without a User-Agent
# GitHub logins: alphanumerics and hyphens (max 39). Repo names also allow "." and "_".
_REPO_URL_RE = re.compile(
    r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})"
)


def parse_repository_url(url: str) -> tuple[str, str]:
    match = _REPO_URL_RE.fullmatch(url.strip().rstrip("/"))
    if match is None or match.group(2) in {".", ".."}:
        raise InvalidInputError(f"Invalid GitHub repository URL: {url[:100]!r}")
    return match.group(1), match.group(2)


def parse_github_facts(data: Mapping[str, Any]) -> GitHubFacts:
    try:
        return GitHubFacts(
            full_name=data["full_name"],  # required
            archived=data["archived"],  # required: never assume "not archived"
            stars=data.get("stargazers_count"),  # optional: missing means unknown, not zero
            open_issues=data.get("open_issues_count"),  # note: GitHub counts open PRs here too
            last_commit_at=data.get("pushed_at"),  # last push to any branch
            contributor_count=None,  # not fetched in this version
        )
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise InvalidResponseError(
            Source.GITHUB, f"unexpected response shape ({type(exc).__name__})"
        ) from exc


def _is_rate_limited(response: httpx.Response) -> bool:
    # Primary limit: 403/429 with x-ratelimit-remaining: 0.
    # Secondary limit: 403/429 with a retry-after header (or only an error message).
    return response.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in response.headers


class GitHubClient(BaseClient):
    source = Source.GITHUB

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        token: SecretStr | None = None,
        max_attempts: int = 3,
        wait: wait_base | None = None,
    ) -> None:
        super().__init__(http, max_attempts=max_attempts, wait=wait)
        self._token = token

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": _USER_AGENT,
        }
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token.get_secret_value()}"
        return headers

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code in (403, 429) and _is_rate_limited(response):
            raise RateLimitedError(self.source, self._rate_limit_message(response))
        super()._raise_for_status(response)

    def _rate_limit_message(self, response: httpx.Response) -> str:
        message = f"HTTP {response.status_code}: rate limit reached"
        reset = response.headers.get("x-ratelimit-reset", "")
        if reset.isdigit() and len(reset) <= 10:
            message += f", resets at {datetime.fromtimestamp(int(reset), tz=UTC):%H:%M} UTC"
        if self._token is None:
            message += " (set GITHUB_TOKEN for a higher limit)"
        return message

    async def fetch(self, repository_url: str) -> GitHubFacts:
        owner, repo = parse_repository_url(repository_url)
        url = _API_URL.format(owner=owner, repo=repo)
        data = as_object(self.source, await self._request_json("GET", url, headers=self._headers()))
        return parse_github_facts(data)
