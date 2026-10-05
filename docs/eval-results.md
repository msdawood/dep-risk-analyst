# Evaluation results

Generated 2026-10-05 11:15 UTC from live PyPI, OSV.dev and GitHub data (deterministic path, no LLM). Format: `rating / confidence`.

**6/6 cases match expectations.**

| Package | Expected | Actual | Result | Why this case |
|---|---|---|---|---|
| `requests` | low / high | low / high | pass | actively maintained, no known vulnerabilities in the latest release |
| `pycrypto` | high / medium | high / medium | pass | abandoned since 2013, CRITICAL CVE-2013-7459 in the final release, no GitHub link |
| `nose` | medium / medium | medium / medium | pass | unmaintained for about a decade; stale release alone gives MEDIUM, no GitHub link |
| `py` | medium / medium | medium / medium | pass | stale release; PyPI lists only a docs site, so GitHub is a data gap |
| `this-package-does-not-exist-xyz-123` | error: not_found | error: not_found | pass | a missing package is an error, not a low-risk report |
| `../etc/passwd` | error: invalid_input | error: invalid_input | pass | rejected before any network call |

Expectations were written from the package's known state before the run. A mismatch means the data changed, the rubric needs revisiting, or there is a bug; each is worth reading, not silencing.
