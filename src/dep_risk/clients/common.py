import re


def clean_text(value: object) -> str | None:
    """Return a stripped, non-empty string, or None."""
    if isinstance(value, str):
        return value.strip() or None
    return None


def canonical_name(name: str) -> str:
    """PEP 503 normalisation, without validation."""
    return re.sub(r"[-_.]+", "-", name).lower()
