import asyncio
import sys

import httpx

from dep_risk.clients.osv import OSVClient
from dep_risk.errors import DepRiskError


async def main(package: str, version: str) -> int:
    async with httpx.AsyncClient(
        timeout=10.0, follow_redirects=True, headers={"User-Agent": "dep-risk/0.1"}
    ) as http:
        try:
            facts = await OSVClient(http).fetch(package, version)
        except DepRiskError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    print(facts.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(
        asyncio.run(
            main(
                sys.argv[1] if len(sys.argv) > 1 else "pyyaml",
                sys.argv[2] if len(sys.argv) > 2 else "5.3",
            )
        )
    )
