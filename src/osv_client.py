"""Queries OSV.dev for known vulnerabilities affecting a set of
dependencies.

OSV's batch endpoint only returns vulnerability IDs (no severity or
summary), so each unique ID found gets a follow-up detail lookup -
cached, since the same vulnerability commonly affects more than one
dependency in a tree.
"""

from concurrent.futures import ThreadPoolExecutor

import requests

from manifest_parser import Dependency

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"

_BATCH_SIZE = 500  # OSV's documented max per querybatch request is 1000
_DETAIL_FETCH_WORKERS = 20  # these are separate independent HTTP calls, so worth parallelizing


def query_batch(deps: list[Dependency]) -> dict[Dependency, list[str]]:
    """Returns {dependency: [vuln_id, ...]} for every dependency that
    has at least one known vulnerability."""
    results: dict[Dependency, list[str]] = {}

    for start in range(0, len(deps), _BATCH_SIZE):
        chunk = deps[start:start + _BATCH_SIZE]
        payload = {
            "queries": [
                {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
                for d in chunk
            ]
        }
        response = requests.post(OSV_BATCH_URL, json=payload, timeout=30)
        response.raise_for_status()

        for dep, result in zip(chunk, response.json().get("results", [])):
            vuln_ids = [v["id"] for v in result.get("vulns", [])]
            if vuln_ids:
                results[dep] = vuln_ids

    return results


def _fetch_one(vuln_id: str) -> tuple[str, dict]:
    response = requests.get(OSV_VULN_URL.format(vuln_id), timeout=30)
    response.raise_for_status()
    return vuln_id, response.json()


def get_vuln_details(vuln_ids: set[str]) -> dict[str, dict]:
    """Fetches full details for each vuln ID once, regardless of how
    many dependencies it affects. These are independent lookups, so
    they're fetched concurrently rather than one at a time."""
    with ThreadPoolExecutor(max_workers=_DETAIL_FETCH_WORKERS) as pool:
        return dict(pool.map(_fetch_one, vuln_ids))
