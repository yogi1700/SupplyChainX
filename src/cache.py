"""Local caching for OSV.dev responses, keyed by package+version for
the batch vulnerability-ID lookup, and by vuln ID for the (much more
numerous) per-vulnerability detail fetches - that second one is where
almost all of the actual HTTP traffic is, so caching only the batch
query barely helps on its own.

A specific package@version's known vulnerabilities only grow over
time, and a specific vuln ID's details essentially never change once
published - so a cache hit is never *wrong*, only potentially a
little stale. There's no built-in expiry here; --no-cache is the
manual override for "I want a fully fresh scan right now."
"""

import json
from pathlib import Path

from manifest_parser import Dependency

CACHE_DIR = Path(".supplychainx_cache")
CACHE_FILE = CACHE_DIR / "osv_cache.json"


def _dep_key(dep: Dependency) -> str:
    return f"{dep.ecosystem}:{dep.name}:{dep.version}"


def load_cache(cache_file: Path = CACHE_FILE) -> dict:
    if not cache_file.exists():
        return {"packages": {}, "vulns": {}}

    data = json.loads(cache_file.read_text(encoding="utf-8"))
    data.setdefault("packages", {})
    data.setdefault("vulns", {})
    return data


def save_cache(cache: dict, cache_file: Path = CACHE_FILE) -> None:
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def split_cached_packages(
    deps: list[Dependency], cache: dict
) -> tuple[dict[Dependency, list[str]], list[Dependency]]:
    """Returns (results already known from cache, deps that still need
    a real OSV batch query). A cached empty list means "queried
    before, no vulnerabilities" - that's still a cache hit, not a miss."""
    packages = cache["packages"]
    cached_results: dict[Dependency, list[str]] = {}
    to_query: list[Dependency] = []

    for dep in deps:
        key = _dep_key(dep)
        if key in packages:
            if packages[key]:
                cached_results[dep] = packages[key]
        else:
            to_query.append(dep)

    return cached_results, to_query


def update_package_cache(cache: dict, queried_deps: list[Dependency], fresh_results: dict) -> None:
    """Records results for every dep that was actually queried,
    including the ones with zero vulnerabilities - otherwise a clean
    package gets re-queried on every single run forever."""
    for dep in queried_deps:
        cache["packages"][_dep_key(dep)] = fresh_results.get(dep, [])


def split_cached_vulns(vuln_ids: set[str], cache: dict) -> tuple[dict[str, dict], set[str]]:
    """Returns (details already known from cache, vuln IDs that still
    need a real fetch). This is the split that matters most - a
    dependency tree with a handful of packages commonly has hundreds
    of individual vulnerability records to fetch, one HTTP call each."""
    vulns = cache["vulns"]
    cached = {vid: vulns[vid] for vid in vuln_ids if vid in vulns}
    to_fetch = {vid for vid in vuln_ids if vid not in vulns}
    return cached, to_fetch


def update_vuln_cache(cache: dict, fresh_details: dict[str, dict]) -> None:
    cache["vulns"].update(fresh_details)
