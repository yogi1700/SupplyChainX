"""Flags dependencies under copyleft licenses (GPL, AGPL, LGPL).

This is a separate risk category from vulnerabilities - a dependency
can be perfectly secure and still be a real legal/compliance problem
if it's copyleft-licensed and pulled into a proprietary product. Product
security work covers both; this tool shouldn't only cover one.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import requests

from manifest_parser import Dependency

_WORKERS = 10

_COPYLEFT_MARKERS = ["AGPL", "GPL", "GNU GENERAL PUBLIC LICENSE", "GNU LESSER GENERAL PUBLIC LICENSE"]
_PERMISSIVE_MARKERS = ["MIT", "BSD", "APACHE", "ISC", "PYTHON SOFTWARE FOUNDATION", "UNLICENSE"]


@dataclass
class LicenseFinding:
    dependency: Dependency
    license_text: str | None
    category: str  # "copyleft", "permissive", "unknown"


def _classify(license_text: str | None) -> str:
    if not license_text:
        return "unknown"

    upper = license_text.upper()

    # check copyleft first - "LGPL" contains "GPL" so this ordering matters,
    # but both are still copyleft, so it doesn't actually change the outcome
    if any(marker in upper for marker in _COPYLEFT_MARKERS):
        return "copyleft"
    if any(marker in upper for marker in _PERMISSIVE_MARKERS):
        return "permissive"
    return "unknown"


def _pypi_license(name: str, version: str) -> str | None:
    try:
        response = requests.get(f"https://pypi.org/pypi/{name}/{version}/json", timeout=15)
        if response.status_code != 200:
            return None
        info = response.json()["info"]

        # classifiers are the more standardized signal when present
        for classifier in info.get("classifiers", []):
            if classifier.startswith("License :: OSI Approved ::"):
                return classifier.split("::")[-1].strip()

        return info.get("license") or None
    except (requests.RequestException, KeyError, ValueError):
        return None


def _npm_license(name: str, version: str) -> str | None:
    try:
        response = requests.get(f"https://registry.npmjs.org/{name}", timeout=15)
        if response.status_code != 200:
            return None
        data = response.json()
        version_data = data.get("versions", {}).get(version, {})
        license_field = version_data.get("license")
        if isinstance(license_field, dict):  # older npm packages use {"type": "..."}
            return license_field.get("type")
        return license_field
    except (requests.RequestException, KeyError, ValueError):
        return None


def _check_one(dep: Dependency) -> LicenseFinding:
    if dep.ecosystem == "PyPI":
        license_text = _pypi_license(dep.name, dep.version)
    elif dep.ecosystem == "npm":
        license_text = _npm_license(dep.name, dep.version)
    else:
        license_text = None

    return LicenseFinding(dependency=dep, license_text=license_text, category=_classify(license_text))


def check_licenses(deps: list[Dependency]) -> list[LicenseFinding]:
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        return list(pool.map(_check_one, deps))
