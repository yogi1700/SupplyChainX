"""Adds real-world exploitation context to raw vulnerability data.

A CVE's CVSS severity says how bad it *could* be. It says nothing about
whether anyone is actually exploiting it. These two sources fill that
gap:

- EPSS (FIRST.org): a model's estimate of the probability a CVE gets
  exploited in the wild in the next 30 days.
- CISA KEV: a maintained list of vulnerabilities that are *confirmed*
  to be under active exploitation right now - the strongest possible
  signal, since it's observed fact rather than a prediction.
"""

import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_EPSS_BATCH_SIZE = 100


def get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Returns {cve_id: epss_score} for whichever of the given CVEs
    EPSS has scored. EPSS doesn't cover every CVE, so missing entries
    just mean "no data", not "zero risk"."""
    scores: dict[str, float] = {}

    unique_ids = list(dict.fromkeys(cve_ids))
    for start in range(0, len(unique_ids), _EPSS_BATCH_SIZE):
        chunk = unique_ids[start:start + _EPSS_BATCH_SIZE]
        response = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=30)
        response.raise_for_status()
        for entry in response.json().get("data", []):
            scores[entry["cve"]] = float(entry["epss"])

    return scores


def get_kev_cve_ids() -> set[str]:
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    return {entry["cveID"] for entry in response.json().get("vulnerabilities", [])}
