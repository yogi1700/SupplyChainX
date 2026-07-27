"""Turns raw vulnerability + enrichment data into a prioritized list.

The point of this module: a dependency tree commonly turns up dozens
of CVEs, and treating them as equally urgent is how real prioritization
gets ignored. The tiering here is deliberately simple and, more
importantly, explainable - every finding says exactly why it landed
in its tier, so it can be argued with rather than just trusted.

Tiering rationale:
  CRITICAL - confirmed under active exploitation right now (CISA KEV).
             This overrides everything else; observed fact beats any
             prediction or theoretical severity.
  HIGH     - severe (CVSS >= 7) AND either meaningfully likely to be
             exploited (EPSS >= 0.1) or reachable directly (a direct
             dependency, not buried three levels deep transitively).
  MEDIUM   - severe but low predicted exploitation and only reachable
             transitively, OR moderate severity with real exploitation
             likelihood.
  LOW      - everything else: low severity, low predicted exploitation,
             transitive-only.
"""

from dataclasses import dataclass, field

from cvss import cvss_v3_base_score, extract_cve_ids
from manifest_parser import Dependency

EPSS_MEANINGFUL_THRESHOLD = 0.1  # 10% predicted exploitation probability


@dataclass
class Finding:
    dependency: Dependency
    vuln_id: str
    summary: str
    cve_ids: list[str]
    cvss_score: float | None
    epss_score: float | None
    in_kev: bool
    tier: str = field(init=False)
    reason: str = field(init=False)
    suppressed: bool = False
    suppression_reason: str | None = None

    def __post_init__(self):
        self.tier, self.reason = self._classify()

    def _classify(self) -> tuple[str, str]:
        if self.in_kev:
            return "CRITICAL", "confirmed under active exploitation (CISA KEV)"

        cvss = self.cvss_score or 0.0
        epss = self.epss_score or 0.0

        if cvss >= 7.0 and (epss >= EPSS_MEANINGFUL_THRESHOLD or self.dependency.direct):
            why = f"CVSS {cvss}"
            why += f", EPSS {epss:.0%}" if epss >= EPSS_MEANINGFUL_THRESHOLD else ""
            why += ", direct dependency" if self.dependency.direct else ""
            return "HIGH", why

        if cvss >= 7.0:
            return "MEDIUM", f"CVSS {cvss} but low predicted exploitation and only transitive"

        if cvss >= 4.0 and epss >= EPSS_MEANINGFUL_THRESHOLD:
            return "MEDIUM", f"CVSS {cvss}, meaningful predicted exploitation (EPSS {epss:.0%})"

        return "LOW", f"CVSS {cvss or 'unknown'}, low predicted exploitation"


_TIER_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def build_findings(
    vulns_by_dep: dict[Dependency, list[str]],
    vuln_details: dict[str, dict],
    epss_scores: dict[str, float],
    kev_ids: set[str],
) -> list[Finding]:
    # OSV aggregates advisories from multiple source databases (GHSA,
    # PYSEC, etc.), so the same real-world CVE commonly shows up under
    # more than one OSV id for the same package. Dedupe on (dependency,
    # CVE set) and keep whichever record actually has a summary.
    candidates: dict[tuple, Finding] = {}

    for dep, vuln_ids in vulns_by_dep.items():
        for vuln_id in vuln_ids:
            detail = vuln_details[vuln_id]

            cve_ids = extract_cve_ids(detail.get("aliases", []))

            cvss_score = None
            for severity in detail.get("severity", []):
                if severity.get("type") == "CVSS_V3":
                    cvss_score = cvss_v3_base_score(severity["score"])
                    break

            epss_score = max(
                (epss_scores[c] for c in cve_ids if c in epss_scores), default=None
            )
            in_kev = any(c in kev_ids for c in cve_ids)

            finding = Finding(
                dependency=dep,
                vuln_id=vuln_id,
                summary=detail.get("summary", "(no summary available)"),
                cve_ids=cve_ids,
                cvss_score=cvss_score,
                epss_score=epss_score,
                in_kev=in_kev,
            )

            dedupe_key = (dep, frozenset(cve_ids)) if cve_ids else (dep, vuln_id)
            existing = candidates.get(dedupe_key)
            if existing is None or (
                existing.summary == "(no summary available)" and finding.summary != existing.summary
            ):
                candidates[dedupe_key] = finding

    findings = list(candidates.values())
    findings.sort(key=lambda f: (_TIER_ORDER[f.tier], -(f.cvss_score or 0)))
    return findings


def apply_suppressions(findings: list[Finding], suppressions: list) -> list[Finding]:
    """Marks findings that match an active suppression. Suppressed
    findings stay in the list (visible in the full report) but are
    flagged so the CI-gate decision can skip them - suppression is a
    documented, auditable exception, not deletion."""
    from suppressions import is_suppressed

    for finding in findings:
        match = is_suppressed(finding.cve_ids, finding.dependency.name, suppressions)
        if match:
            finding.suppressed = True
            finding.suppression_reason = match.reason

    return findings
