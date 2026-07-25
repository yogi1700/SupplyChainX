"""Human-readable console report and JSON export for a finding list."""

import json
from pathlib import Path

from risk_engine import Finding

_TIER_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def print_console_report(findings: list[Finding]) -> None:
    counts = {tier: 0 for tier in _TIER_ORDER}
    for f in findings:
        counts[f.tier] += 1

    print("\n--- SupplyChainX Risk Report ---")
    print(f"Total findings: {len(findings)}  "
          f"(CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} "
          f"MEDIUM={counts['MEDIUM']} LOW={counts['LOW']})\n")

    for tier in ("CRITICAL", "HIGH"):
        tier_findings = [f for f in findings if f.tier == tier]
        if not tier_findings:
            continue
        print(f"[{tier}]")
        for f in tier_findings:
            cve = f.cve_ids[0] if f.cve_ids else f.vuln_id
            print(f"  {f.dependency.name}@{f.dependency.version} ({f.dependency.ecosystem}) "
                  f"- {cve}")
            print(f"    {f.summary[:100]}")
            print(f"    why: {f.reason}")
        print()

    if counts["MEDIUM"] or counts["LOW"]:
        print(f"({counts['MEDIUM']} MEDIUM and {counts['LOW']} LOW findings omitted from "
              f"console output - see the full JSON report)")


def write_json_report(findings: list[Finding], path: Path) -> None:
    data = [
        {
            "package": f.dependency.name,
            "version": f.dependency.version,
            "ecosystem": f.dependency.ecosystem,
            "direct": f.dependency.direct,
            "vuln_id": f.vuln_id,
            "cve_ids": f.cve_ids,
            "summary": f.summary,
            "cvss_score": f.cvss_score,
            "epss_score": f.epss_score,
            "in_kev": f.in_kev,
            "tier": f.tier,
            "reason": f.reason,
        }
        for f in findings
    ]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def worst_tier_present(findings: list[Finding]) -> str | None:
    for tier in _TIER_ORDER:
        if any(f.tier == tier for f in findings):
            return tier
    return None
