"""Human-readable console report and JSON export for a finding list."""

import json
from pathlib import Path

from license_check import LicenseFinding
from risk_engine import Finding

_TIER_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def print_console_report(findings: list[Finding]) -> None:
    active = [f for f in findings if not f.suppressed]
    suppressed_count = len(findings) - len(active)

    counts = {tier: 0 for tier in _TIER_ORDER}
    for f in active:
        counts[f.tier] += 1

    print("\n--- SupplyChainX Risk Report ---")
    print(f"Total findings: {len(findings)}  "
          f"(CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} "
          f"MEDIUM={counts['MEDIUM']} LOW={counts['LOW']})"
          + (f"  [{suppressed_count} suppressed, excluded from the counts above]"
             if suppressed_count else "") + "\n")

    for tier in ("CRITICAL", "HIGH"):
        tier_findings = [f for f in active if f.tier == tier]
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
            "suppressed": f.suppressed,
            "suppression_reason": f.suppression_reason,
        }
        for f in findings
    ]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def worst_tier_present(findings: list[Finding]) -> str | None:
    """Only considers non-suppressed findings - a suppression is a
    documented decision to exclude something from the CI-gate, not a
    way to hide it (it still shows up in the full JSON report)."""
    active = [f for f in findings if not f.suppressed]
    for tier in _TIER_ORDER:
        if any(f.tier == tier for f in active):
            return tier
    return None


def print_license_report(license_findings: list[LicenseFinding]) -> None:
    copyleft = [f for f in license_findings if f.category == "copyleft"]
    permissive = sum(1 for f in license_findings if f.category == "permissive")
    unknown = sum(1 for f in license_findings if f.category == "unknown")

    print("\n--- License Risk ---")
    if copyleft:
        print(f"{len(copyleft)} copyleft-licensed dependency(ies) - a legal/compliance "
              f"concern separate from security risk:")
        for f in copyleft:
            print(f"  {f.dependency.name}@{f.dependency.version} "
                  f"({f.dependency.ecosystem}) - {f.license_text}")
    else:
        print("No copyleft-licensed dependencies found.")
    print(f"({permissive} permissive, {unknown} unknown/unresolved)")


def write_license_json(license_findings: list[LicenseFinding], path: Path) -> None:
    data = [
        {
            "package": f.dependency.name,
            "version": f.dependency.version,
            "ecosystem": f.dependency.ecosystem,
            "license": f.license_text,
            "category": f.category,
        }
        for f in license_findings
    ]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
