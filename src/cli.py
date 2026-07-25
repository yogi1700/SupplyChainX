"""Entry point: scan a project's dependencies, prioritize the real
risk, generate an SBOM, and (optionally) fail the build if policy says
so - the "shift security left into CI" part of this tool.

Usage:
    py cli.py <project_dir> [--config config/policy.json]
"""

import argparse
import json
import sys
from pathlib import Path

from manifest_parser import parse_manifests
from osv_client import query_batch, get_vuln_details
from enrichment import get_epss_scores, get_kev_cve_ids
from risk_engine import build_findings
from sbom import build_sbom
from report import print_console_report, write_json_report, worst_tier_present

_TIER_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def load_policy(config_path: Path) -> dict:
    if config_path.exists():
        return json.loads(config_path.read_text(encoding="utf-8"))
    return {"fail_on": "HIGH", "sbom_output": "sbom.json", "report_output": "report.json"}


def run(project_dir: Path, policy: dict) -> int:
    print(f"[SupplyChainX] Scanning {project_dir} ...")

    deps = parse_manifests(project_dir)
    if not deps:
        print("[SupplyChainX] No pinned dependencies found "
              "(requirements.txt with ==, or package-lock.json)")
        return 0
    print(f"[SupplyChainX] Found {len(deps)} resolved package(s)")

    print("[SupplyChainX] Querying OSV.dev for known vulnerabilities ...")
    vulns_by_dep = query_batch(deps)

    if not vulns_by_dep:
        print("[SupplyChainX] No known vulnerabilities found. Clean bill of health.")
        findings = []
    else:
        all_vuln_ids = {vid for ids in vulns_by_dep.values() for vid in ids}
        print(f"[SupplyChainX] {len(all_vuln_ids)} unique vulnerability record(s) to fetch ...")
        vuln_details = get_vuln_details(all_vuln_ids)

        all_cve_ids = [
            cve
            for detail in vuln_details.values()
            for cve in detail.get("aliases", [])
            if cve.startswith("CVE-")
        ]
        print(f"[SupplyChainX] Enriching {len(set(all_cve_ids))} CVE(s) with EPSS + CISA KEV ...")
        epss_scores = get_epss_scores(all_cve_ids)
        kev_ids = get_kev_cve_ids()

        findings = build_findings(vulns_by_dep, vuln_details, epss_scores, kev_ids)

    print_console_report(findings)

    sbom_path = project_dir / policy.get("sbom_output", "sbom.json")
    sbom_path.write_text(json.dumps(build_sbom(deps, project_dir.name), indent=2), encoding="utf-8")
    print(f"[SupplyChainX] SBOM written to {sbom_path}")

    report_path = project_dir / policy.get("report_output", "report.json")
    write_json_report(findings, report_path)
    print(f"[SupplyChainX] Full report written to {report_path}")

    fail_on = policy.get("fail_on", "HIGH")
    worst = worst_tier_present(findings)
    if worst and _TIER_ORDER.index(worst) <= _TIER_ORDER.index(fail_on):
        print(f"\n[SupplyChainX] FAILING: worst finding is {worst}, policy fails on {fail_on}+")
        return 1

    print(f"\n[SupplyChainX] PASSING: nothing at or above policy threshold ({fail_on})")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan project dependencies for real, prioritized risk.")
    parser.add_argument("project_dir", type=Path)
    parser.add_argument("--config", type=Path, default=Path("config/policy.json"))
    args = parser.parse_args()

    exit_code = run(args.project_dir, load_policy(args.config))
    sys.exit(exit_code)
