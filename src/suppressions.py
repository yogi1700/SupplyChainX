"""Suppression/waiver support: lets a specific CVE+package finding be
marked as an accepted risk with a documented reason, so it stops
blocking CI without silently vanishing from the report.

This mirrors how real vulnerability-management tools work - "won't
fix, here's why" is a normal, auditable outcome, not the same thing as
"we didn't know about it."
"""

import json
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path


@dataclass(frozen=True)
class Suppression:
    cve_id: str
    package: str
    reason: str
    expires: str | None  # ISO date string, or None for no expiry

    def is_active(self, today: date) -> bool:
        if not self.expires:
            return True
        return date.fromisoformat(self.expires) >= today


def load_suppressions(path: Path) -> list[Suppression]:
    if not path.exists():
        return []

    raw = json.loads(path.read_text(encoding="utf-8"))
    return [
        Suppression(
            cve_id=entry["cve_id"],
            package=entry["package"].lower(),
            reason=entry["reason"],
            expires=entry.get("expires"),
        )
        for entry in raw
    ]


def is_suppressed(cve_ids: list[str], package_name: str, suppressions: list[Suppression],
                   today: date | None = None) -> Suppression | None:
    """Returns the matching active Suppression, or None. An expired
    suppression does NOT match - the finding goes back to blocking CI,
    which is the point of an expiry date (force a re-review instead of
    a waiver silently lasting forever)."""
    today = today or datetime.now().date()
    package_name = package_name.lower()

    for suppression in suppressions:
        if suppression.package != package_name:
            continue
        if suppression.cve_id not in cve_ids:
            continue
        if suppression.is_active(today):
            return suppression

    return None
