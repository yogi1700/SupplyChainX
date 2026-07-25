"""Minimal CVSS v3.1 base score calculator.

OSV.dev vulnerability records give the CVSS vector string (e.g.
"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), not a plain numeric
score - the score has to be computed from it per the FIRST.org CVSS
v3.1 spec. This implements just the base score, which is what almost
every advisory reports and all we need for prioritization.
"""

import math
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(value: float) -> float:
    # CVSS spec's "round up to nearest 0.1"
    return math.ceil(value * 10) / 10


def cvss_v3_base_score(vector: str) -> float | None:
    """Returns the base score (0.0-10.0), or None if the vector can't
    be parsed (unexpected/older format)."""
    parts = dict(
        part.split(":") for part in vector.split("/") if ":" in part
    )

    try:
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        ui = _UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[parts["PR"]]
        c, i, a = _CIA[parts["C"]], _CIA[parts["I"]], _CIA[parts["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        return min(_roundup(1.08 * (impact + exploitability)), 10.0)
    return min(_roundup(impact + exploitability), 10.0)


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def extract_cve_ids(aliases: list[str]) -> list[str]:
    return [a for a in aliases if _CVE_RE.fullmatch(a)]
