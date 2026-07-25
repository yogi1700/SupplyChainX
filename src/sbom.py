"""Generates a CycloneDX 1.5 JSON SBOM - the industry-standard format
(also used by Dependency-Track, Syft, and most enterprise SBOM
tooling), so this output is usable by other tools, not just this one.
"""

import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from manifest_parser import Dependency

_ECOSYSTEM_TO_PURL_TYPE = {"PyPI": "pypi", "npm": "npm"}


def _purl(dep: Dependency) -> str:
    purl_type = _ECOSYSTEM_TO_PURL_TYPE[dep.ecosystem]
    name = dep.name

    if purl_type == "npm" and name.startswith("@"):
        # scoped package, e.g. @scope/name -> pkg:npm/%40scope/name@version
        scope, _, rest = name.partition("/")
        name = f"{quote(scope)}/{rest}"

    return f"pkg:{purl_type}/{name}@{dep.version}"


def build_sbom(deps: list[Dependency], project_name: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": project_name,
            },
        },
        "components": [
            {
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "purl": _purl(dep),
                "scope": "required" if dep.direct else "optional",
            }
            for dep in sorted(deps, key=lambda d: (d.ecosystem, d.name))
        ],
    }
