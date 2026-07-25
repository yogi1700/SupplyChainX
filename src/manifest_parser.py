"""Parses dependency manifests into a flat list of resolved packages.

Supports Python (requirements.txt, pinned versions only) and Node
(package-lock.json, which has exact resolved versions for the whole
tree including transitive deps - preferred over package.json, which
only lists version ranges for direct deps).
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Dependency:
    ecosystem: str  # matches OSV.dev ecosystem names: "PyPI", "npm"
    name: str
    version: str
    direct: bool
    source_file: str


_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)\s*(?:;.*)?$"
)


def parse_requirements_txt(path: Path) -> list[Dependency]:
    """Only picks up exact pins (name==version). Anything else (ranges,
    unpinned, -r includes, git URLs) is skipped - we can't reliably
    resolve those to a single real version without actually installing
    them, and a wrong version means wrong vulnerability matches."""
    deps = []
    skipped = []

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        match = _REQ_LINE_RE.match(stripped)
        if match:
            name, version = match.groups()
            deps.append(Dependency("PyPI", name.lower(), version, True, str(path)))
        else:
            skipped.append(stripped)

    if skipped:
        print(f"[manifest] {path}: skipped {len(skipped)} unpinned/complex line(s): "
              f"{', '.join(skipped[:5])}{' ...' if len(skipped) > 5 else ''}")

    return deps


def parse_package_lock(path: Path) -> list[Dependency]:
    """Handles npm lockfile v2/v3 ("packages" map) and falls back to v1
    ("dependencies" tree) if that's what's present."""
    data = json.loads(path.read_text(encoding="utf-8"))
    deps: list[Dependency] = []

    if "packages" in data:
        # v2/v3: keys are paths like "node_modules/foo" or "" for the root
        for pkg_path, info in data["packages"].items():
            if pkg_path == "" or "node_modules" not in pkg_path:
                continue
            name = pkg_path.split("node_modules/")[-1]
            version = info.get("version")
            if not version:
                continue
            direct = pkg_path.count("node_modules/") == 1
            deps.append(Dependency("npm", name, version, direct, str(path)))

    elif "dependencies" in data:
        def walk(tree: dict, direct: bool):
            for name, info in tree.items():
                version = info.get("version")
                if version:
                    deps.append(Dependency("npm", name, version, direct, str(path)))
                if "dependencies" in info:
                    walk(info["dependencies"], direct=False)

        walk(data["dependencies"], direct=True)

    return deps


def parse_manifests(project_dir: Path) -> list[Dependency]:
    deps: list[Dependency] = []

    req_file = project_dir / "requirements.txt"
    if req_file.exists():
        deps.extend(parse_requirements_txt(req_file))

    lock_file = project_dir / "package-lock.json"
    if lock_file.exists():
        deps.extend(parse_package_lock(lock_file))

    # de-dupe (same name+version can appear multiple times in a lockfile
    # via different dependency paths) - keep "direct" if any occurrence was direct
    merged: dict[tuple[str, str, str], Dependency] = {}
    for dep in deps:
        key = (dep.ecosystem, dep.name, dep.version)
        if key not in merged or (dep.direct and not merged[key].direct):
            merged[key] = dep

    return list(merged.values())
