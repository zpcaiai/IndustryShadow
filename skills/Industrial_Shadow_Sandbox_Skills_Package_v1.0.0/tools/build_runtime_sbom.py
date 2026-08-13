from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import tomllib
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "backend/pyproject.toml"
RUNTIME_LOCK = ROOT / "backend/requirements.runtime.lock"
RUNTIME_EXTRAS = ("opcua", "observability", "object-storage")


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _runtime_direct_dependencies() -> set[str]:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    requirements = list(project["dependencies"])
    optional = project.get("optional-dependencies", {})
    for extra in RUNTIME_EXTRAS:
        requirements.extend(optional[extra])
    return {_normalized(Requirement(value).name) for value in requirements}


def _generate_inventory(destination: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "cyclonedx_py",
            "requirements",
            str(RUNTIME_LOCK),
            "--pyproject",
            str(PYPROJECT),
            "--output-reproducible",
            "--of",
            "JSON",
            "-o",
            str(destination),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"CycloneDX inventory generation failed: {completed.stdout[-2000:]}")
    return json.loads(destination.read_text(encoding="utf-8"))


def _dependency_graph(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    components = payload.get("components")
    if not isinstance(components, list) or not components:
        raise RuntimeError("CycloneDX inventory contains no runtime components")
    references: dict[str, str] = {}
    versions: dict[str, str] = {}
    for component in components:
        name = component.get("name")
        reference = component.get("bom-ref")
        version = component.get("version")
        if not all(isinstance(value, str) for value in (name, reference, version)):
            raise TypeError("CycloneDX component is missing a name, version, or bom-ref")
        normalized = _normalized(name)
        if normalized in references:
            raise RuntimeError(f"duplicate normalized SBOM component: {normalized}")
        references[normalized] = reference
        versions[normalized] = version

    direct = _runtime_direct_dependencies()
    missing = sorted(direct - references.keys())
    if missing:
        raise RuntimeError(f"runtime lock is missing direct dependencies: {', '.join(missing)}")

    graph: dict[str, set[str]] = {
        "root-component": {references[name] for name in direct}
    }
    for name, reference in references.items():
        graph.setdefault(reference, set())
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError:
            # Universal locks may include marker-selected packages for a different
            # operating system (for example colorama on Windows).
            continue
        if distribution.version != versions[name]:
            raise RuntimeError(
                f"installed runtime package does not match the lock: {name} "
                f"{distribution.version} != {versions[name]}"
            )
        requirements = distribution.requires or ()
        for raw_requirement in requirements:
            dependency = _normalized(Requirement(raw_requirement).name)
            if dependency in references and references[dependency] != reference:
                graph[reference].add(references[dependency])

    known_references = {"root-component", *references.values()}
    if any(child not in known_references for children in graph.values() for child in children):
        raise RuntimeError("SBOM dependency graph contains an unknown component reference")
    dependencies = [
        {"ref": reference, **({"dependsOn": sorted(children)} if children else {})}
        for reference, children in sorted(graph.items())
    ]
    return dependencies, sum(len(children) for children in graph.values())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a reproducible runtime CycloneDX SBOM with a complete dependency graph"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts/python-runtime-sbom.cdx.json",
    )
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="industrial-shadow-sbom-") as directory:
        inventory = Path(directory) / "inventory.json"
        payload = _generate_inventory(inventory)
        dependencies, edges = _dependency_graph(payload)
        payload["dependencies"] = dependencies
        descriptor, temporary = tempfile.mkstemp(prefix=".sbom-", dir=args.output.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, args.output)
        except Exception:
            Path(temporary).unlink(missing_ok=True)
            raise
    print(
        f"Generated CycloneDX {payload['specVersion']} runtime SBOM with "
        f"{len(payload['components'])} components and {edges} dependency edges."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
