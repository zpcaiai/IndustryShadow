#!/usr/bin/env python3
"""Validate this skill package's batch contracts; never validate product implementation."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REQUIRED_HEADINGS = (
    "## Context",
    "## Outcome",
    "## Inputs",
    "## Code modules",
    "## Interfaces",
    "## Implementation requirements",
    "## Tests",
    "## Required evidence",
    "## Definition of Done",
    "## Out of scope",
)


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    errors: list[str] = []
    skill = root / "SKILL.md"
    if not skill.is_file():
        errors.append("missing SKILL.md")
    else:
        frontmatter = skill.read_text(encoding="utf-8")
        if not re.match(r"^---\nname: implement-industrial-shadow-sandbox\ndescription: .+\n---\n", frontmatter):
            errors.append("invalid root SKILL.md frontmatter")

    refs = root / "references"
    system_contract = refs / "system-contract.md"
    if not system_contract.is_file():
        errors.append("missing references/system-contract.md")

    for number in range(1, 25):
        path = refs / f"batch-{number:02d}.md"
        if not path.is_file():
            errors.append(f"missing {path.relative_to(root)}")
            continue
        text = path.read_text(encoding="utf-8")
        if not text.startswith(f"# Batch {number:02d}:"):
            errors.append(f"{path.name}: invalid title")
        for heading in REQUIRED_HEADINGS:
            if heading not in text:
                errors.append(f"{path.name}: missing {heading}")
        for token in ("TODO", "TBD", "待补充", "占位"):
            if token in text:
                errors.append(f"{path.name}: forbidden placeholder token {token}")
        if "docs/evidence/batch-" not in text:
            errors.append(f"{path.name}: missing evidence path")
        if len(text.splitlines()) < 70:
            errors.append(f"{path.name}: contract is too short ({len(text.splitlines())} lines)")

    if errors:
        print("Batch contract validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Validated 24 implementation batch contracts and the root skill structure.")
    print("This result does not claim any target repository code is implemented.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
