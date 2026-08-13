from __future__ import annotations

import html
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from shadow_sandbox.common.models import canonical_digest, canonical_json


@dataclass(frozen=True, slots=True)
class Report:
    report_id: str
    run_id: str
    title: str
    sections: Mapping[str, Any]
    version_manifest: Mapping[str, str]
    evidence_refs: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


class ReportRenderer:
    def render_json(self, report: Report) -> str:
        return canonical_json({**asdict(report), "digest": report.digest})

    def render_html(self, report: Report) -> str:
        sections = []
        for name, value in report.sections.items():
            sections.append(
                f"<section><h2>{html.escape(str(name))}</h2>"
                f"<pre>{html.escape(json.dumps(value, ensure_ascii=False, indent=2))}</pre></section>"
            )
        limitations = "".join(f"<li>{html.escape(item)}</li>" for item in report.limitations)
        return (
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width'><title>"
            + html.escape(report.title)
            + "</title></head><body><main><h1>"
            + html.escape(report.title)
            + "</h1>"
            + "".join(sections)
            + f"<h2>Limitations</h2><ul>{limitations}</ul>"
            + f"<footer>Report digest: {report.digest}</footer></main></body></html>"
        )
