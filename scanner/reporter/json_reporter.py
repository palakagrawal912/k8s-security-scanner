from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path

from scanner.models import ScanResult


class JsonReporter:
    def __init__(self, output_path: str):
        self.output_path = Path(output_path)

    def report(self, result: ScanResult, cluster_name: str = "unknown") -> None:
        summary = result.summary
        data = {
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "cluster": cluster_name,
            "summary": {
                "scanned_pods": result.scanned_pods,
                "scanned_roles": result.scanned_roles,
                "scanned_bindings": result.scanned_bindings,
                "findings_by_severity": {k.value: v for k, v in summary.items()},
            },
            "findings": [dataclasses.asdict(f) for f in result.findings],
        }
        self.output_path.write_text(json.dumps(data, indent=2, default=str))
