from __future__ import annotations

from scanner.config import build_client, current_cluster_name
from scanner.models import ScanResult, Severity
from scanner.scanners.pod_scanner import PodScanner
from scanner.scanners.rbac_scanner import RBACScanner
from scanner.reporter.console import ConsoleReporter
from scanner.reporter.json_reporter import JsonReporter


class ScanRunner:
    def __init__(
        self,
        namespaces: list[str] | None = None,
        kubeconfig: str | None = None,
        output: str = "console",
        output_file: str = "report.json",
        skip_checks: list[str] | None = None,
        fail_on: list[str] | None = None,
    ):
        self.namespaces = namespaces or None
        self.kubeconfig = kubeconfig
        self.output = output
        self.output_file = output_file
        self.skip_checks = set(skip_checks or [])
        self.fail_on_severities = {Severity(s) for s in (fail_on or ["CRITICAL", "HIGH"])}

    def run(self) -> int:
        api_client = build_client(self.kubeconfig)
        cluster_name = current_cluster_name(self.kubeconfig)

        result = ScanResult()
        for scanner_cls in [PodScanner, RBACScanner]:
            sub = scanner_cls(api_client, self.namespaces).run()
            result.findings.extend(sub.findings)
            result.scanned_pods += sub.scanned_pods
            result.scanned_roles += sub.scanned_roles
            result.scanned_bindings += sub.scanned_bindings

        ConsoleReporter().report(result, cluster_name=cluster_name, skip_checks=self.skip_checks)

        if self.output in ("json", "both"):
            JsonReporter(self.output_file).report(result, cluster_name=cluster_name)

        has_failures = any(
            f.severity in self.fail_on_severities
            for f in result.findings
            if f.check_id not in self.skip_checks
        )
        return 1 if has_failures else 0
