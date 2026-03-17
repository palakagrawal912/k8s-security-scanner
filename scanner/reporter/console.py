from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from scanner.models import Finding, Severity, ScanResult

SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}

console = Console()


class ConsoleReporter:
    def report(self, result: ScanResult, cluster_name: str = "unknown",
               skip_checks: set[str] | None = None, min_severity: Severity | None = None) -> None:
        findings = result.findings
        if skip_checks:
            findings = [f for f in findings if f.check_id not in skip_checks]
        if min_severity:
            order = list(Severity)
            findings = [f for f in findings if order.index(f.severity) >= order.index(min_severity)]

        console.print()
        console.print(Panel(
            f"[bold]Kubernetes Security Scanner[/bold]\n"
            f"Cluster: [cyan]{cluster_name}[/cyan] | "
            f"Pods: [green]{result.scanned_pods}[/green] | "
            f"Roles: [green]{result.scanned_roles}[/green] | "
            f"Bindings: [green]{result.scanned_bindings}[/green]",
            expand=False,
        ))

        if not findings:
            console.print("\n[bold green]No findings — cluster looks clean![/bold green]\n")
            return

        table = Table(box=box.ROUNDED, show_lines=True)
        table.add_column("Check ID", style="bold", width=10)
        table.add_column("Severity", width=10)
        table.add_column("Resource", overflow="fold")
        table.add_column("Title")

        severity_order = {s: i for i, s in enumerate(reversed(list(Severity)))}
        sorted_findings = sorted(findings, key=lambda f: severity_order[f.severity])

        for f in sorted_findings:
            color = SEVERITY_COLOR[f.severity]
            table.add_row(
                f.check_id,
                f"[{color}]{f.severity.value}[/{color}]",
                f.resource,
                f.title,
            )

        console.print(table)

        # Summary
        summary = result.summary
        parts = []
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = summary.get(sev, 0)
            color = SEVERITY_COLOR[sev]
            parts.append(f"[{color}]{sev.value}: {count}[/{color}]")

        console.print(f"\nSummary: {' | '.join(parts)} | Total: {len(findings)}\n")

        if summary.get(Severity.CRITICAL, 0) > 0 or summary.get(Severity.HIGH, 0) > 0:
            console.print("[bold red]FAIL[/bold red] — critical or high severity findings detected.\n")
        else:
            console.print("[bold green]PASS[/bold green] — no critical or high severity findings.\n")
