from __future__ import annotations

import sys
from typing import Optional

import typer

app = typer.Typer(help="Kubernetes security scanner — pods and RBAC.")


@app.command()
def scan(
    namespace: Optional[list[str]] = typer.Option(
        None, "--namespace", "-n", help="Namespace(s) to scan. Defaults to all namespaces."
    ),
    kubeconfig: Optional[str] = typer.Option(
        None, "--kubeconfig", "-k", help="Path to kubeconfig file. Defaults to ~/.kube/config."
    ),
    output: str = typer.Option(
        "console", "--output", "-o", help="Output format: console | json | both"
    ),
    output_file: str = typer.Option(
        "report.json", "--output-file", help="Path for JSON report output."
    ),
    skip_check: Optional[list[str]] = typer.Option(
        None, "--skip-check", help="Check IDs to skip (e.g. POD-014)."
    ),
    fail_on: Optional[list[str]] = typer.Option(
        None, "--fail-on", help="Severity levels that cause exit code 1 (default: CRITICAL HIGH)."
    ),
) -> None:
    from scanner.runner import ScanRunner

    runner = ScanRunner(
        namespaces=namespace or None,
        kubeconfig=kubeconfig,
        output=output,
        output_file=output_file,
        skip_checks=skip_check or [],
        fail_on=fail_on or ["CRITICAL", "HIGH"],
    )
    sys.exit(runner.run())


if __name__ == "__main__":
    app()
