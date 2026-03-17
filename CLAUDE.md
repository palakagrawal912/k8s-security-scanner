# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_pod_checks.py -v

# Run a single test by name
python -m pytest tests/test_pod_checks.py::test_privileged_container_detected -v

# Scan all namespaces (must be in k8s-security-scanner/ directory)
python -m scanner.cli -o both

# Scan specific namespace(s)
python -m scanner.cli -n default -n kube-system

# Skip specific checks
python -m scanner.cli --skip-check RBAC-019 --skip-check POD-014

# Console output only (default)
python -m scanner.cli

# JSON report only
python -m scanner.cli -o json --output-file report.json
```

> Note: the CLI entry point is `python -m scanner.cli` (not `python -m scanner.cli scan`) — Typer treats the single `@app.command()` as the root command.

## Architecture

The scanner follows a strict layered design where **check functions are pure** (no K8s imports, dict in → `Finding` out), making all security logic unit-testable offline without a cluster.

```
CLI (cli.py)
  └── ScanRunner (runner.py)          # orchestrates everything
        ├── PodScanner                # calls K8s API, feeds dicts to checks
        ├── RBACScanner               # calls K8s API, feeds dicts to checks
        ├── ConsoleReporter           # Rich colored table output
        └── JsonReporter              # structured JSON file
```

### Key design decisions

**`scanner/checks/`** — Pure functions only. Each check accepts a raw dict (K8s API object) and returns `Optional[Finding]` or `list[Finding]`. Zero network I/O. This is where all security logic lives and where new checks should be added.

**`scanner/scanners/`** — Owns K8s API calls via `kubernetes` Python client. Iterates resources, calls check functions, aggregates into `ScanResult`. Pod-level checks (e.g. `hostNetwork`) take just the pod dict; container-level checks take both pod dict and container dict (needed for resource path in `Finding`).

**`scanner/models.py`** — The single `Finding` dataclass flows through everything. Add fields here only if reporters need them.

**`scanner/utils/k8s_helpers.py`** — All pagination logic is here. Scanners call `list_all_pods()` / `list_all_roles()` etc. and get flat lists back.

### Adding a new check

1. Add the pure function to `scanner/checks/pod_checks.py` or `rbac_checks.py` with the next available check ID (POD-0xx / RBAC-0xx).
2. Add it to the appropriate list in `scanner/scanners/pod_scanner.py` or `rbac_scanner.py` (`POD_LEVEL_CHECKS`, `CONTAINER_LEVEL_CHECKS`, `ROLE_CHECKS`, or `BINDING_SINGLE_CHECKS`).
3. Add a fixture and test in `tests/`.

### Check ID reference

**Pod checks:** POD-001 (privileged) through POD-024 (imagePullPolicy). Next available: POD-025.
**RBAC checks:** RBAC-001 (cluster-admin binding) through RBAC-020 (default SA binding). Next available: RBAC-021.

### Python version

The codebase runs on Python 3.9 (system Anaconda install). Use `from __future__ import annotations` at the top of any file that uses `list[str] | None` or other 3.10+ union type syntax at runtime — all existing files already do this.
