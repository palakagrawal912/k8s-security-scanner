# k8s-security-scanner

A Python CLI tool that scans Kubernetes clusters for security misconfigurations across pods and RBAC resources.

## Features

- **24 pod checks** — privileged containers, host namespaces, root users, missing resource limits, writable filesystems, dangerous capabilities, plaintext secrets in env vars, and more
- **20 RBAC checks** — cluster-admin bindings, wildcard permissions, secrets access, workload injection vectors, privilege escalation paths, anonymous bindings, and more
- **Rich terminal output** — color-coded findings table sorted by severity
- **JSON report** — machine-readable output for CI pipelines
- **CI-friendly exit codes** — exits `1` when CRITICAL or HIGH findings are detected

## Installation

```bash
git clone https://github.com/palakagrawal912/k8s-security-scanner.git
cd k8s-security-scanner
pip install -r requirements.txt
```

## Usage

```bash
# Scan all namespaces
python -m scanner.cli

# Scan specific namespace(s)
python -m scanner.cli -n default -n kube-system

# Output console + JSON report
python -m scanner.cli -o both --output-file report.json

# Skip noisy checks
python -m scanner.cli --skip-check RBAC-019 --skip-check POD-014

# Use a specific kubeconfig
python -m scanner.cli --kubeconfig ~/.kube/my-cluster-config
```

## Example Output

```
╭─────────────────────────────────────────────────────────────╮
│ Kubernetes Security Scanner                                 │
│ Cluster: my-cluster | Pods: 42 | Roles: 84 | Bindings: 72  │
╰─────────────────────────────────────────────────────────────╯
┌────────────┬──────────┬──────────────────────────────────┬──────────────────────────────┐
│ Check ID   │ Severity │ Resource                         │ Title                        │
├────────────┼──────────┼──────────────────────────────────┼──────────────────────────────┤
│ RBAC-001   │ CRITICAL │ ClusterRoleBinding/dev-admin     │ Non-system subject bound to  │
│            │          │                                  │ cluster-admin                │
│ POD-001    │ CRITICAL │ Pod/default/nginx (container:    │ Privileged container         │
│            │          │ nginx)                           │                              │
│ POD-005    │ HIGH     │ Pod/default/api (container: app) │ Container may run as root    │
└────────────┴──────────┴──────────────────────────────────┴──────────────────────────────┘

Summary: CRITICAL: 2 | HIGH: 5 | MEDIUM: 8 | LOW: 3
FAIL — critical or high severity findings detected.
```

## Check Reference

### Pod Checks

| ID | Severity | Description |
|---|---|---|
| POD-001 | CRITICAL | Privileged container |
| POD-002 | HIGH | `hostNetwork` enabled |
| POD-003 | HIGH | `hostPID` enabled |
| POD-004 | HIGH | `hostIPC` enabled |
| POD-005 | HIGH | Container may run as root |
| POD-006 | MEDIUM | Missing resource limits |
| POD-008 | MEDIUM | Writable root filesystem |
| POD-009 | HIGH | Privilege escalation not disabled |
| POD-011 | MEDIUM | No pod-level `securityContext` |
| POD-012 | LOW | Image uses `:latest` tag or no tag |
| POD-013 | HIGH | Dangerous Linux capabilities added |
| POD-014 | LOW | No liveness probe |
| POD-015 | MEDIUM | No seccomp profile |
| POD-017 | HIGH | `hostPath` volume mounted |
| POD-019 | MEDIUM | Service account token auto-mounted |
| POD-020 | LOW | No readiness probe |
| POD-021 | HIGH | Sensitive value in plaintext env var |
| POD-022 | MEDIUM | Container exposes host port |
| POD-023 | MEDIUM | Linux capabilities not dropped |
| POD-024 | LOW | `imagePullPolicy` not `Always` for mutable image |

### RBAC Checks

| ID | Severity | Description |
|---|---|---|
| RBAC-001 | CRITICAL | Non-system subject bound to `cluster-admin` |
| RBAC-002 | HIGH | Wildcard verb (`*`) in role rule |
| RBAC-003 | HIGH | Wildcard resource (`*`) in role rule |
| RBAC-004 | HIGH | Wildcard apiGroup (`*`) in role rule |
| RBAC-005 | HIGH | Write access to `secrets` |
| RBAC-006 | HIGH | Access to `pods/exec` or `pods/attach` |
| RBAC-007 | MEDIUM | Read access to `secrets` |
| RBAC-008 | MEDIUM | Binding includes anonymous/unauthenticated subject |
| RBAC-010 | HIGH | Privilege escalation verbs (`escalate`, `bind`, `impersonate`) |
| RBAC-011 | MEDIUM | Can create/modify role bindings |
| RBAC-014 | HIGH | Access to `nodes/proxy` |
| RBAC-016 | HIGH | Write access to workload resources |
| RBAC-017 | MEDIUM | Write access to configmaps |
| RBAC-018 | HIGH | Can create service account tokens |
| RBAC-019 | LOW | Cluster-wide resource enumeration |
| RBAC-020 | MEDIUM | Default service account has role binding |

## CI Integration

The scanner exits with code `1` if any CRITICAL or HIGH findings are detected, making it suitable as a pipeline gate:

```yaml
# GitHub Actions example
- name: Scan Kubernetes cluster
  run: python -m scanner.cli --skip-check RBAC-019
```

Customize the failure threshold with `--fail-on`:

```bash
python -m scanner.cli --fail-on CRITICAL  # only fail on CRITICAL
```

## Running Tests

```bash
pytest tests/ -v
```

Tests run entirely offline using fixture JSON files — no cluster required.

## Requirements

- Python 3.9+
- `kubectl` configured with access to a cluster (or in-cluster service account)
