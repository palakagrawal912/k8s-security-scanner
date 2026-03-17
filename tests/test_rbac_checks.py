import json
from pathlib import Path

import pytest

from scanner.checks.rbac_checks import (
    check_cluster_admin_binding,
    check_anonymous_binding,
    check_wildcard_permissions,
    check_secrets_access,
    check_exec_attach_access,
    check_escalation_permissions,
    check_binding_manipulation,
    check_nodes_proxy,
)
from scanner.models import Severity

FIXTURES = Path(__file__).parent / "fixtures" / "rbac"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ── Cluster-admin binding ─────────────────────────────────────────────────────

def test_cluster_admin_binding_detected():
    binding = load("cluster_admin_binding.json")
    findings = check_cluster_admin_binding(binding)
    assert len(findings) == 1
    assert findings[0].check_id == "RBAC-001"
    assert findings[0].severity == Severity.CRITICAL


def test_system_account_cluster_admin_ignored():
    binding = {
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "system-admin"},
        "roleRef": {"name": "cluster-admin"},
        "subjects": [{"kind": "ServiceAccount", "name": "system:serviceaccount:kube-system:default"}],
    }
    findings = check_cluster_admin_binding(binding)
    assert findings == []


# ── Wildcard permissions ──────────────────────────────────────────────────────

def test_wildcard_role_detected():
    role = load("wildcard_role.json")
    findings = check_wildcard_permissions(role)
    check_ids = {f.check_id for f in findings}
    assert "RBAC-002" in check_ids  # wildcard verb
    assert "RBAC-003" in check_ids  # wildcard resource
    assert "RBAC-004" in check_ids  # wildcard apiGroup


def test_compliant_role_no_wildcards():
    role = load("compliant_role.json")
    findings = check_wildcard_permissions(role)
    assert findings == []


# ── Secrets access ────────────────────────────────────────────────────────────

def test_write_secrets_detected():
    role = {
        "kind": "Role",
        "metadata": {"name": "secret-writer", "namespace": "default"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create", "update"]}],
    }
    findings = check_secrets_access(role)
    assert any(f.check_id == "RBAC-005" for f in findings)


def test_read_secrets_detected():
    role = {
        "kind": "Role",
        "metadata": {"name": "secret-reader", "namespace": "default"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}],
    }
    findings = check_secrets_access(role)
    assert any(f.check_id == "RBAC-007" for f in findings)


# ── Exec/attach ───────────────────────────────────────────────────────────────

def test_pods_exec_detected():
    role = {
        "kind": "Role",
        "metadata": {"name": "exec-role", "namespace": "default"},
        "rules": [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}],
    }
    findings = check_exec_attach_access(role)
    assert any(f.check_id == "RBAC-006" for f in findings)


# ── Escalation verbs ──────────────────────────────────────────────────────────

def test_escalation_verb_detected():
    role = {
        "kind": "ClusterRole",
        "metadata": {"name": "escalator"},
        "rules": [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["escalate"]}],
    }
    findings = check_escalation_permissions(role)
    assert any(f.check_id == "RBAC-010" for f in findings)


# ── Anonymous binding ─────────────────────────────────────────────────────────

def test_anonymous_binding_detected():
    binding = {
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "anon-binding"},
        "roleRef": {"name": "view"},
        "subjects": [{"kind": "Group", "name": "system:unauthenticated"}],
    }
    finding = check_anonymous_binding(binding)
    assert finding is not None
    assert finding.check_id == "RBAC-008"


# ── nodes/proxy ───────────────────────────────────────────────────────────────

def test_nodes_proxy_detected():
    role = {
        "kind": "ClusterRole",
        "metadata": {"name": "node-proxier"},
        "rules": [{"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get", "create"]}],
    }
    findings = check_nodes_proxy(role)
    assert any(f.check_id == "RBAC-014" for f in findings)
