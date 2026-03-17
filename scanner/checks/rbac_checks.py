"""Pure-function RBAC security checks. Inputs are plain dicts (K8s API objects)."""
from __future__ import annotations

from typing import Optional

from scanner.models import Finding, Severity

RISKY_WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
ESCALATION_VERBS = {"escalate", "bind", "impersonate"}
SENSITIVE_RESOURCES = {"secrets", "pods/exec", "pods/attach", "nodes/proxy"}
ANONYMOUS_SUBJECTS = {"system:anonymous", "system:unauthenticated"}


def _role_resource(role: dict) -> str:
    kind = role.get("kind", "Role")
    name = role.get("metadata", {}).get("name", "")
    ns = role.get("metadata", {}).get("namespace")
    return f"{kind}/{ns}/{name}" if ns else f"{kind}/{name}"


def _binding_resource(binding: dict) -> str:
    kind = binding.get("kind", "RoleBinding")
    name = binding.get("metadata", {}).get("name", "")
    return f"{kind}/{name}"


# ── Binding checks ────────────────────────────────────────────────────────────

def check_cluster_admin_binding(binding: dict) -> list[Finding]:
    findings = []
    if binding.get("roleRef", {}).get("name") != "cluster-admin":
        return findings
    for subject in binding.get("subjects") or []:
        subj_name = subject.get("name", "")
        if subj_name.startswith("system:serviceaccount:kube-"):
            continue
        findings.append(Finding(
            check_id="RBAC-001",
            severity=Severity.CRITICAL,
            resource=_binding_resource(binding),
            namespace=binding.get("metadata", {}).get("namespace"),
            title="Non-system subject bound to cluster-admin",
            detail=f"Subject '{subj_name}' ({subject.get('kind')}) has cluster-admin.",
            remediation="Replace cluster-admin with a least-privilege role scoped to specific namespaces.",
        ))
    return findings


def check_anonymous_binding(binding: dict) -> Optional[Finding]:
    for subject in binding.get("subjects") or []:
        if subject.get("name") in ANONYMOUS_SUBJECTS:
            return Finding(
                check_id="RBAC-008",
                severity=Severity.MEDIUM,
                resource=_binding_resource(binding),
                namespace=binding.get("metadata", {}).get("namespace"),
                title="Binding includes anonymous/unauthenticated subject",
                detail=f"Subject '{subject.get('name')}' allows unauthenticated access.",
                remediation="Remove system:anonymous and system:unauthenticated from all bindings.",
            )


# ── Role / ClusterRole checks ─────────────────────────────────────────────────

def check_wildcard_permissions(role: dict) -> list[Finding]:
    findings = []
    resource_id = _role_resource(role)
    for rule in role.get("rules") or []:
        verbs = rule.get("verbs") or []
        resources = rule.get("resources") or []
        api_groups = rule.get("apiGroups") or []

        if "*" in verbs:
            findings.append(Finding(
                check_id="RBAC-002",
                severity=Severity.HIGH,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Wildcard verb in role rule",
                detail=f"Rule grants verb '*' on resources: {resources}.",
                remediation="Replace '*' verbs with the minimum required set.",
            ))
        if "*" in resources:
            findings.append(Finding(
                check_id="RBAC-003",
                severity=Severity.HIGH,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Wildcard resource in role rule",
                detail="Rule targets all resources ('*').",
                remediation="Scope rules to specific resource types.",
            ))
        if "*" in api_groups:
            findings.append(Finding(
                check_id="RBAC-004",
                severity=Severity.HIGH,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Wildcard apiGroup in role rule",
                detail="Rule covers all API groups ('*').",
                remediation="Scope rules to specific API groups.",
            ))
    return findings


def check_secrets_access(role: dict) -> list[Finding]:
    findings = []
    resource_id = _role_resource(role)
    for rule in role.get("rules") or []:
        resources = {r.lower() for r in (rule.get("resources") or [])}
        verbs = {v.lower() for v in (rule.get("verbs") or [])}
        if "secrets" not in resources and "*" not in resources:
            continue

        write_verbs = verbs & (RISKY_WRITE_VERBS | {"*"})
        if write_verbs:
            findings.append(Finding(
                check_id="RBAC-005",
                severity=Severity.HIGH,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Write access to secrets",
                detail=f"Rule grants {sorted(write_verbs)} on secrets.",
                remediation="Remove write permissions on secrets resource.",
            ))
        read_verbs = verbs & {"get", "list", "watch"}
        if read_verbs and not write_verbs:
            findings.append(Finding(
                check_id="RBAC-007",
                severity=Severity.MEDIUM,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Read access to secrets",
                detail=f"Rule grants {sorted(read_verbs)} on secrets.",
                remediation="Restrict secret access to only the specific secrets needed.",
            ))
    return findings


def check_exec_attach_access(role: dict) -> list[Finding]:
    findings = []
    resource_id = _role_resource(role)
    for rule in role.get("rules") or []:
        resources = {r.lower() for r in (rule.get("resources") or [])}
        verbs = {v.lower() for v in (rule.get("verbs") or [])}
        risky = resources & {"pods/exec", "pods/attach"}
        if risky and verbs:
            findings.append(Finding(
                check_id="RBAC-006",
                severity=Severity.HIGH,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title=f"Access to {' and '.join(sorted(risky))}",
                detail=f"Grants {sorted(verbs)} on {sorted(risky)} — remote code execution surface.",
                remediation="Remove access to pods/exec and pods/attach unless absolutely required.",
            ))
    return findings


def check_escalation_permissions(role: dict) -> list[Finding]:
    findings = []
    resource_id = _role_resource(role)
    for rule in role.get("rules") or []:
        verbs = {v.lower() for v in (rule.get("verbs") or [])}
        found = verbs & ESCALATION_VERBS
        if found:
            findings.append(Finding(
                check_id="RBAC-010",
                severity=Severity.HIGH,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Privilege escalation verbs present",
                detail=f"Rule contains escalation verbs: {sorted(found)}.",
                remediation="Remove escalate, bind, and impersonate verbs unless explicitly needed.",
            ))
    return findings


def check_binding_manipulation(role: dict) -> list[Finding]:
    findings = []
    resource_id = _role_resource(role)
    for rule in role.get("rules") or []:
        resources = {r.lower() for r in (rule.get("resources") or [])}
        verbs = {v.lower() for v in (rule.get("verbs") or [])}
        binding_resources = resources & {"rolebindings", "clusterrolebindings"}
        write_verbs = verbs & {"create", "patch", "update", "*"}
        if binding_resources and write_verbs:
            findings.append(Finding(
                check_id="RBAC-011",
                severity=Severity.MEDIUM,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Can create/modify role bindings",
                detail=f"Rule grants {sorted(write_verbs)} on {sorted(binding_resources)}.",
                remediation="Restrict ability to create or modify bindings — this is a privilege escalation path.",
            ))
    return findings


def check_nodes_proxy(role: dict) -> list[Finding]:
    findings = []
    resource_id = _role_resource(role)
    for rule in role.get("rules") or []:
        resources = {r.lower() for r in (rule.get("resources") or [])}
        verbs = {v.lower() for v in (rule.get("verbs") or [])}
        if "nodes/proxy" in resources and verbs:
            findings.append(Finding(
                check_id="RBAC-014",
                severity=Severity.HIGH,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Access to nodes/proxy",
                detail="nodes/proxy bypasses API server authorization — effectively root on nodes.",
                remediation="Remove nodes/proxy access entirely.",
            ))
    return findings


def check_workload_injection(role: dict) -> list[Finding]:
    """RBAC-016: Write access to workload resources — can inject malicious containers."""
    findings = []
    resource_id = _role_resource(role)
    workload_resources = {"pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs"}
    write_verbs = {"create", "update", "patch", "*"}
    for rule in role.get("rules") or []:
        resources = {r.lower() for r in (rule.get("resources") or [])}
        verbs = {v.lower() for v in (rule.get("verbs") or [])}
        matched = resources & workload_resources
        if matched and (verbs & write_verbs):
            findings.append(Finding(
                check_id="RBAC-016",
                severity=Severity.HIGH,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title=f"Write access to workload resources",
                detail=f"Can create/modify {sorted(matched)} — potential workload injection vector.",
                remediation="Restrict workload write permissions to only necessary namespaces and resource types.",
            ))
    return findings


def check_configmap_access(role: dict) -> list[Finding]:
    """RBAC-017: ConfigMaps often hold sensitive config — write access is risky."""
    findings = []
    resource_id = _role_resource(role)
    for rule in role.get("rules") or []:
        resources = {r.lower() for r in (rule.get("resources") or [])}
        verbs = {v.lower() for v in (rule.get("verbs") or [])}
        if "configmaps" not in resources and "*" not in resources:
            continue
        write_verbs = verbs & {"create", "update", "patch", "delete", "*"}
        if write_verbs:
            findings.append(Finding(
                check_id="RBAC-017",
                severity=Severity.MEDIUM,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Write access to configmaps",
                detail=f"Rule grants {sorted(write_verbs)} on configmaps — may contain sensitive config.",
                remediation="Restrict configmap write access; avoid storing secrets in configmaps.",
            ))
    return findings


def check_token_request(role: dict) -> list[Finding]:
    """RBAC-018: Can create service account tokens on demand."""
    findings = []
    resource_id = _role_resource(role)
    for rule in role.get("rules") or []:
        resources = {r.lower() for r in (rule.get("resources") or [])}
        verbs = {v.lower() for v in (rule.get("verbs") or [])}
        if "serviceaccounts/token" in resources and ("create" in verbs or "*" in verbs):
            findings.append(Finding(
                check_id="RBAC-018",
                severity=Severity.HIGH,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Can create service account tokens",
                detail="Permission to create serviceaccounts/token allows minting arbitrary tokens.",
                remediation="Remove serviceaccounts/token create permission unless required for token projection.",
            ))
    return findings


def check_sensitive_resource_enumeration(role: dict) -> list[Finding]:
    """RBAC-019: List/watch on sensitive resources leaks cluster topology."""
    findings = []
    resource_id = _role_resource(role)
    sensitive = {"nodes", "namespaces", "persistentvolumes", "clusterroles", "clusterrolebindings"}
    for rule in role.get("rules") or []:
        resources = {r.lower() for r in (rule.get("resources") or [])}
        verbs = {v.lower() for v in (rule.get("verbs") or [])}
        matched = resources & sensitive
        list_verbs = verbs & {"list", "watch", "*"}
        if matched and list_verbs:
            findings.append(Finding(
                check_id="RBAC-019",
                severity=Severity.LOW,
                resource=resource_id,
                namespace=role.get("metadata", {}).get("namespace"),
                title="Cluster-wide resource enumeration",
                detail=f"Can list/watch {sorted(matched)} — leaks cluster topology to attacker.",
                remediation="Scope list/watch permissions to only necessary resource types.",
            ))
    return findings


def check_default_sa_binding(binding: dict) -> Optional[Finding]:
    """RBAC-020: default service account has explicit role binding."""
    for subject in binding.get("subjects") or []:
        if (subject.get("kind") == "ServiceAccount"
                and subject.get("name") == "default"
                and subject.get("namespace") not in (None, "kube-system", "kube-public")):
            role_name = binding.get("roleRef", {}).get("name", "")
            return Finding(
                check_id="RBAC-020",
                severity=Severity.MEDIUM,
                resource=_binding_resource(binding),
                namespace=binding.get("metadata", {}).get("namespace"),
                title="Default service account has role binding",
                detail=f"The 'default' SA in namespace '{subject.get('namespace')}' is bound to '{role_name}'.",
                remediation="Create a dedicated service account for workloads instead of binding the default SA.",
            )
