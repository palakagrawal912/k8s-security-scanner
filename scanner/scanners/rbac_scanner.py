from __future__ import annotations

from kubernetes import client as k8s_client

from scanner.models import ScanResult
from scanner.scanners.base import BaseScan
from scanner.utils.k8s_helpers import (
    list_all_roles,
    list_all_cluster_roles,
    list_all_role_bindings,
    list_all_cluster_role_bindings,
)
from scanner.checks.rbac_checks import (
    check_cluster_admin_binding,
    check_anonymous_binding,
    check_wildcard_permissions,
    check_secrets_access,
    check_exec_attach_access,
    check_escalation_permissions,
    check_binding_manipulation,
    check_nodes_proxy,
    check_workload_injection,
    check_configmap_access,
    check_token_request,
    check_sensitive_resource_enumeration,
    check_default_sa_binding,
)

ROLE_CHECKS = [
    check_wildcard_permissions,
    check_secrets_access,
    check_exec_attach_access,
    check_escalation_permissions,
    check_binding_manipulation,
    check_nodes_proxy,
    check_workload_injection,
    check_configmap_access,
    check_token_request,
    check_sensitive_resource_enumeration,
]

BINDING_CHECKS = [
    check_cluster_admin_binding,
]

BINDING_SINGLE_CHECKS = [
    check_anonymous_binding,
    check_default_sa_binding,
]


class RBACScanner(BaseScan):
    def run(self) -> ScanResult:
        result = ScanResult()
        rbac = k8s_client.RbacAuthorizationV1Api(self.api_client)

        # Roles
        roles = list_all_roles(rbac, self.namespaces)
        cluster_roles = list_all_cluster_roles(rbac)
        result.scanned_roles = len(roles) + len(cluster_roles)

        for role in roles + cluster_roles:
            role_dict = role.to_dict()
            for check in ROLE_CHECKS:
                result.findings.extend(check(role_dict))

        # Bindings
        bindings = list_all_role_bindings(rbac, self.namespaces)
        cluster_bindings = list_all_cluster_role_bindings(rbac)
        result.scanned_bindings = len(bindings) + len(cluster_bindings)

        for binding in bindings + cluster_bindings:
            binding_dict = binding.to_dict()
            for check in BINDING_CHECKS:
                result.findings.extend(check(binding_dict))
            for check in BINDING_SINGLE_CHECKS:
                finding = check(binding_dict)
                if finding:
                    result.findings.append(finding)

        return result
