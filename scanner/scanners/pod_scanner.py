from __future__ import annotations

from kubernetes import client as k8s_client

from scanner.models import ScanResult
from scanner.scanners.base import BaseScan
from scanner.utils.k8s_helpers import list_all_pods
from scanner.checks.pod_checks import (
    check_host_network,
    check_host_pid,
    check_host_ipc,
    check_pod_security_context,
    check_host_path_volume,
    check_automount_service_account_token,
    check_privileged,
    check_root_user,
    check_resource_limits,
    check_readonly_rootfs,
    check_privilege_escalation,
    check_image_tag,
    check_dangerous_caps,
    check_seccomp,
    check_no_liveness_probe,
    check_no_readiness_probe,
    check_sensitive_env_vars,
    check_host_port,
    check_capabilities_not_dropped,
    check_image_pull_policy,
)

POD_LEVEL_CHECKS = [
    check_host_network,
    check_host_pid,
    check_host_ipc,
    check_pod_security_context,
    check_host_path_volume,
    check_automount_service_account_token,
]

CONTAINER_LEVEL_CHECKS = [
    check_privileged,
    check_root_user,
    check_resource_limits,
    check_readonly_rootfs,
    check_privilege_escalation,
    check_image_tag,
    check_dangerous_caps,
    check_seccomp,
    check_no_liveness_probe,
    check_no_readiness_probe,
    check_sensitive_env_vars,
    check_host_port,
    check_capabilities_not_dropped,
    check_image_pull_policy,
]


class PodScanner(BaseScan):
    def run(self) -> ScanResult:
        result = ScanResult()
        v1 = k8s_client.CoreV1Api(self.api_client)
        pods = list_all_pods(v1, self.namespaces)

        for pod in pods:
            result.scanned_pods += 1
            pod_dict = pod.to_dict()

            for check in POD_LEVEL_CHECKS:
                finding = check(pod_dict)
                if finding:
                    result.findings.append(finding)

            for container in pod_dict.get("spec", {}).get("containers") or []:
                for check in CONTAINER_LEVEL_CHECKS:
                    finding = check(pod_dict, container)
                    if finding:
                        result.findings.append(finding)

            # Also check init containers
            for container in pod_dict.get("spec", {}).get("init_containers") or []:
                for check in CONTAINER_LEVEL_CHECKS:
                    finding = check(pod_dict, container)
                    if finding:
                        result.findings.append(finding)

        return result
