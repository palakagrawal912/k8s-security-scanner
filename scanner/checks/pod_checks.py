"""Pure-function pod security checks. Inputs are plain dicts (K8s API objects)."""
from __future__ import annotations

from typing import Optional

from scanner.models import Finding, Severity

DANGEROUS_CAPS = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "SYS_RAWIO", "NET_RAW", "SYS_CHROOT", "AUDIT_WRITE",
}

SENSITIVE_ENV_KEYWORDS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "auth", "credential", "private_key", "access_key", "aws_secret",
}


def _res(pod: dict) -> str:
    m = pod.get("metadata", {})
    return f"Pod/{m.get('namespace', '')}/{m.get('name', '')}"


# ── Pod-level checks ──────────────────────────────────────────────────────────

def check_host_network(pod: dict) -> Optional[Finding]:
    if pod.get("spec", {}).get("hostNetwork") is True:
        return Finding(
            check_id="POD-002",
            severity=Severity.HIGH,
            resource=_res(pod),
            namespace=pod.get("metadata", {}).get("namespace"),
            title="hostNetwork enabled",
            detail="Pod shares the host's network namespace.",
            remediation="Remove spec.hostNetwork or set it to false.",
        )


def check_host_pid(pod: dict) -> Optional[Finding]:
    if pod.get("spec", {}).get("hostPID") is True:
        return Finding(
            check_id="POD-003",
            severity=Severity.HIGH,
            resource=_res(pod),
            namespace=pod.get("metadata", {}).get("namespace"),
            title="hostPID enabled",
            detail="Pod shares the host's PID namespace.",
            remediation="Remove spec.hostPID or set it to false.",
        )


def check_host_ipc(pod: dict) -> Optional[Finding]:
    if pod.get("spec", {}).get("hostIPC") is True:
        return Finding(
            check_id="POD-004",
            severity=Severity.HIGH,
            resource=_res(pod),
            namespace=pod.get("metadata", {}).get("namespace"),
            title="hostIPC enabled",
            detail="Pod shares the host's IPC namespace.",
            remediation="Remove spec.hostIPC or set it to false.",
        )


def check_pod_security_context(pod: dict) -> Optional[Finding]:
    if not pod.get("spec", {}).get("securityContext"):
        return Finding(
            check_id="POD-011",
            severity=Severity.MEDIUM,
            resource=_res(pod),
            namespace=pod.get("metadata", {}).get("namespace"),
            title="No pod-level securityContext",
            detail="Pod is missing spec.securityContext.",
            remediation="Add spec.securityContext with runAsNonRoot: true and seccompProfile.",
        )


def check_host_path_volume(pod: dict) -> Optional[Finding]:
    for vol in pod.get("spec", {}).get("volumes") or []:
        if "hostPath" in vol:
            return Finding(
                check_id="POD-017",
                severity=Severity.HIGH,
                resource=_res(pod),
                namespace=pod.get("metadata", {}).get("namespace"),
                title="hostPath volume mounted",
                detail=f"Volume '{vol.get('name')}' mounts a host path: {vol['hostPath'].get('path')}.",
                remediation="Use emptyDir, configMap, or persistent volumes instead of hostPath.",
            )


# ── Container-level checks ────────────────────────────────────────────────────

def check_privileged(pod: dict, container: dict) -> Optional[Finding]:
    sc = container.get("securityContext") or {}
    if sc.get("privileged") is True:
        return Finding(
            check_id="POD-001",
            severity=Severity.CRITICAL,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="Privileged container",
            detail=f"Container '{container['name']}' runs in privileged mode.",
            remediation="Set securityContext.privileged: false.",
        )


def check_root_user(pod: dict, container: dict) -> Optional[Finding]:
    sc = container.get("securityContext") or {}
    pod_sc = pod.get("spec", {}).get("securityContext") or {}
    run_as_root = sc.get("runAsUser") == 0
    non_root_unset = sc.get("runAsNonRoot") is not True and pod_sc.get("runAsNonRoot") is not True
    if run_as_root or (non_root_unset and sc.get("runAsUser") is None):
        return Finding(
            check_id="POD-005",
            severity=Severity.HIGH,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="Container may run as root",
            detail="runAsNonRoot is not set to true and runAsUser is not specified.",
            remediation="Set securityContext.runAsNonRoot: true or securityContext.runAsUser to a non-zero UID.",
        )


def check_resource_limits(pod: dict, container: dict) -> Optional[Finding]:
    resources = container.get("resources") or {}
    limits = resources.get("limits") or {}
    if not limits.get("cpu") or not limits.get("memory"):
        return Finding(
            check_id="POD-006",
            severity=Severity.MEDIUM,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="Missing resource limits",
            detail="Container is missing CPU and/or memory limits.",
            remediation="Set resources.limits.cpu and resources.limits.memory.",
        )


def check_readonly_rootfs(pod: dict, container: dict) -> Optional[Finding]:
    sc = container.get("securityContext") or {}
    if sc.get("readOnlyRootFilesystem") is not True:
        return Finding(
            check_id="POD-008",
            severity=Severity.MEDIUM,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="Writable root filesystem",
            detail="readOnlyRootFilesystem is not set to true.",
            remediation="Set securityContext.readOnlyRootFilesystem: true.",
        )


def check_privilege_escalation(pod: dict, container: dict) -> Optional[Finding]:
    sc = container.get("securityContext") or {}
    if sc.get("allowPrivilegeEscalation") is not False:
        return Finding(
            check_id="POD-009",
            severity=Severity.HIGH,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="Privilege escalation not disabled",
            detail="allowPrivilegeEscalation is not explicitly set to false.",
            remediation="Set securityContext.allowPrivilegeEscalation: false.",
        )


def check_image_tag(pod: dict, container: dict) -> Optional[Finding]:
    image = container.get("image", "")
    if ":" not in image or image.endswith(":latest"):
        return Finding(
            check_id="POD-012",
            severity=Severity.LOW,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="Image uses :latest tag or no tag",
            detail=f"Image '{image}' is not pinned to a specific version.",
            remediation="Pin the image to a specific immutable digest or version tag.",
        )


def check_dangerous_caps(pod: dict, container: dict) -> Optional[Finding]:
    sc = container.get("securityContext") or {}
    caps = sc.get("capabilities") or {}
    added = {c.upper() for c in (caps.get("add") or [])}
    dangerous = added & DANGEROUS_CAPS
    if dangerous:
        return Finding(
            check_id="POD-013",
            severity=Severity.HIGH,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="Dangerous Linux capabilities added",
            detail=f"Container adds risky capabilities: {', '.join(sorted(dangerous))}.",
            remediation="Remove dangerous capabilities from securityContext.capabilities.add.",
        )


def check_seccomp(pod: dict, container: dict) -> Optional[Finding]:
    sc = container.get("securityContext") or {}
    pod_sc = pod.get("spec", {}).get("securityContext") or {}
    has_seccomp = (
        sc.get("seccompProfile") is not None
        or pod_sc.get("seccompProfile") is not None
    )
    if not has_seccomp:
        return Finding(
            check_id="POD-015",
            severity=Severity.MEDIUM,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="No seccomp profile",
            detail="seccompProfile is not set at container or pod level.",
            remediation="Set securityContext.seccompProfile.type to RuntimeDefault or Localhost.",
        )


# ── New pod-level checks ──────────────────────────────────────────────────────

def check_automount_service_account_token(pod: dict) -> Optional[Finding]:
    """POD-019: Service account token auto-mounted."""
    spec = pod.get("spec", {})
    if spec.get("automountServiceAccountToken") is not False:
        return Finding(
            check_id="POD-019",
            severity=Severity.MEDIUM,
            resource=_res(pod),
            namespace=pod.get("metadata", {}).get("namespace"),
            title="Service account token auto-mounted",
            detail="automountServiceAccountToken is not explicitly set to false.",
            remediation="Set spec.automountServiceAccountToken: false if the pod does not need API access.",
        )


def check_no_liveness_probe(pod: dict, container: dict) -> Optional[Finding]:
    """POD-014: No liveness probe."""
    if not container.get("livenessProbe"):
        return Finding(
            check_id="POD-014",
            severity=Severity.LOW,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="No liveness probe defined",
            detail=f"Container '{container['name']}' has no livenessProbe.",
            remediation="Add a livenessProbe so Kubernetes can restart unhealthy containers.",
        )


def check_no_readiness_probe(pod: dict, container: dict) -> Optional[Finding]:
    """POD-020: No readiness probe."""
    if not container.get("readinessProbe"):
        return Finding(
            check_id="POD-020",
            severity=Severity.LOW,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="No readiness probe defined",
            detail=f"Container '{container['name']}' has no readinessProbe.",
            remediation="Add a readinessProbe to prevent traffic routing to unready containers.",
        )


def check_sensitive_env_vars(pod: dict, container: dict) -> Optional[Finding]:
    """POD-021: Plaintext sensitive values in env vars."""
    for env in container.get("env") or []:
        name = (env.get("name") or "").lower()
        value = env.get("value")
        # Only flag direct value= entries — valueFrom (secretKeyRef) is fine
        if value is not None and any(kw in name for kw in SENSITIVE_ENV_KEYWORDS):
            return Finding(
                check_id="POD-021",
                severity=Severity.HIGH,
                resource=f"{_res(pod)} (container: {container['name']})",
                namespace=pod.get("metadata", {}).get("namespace"),
                title="Sensitive value in plaintext env var",
                detail=f"Env var '{env.get('name')}' appears to contain a sensitive value in plaintext.",
                remediation="Use secretKeyRef or a secrets manager instead of hardcoding sensitive values.",
            )


def check_host_port(pod: dict, container: dict) -> Optional[Finding]:
    """POD-022: Container exposes a host port."""
    for port in container.get("ports") or []:
        if port.get("hostPort"):
            return Finding(
                check_id="POD-022",
                severity=Severity.MEDIUM,
                resource=f"{_res(pod)} (container: {container['name']})",
                namespace=pod.get("metadata", {}).get("namespace"),
                title="Container exposes host port",
                detail=f"Port {port.get('containerPort')} is mapped to host port {port.get('hostPort')}.",
                remediation="Remove hostPort and use a Service or Ingress for external access.",
            )


def check_capabilities_not_dropped(pod: dict, container: dict) -> Optional[Finding]:
    """POD-023: No capability drop — especially ALL."""
    sc = container.get("securityContext") or {}
    caps = sc.get("capabilities") or {}
    dropped = [c.upper() for c in (caps.get("drop") or [])]
    if "ALL" not in dropped:
        return Finding(
            check_id="POD-023",
            severity=Severity.MEDIUM,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="Capabilities not dropped",
            detail="securityContext.capabilities.drop does not include ALL.",
            remediation="Add securityContext.capabilities.drop: [ALL] and only add back what is needed.",
        )


def check_image_pull_policy(pod: dict, container: dict) -> Optional[Finding]:
    """POD-024: imagePullPolicy not Always for mutable tags."""
    image = container.get("image", "")
    policy = container.get("imagePullPolicy", "")
    is_mutable = ":" not in image or image.endswith(":latest") or "@sha256:" not in image
    if is_mutable and policy != "Always":
        return Finding(
            check_id="POD-024",
            severity=Severity.LOW,
            resource=f"{_res(pod)} (container: {container['name']})",
            namespace=pod.get("metadata", {}).get("namespace"),
            title="imagePullPolicy not Always for mutable image",
            detail=f"Image '{image}' uses a mutable tag but imagePullPolicy is '{policy or 'IfNotPresent'}'.",
            remediation="Set imagePullPolicy: Always or pin the image to an immutable digest.",
        )
