import json
from pathlib import Path

import pytest

from scanner.checks.pod_checks import (
    check_host_network, check_host_pid, check_host_ipc,
    check_privileged, check_root_user, check_resource_limits,
    check_readonly_rootfs, check_privilege_escalation,
    check_image_tag, check_dangerous_caps, check_seccomp,
    check_pod_security_context, check_host_path_volume,
)
from scanner.models import Severity

FIXTURES = Path(__file__).parent / "fixtures" / "pods"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ── Privileged pod: should trigger many checks ────────────────────────────────

def test_host_network_detected():
    pod = load("privileged_pod.json")
    finding = check_host_network(pod)
    assert finding is not None
    assert finding.check_id == "POD-002"
    assert finding.severity == Severity.HIGH


def test_host_pid_detected():
    pod = load("privileged_pod.json")
    finding = check_host_pid(pod)
    assert finding is not None
    assert finding.check_id == "POD-003"


def test_privileged_container_detected():
    pod = load("privileged_pod.json")
    container = pod["spec"]["containers"][0]
    finding = check_privileged(pod, container)
    assert finding is not None
    assert finding.check_id == "POD-001"
    assert finding.severity == Severity.CRITICAL


def test_latest_image_detected():
    pod = load("privileged_pod.json")
    container = pod["spec"]["containers"][0]
    finding = check_image_tag(pod, container)
    assert finding is not None
    assert finding.check_id == "POD-012"


def test_dangerous_caps_detected():
    pod = load("privileged_pod.json")
    container = pod["spec"]["containers"][0]
    finding = check_dangerous_caps(pod, container)
    assert finding is not None
    assert finding.check_id == "POD-013"
    assert "SYS_ADMIN" in finding.detail or "NET_ADMIN" in finding.detail


# ── Compliant pod: should NOT trigger most checks ─────────────────────────────

def test_compliant_pod_no_host_network():
    pod = load("compliant_pod.json")
    assert check_host_network(pod) is None


def test_compliant_pod_no_privileged():
    pod = load("compliant_pod.json")
    container = pod["spec"]["containers"][0]
    assert check_privileged(pod, container) is None


def test_compliant_pod_no_image_tag():
    pod = load("compliant_pod.json")
    container = pod["spec"]["containers"][0]
    assert check_image_tag(pod, container) is None


def test_compliant_pod_has_resource_limits():
    pod = load("compliant_pod.json")
    container = pod["spec"]["containers"][0]
    assert check_resource_limits(pod, container) is None


def test_compliant_pod_readonly_rootfs():
    pod = load("compliant_pod.json")
    container = pod["spec"]["containers"][0]
    assert check_readonly_rootfs(pod, container) is None


def test_compliant_pod_privilege_escalation_disabled():
    pod = load("compliant_pod.json")
    container = pod["spec"]["containers"][0]
    assert check_privilege_escalation(pod, container) is None


def test_compliant_pod_seccomp():
    pod = load("compliant_pod.json")
    container = pod["spec"]["containers"][0]
    assert check_seccomp(pod, container) is None


# ── Inline edge cases ─────────────────────────────────────────────────────────

def test_host_path_volume_detected():
    pod = {
        "metadata": {"name": "p", "namespace": "default"},
        "spec": {
            "volumes": [{"name": "host-vol", "hostPath": {"path": "/etc"}}],
            "containers": [],
        },
    }
    finding = check_host_path_volume(pod)
    assert finding is not None
    assert finding.check_id == "POD-017"


def test_missing_resource_limits():
    pod = {"metadata": {"name": "p", "namespace": "default"}, "spec": {}}
    container = {"name": "app", "image": "myapp:1.0", "resources": {}}
    finding = check_resource_limits(pod, container)
    assert finding is not None
    assert finding.check_id == "POD-006"
