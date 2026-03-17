from __future__ import annotations

from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException


def build_client(kubeconfig: str | None = None) -> client.ApiClient:
    """Load kubeconfig (file or in-cluster), return an ApiClient."""
    try:
        config.load_kube_config(config_file=kubeconfig)
    except ConfigException:
        config.load_incluster_config()
    return client.ApiClient()


def current_cluster_name(kubeconfig: str | None = None) -> str:
    try:
        contexts, active = config.list_kube_config_contexts(config_file=kubeconfig)
        return active.get("name", "unknown") if active else "unknown"
    except Exception:
        return "in-cluster"
