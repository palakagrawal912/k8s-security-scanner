"""K8s API helpers: pagination, namespace listing."""
from __future__ import annotations

from kubernetes import client


def list_all_pods(v1: client.CoreV1Api, namespaces: list[str] | None) -> list:
    pods = []
    if namespaces:
        for ns in namespaces:
            pods.extend(_paginate(lambda cont, ns=ns: v1.list_namespaced_pod(ns, _continue=cont)))
    else:
        pods.extend(_paginate(lambda cont: v1.list_pod_for_all_namespaces(_continue=cont)))
    return pods


def list_all_roles(rbac: client.RbacAuthorizationV1Api, namespaces: list[str] | None) -> list:
    roles = []
    if namespaces:
        for ns in namespaces:
            roles.extend(_paginate(lambda cont, ns=ns: rbac.list_namespaced_role(ns, _continue=cont)))
    else:
        roles.extend(_paginate(lambda cont: rbac.list_role_for_all_namespaces(_continue=cont)))
    return roles


def list_all_cluster_roles(rbac: client.RbacAuthorizationV1Api) -> list:
    return _paginate(lambda cont: rbac.list_cluster_role(_continue=cont))


def list_all_role_bindings(rbac: client.RbacAuthorizationV1Api, namespaces: list[str] | None) -> list:
    bindings = []
    if namespaces:
        for ns in namespaces:
            bindings.extend(_paginate(lambda cont, ns=ns: rbac.list_namespaced_role_binding(ns, _continue=cont)))
    else:
        bindings.extend(_paginate(lambda cont: rbac.list_role_binding_for_all_namespaces(_continue=cont)))
    return bindings


def list_all_cluster_role_bindings(rbac: client.RbacAuthorizationV1Api) -> list:
    return _paginate(lambda cont: rbac.list_cluster_role_binding(_continue=cont))


def _paginate(list_fn) -> list:
    items = []
    continuation = None
    while True:
        resp = list_fn(continuation)
        items.extend(resp.items)
        continuation = resp.metadata._continue  # type: ignore[union-attr]
        if not continuation:
            break
    return items
