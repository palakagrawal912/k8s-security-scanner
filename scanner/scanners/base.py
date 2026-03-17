from __future__ import annotations

from abc import ABC, abstractmethod
from kubernetes import client as k8s_client
from scanner.models import ScanResult


class BaseScan(ABC):
    def __init__(self, api_client: k8s_client.ApiClient, namespaces: list[str] | None = None):
        self.api_client = api_client
        self.namespaces = namespaces

    @abstractmethod
    def run(self) -> ScanResult:
        ...
