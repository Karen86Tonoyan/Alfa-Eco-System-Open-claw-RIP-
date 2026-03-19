from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .base import BackendSpec
from .builtin import CloudPreviewBackend, OllamaPreviewBackend


@dataclass
class BackendRegistry:
    backends: dict[str, BackendSpec] = field(default_factory=dict)

    def register(self, backend: Any) -> None:
        self.backends[backend.spec.name] = backend.spec

    def list_specs(self) -> list[dict[str, Any]]:
        return [spec.to_dict() for spec in self.backends.values()]


def build_public_backend_registry() -> BackendRegistry:
    registry = BackendRegistry()
    registry.register(OllamaPreviewBackend())
    registry.register(CloudPreviewBackend())
    return registry
