from __future__ import annotations

from .base import BackendSpec


class OllamaPreviewBackend:
    spec = BackendSpec(
        name="ollama_preview",
        deployment="local",
        transport="local_runtime",
        description="Public preview of the local model channel.",
        metadata={"visibility": "public_preview"},
    )


class CloudPreviewBackend:
    spec = BackendSpec(
        name="cloud_preview",
        deployment="cloud",
        transport="managed_endpoint",
        description="Public preview of the managed cloud model channel.",
        metadata={"visibility": "public_preview"},
    )

