from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .base import BasePlugin, PluginSpec
from .builtin import NotesLookupPlugin, ScriptRunnerPlugin, WebLookupPlugin


@dataclass
class PluginRegistry:
    plugins: dict[str, BasePlugin] = field(default_factory=dict)

    def register(self, plugin: BasePlugin) -> None:
        self.plugins[plugin.spec.name] = plugin

    def get(self, name: str | None) -> BasePlugin | None:
        if not name:
            return None
        return self.plugins.get(name)

    def spec(self, name: str | None) -> PluginSpec | None:
        plugin = self.get(name)
        return plugin.spec if plugin else None

    def list_specs(self) -> list[dict[str, Any]]:
        return [plugin.spec.to_dict() for plugin in self.plugins.values()]

    def execute(
        self,
        name: str,
        text: str,
        *,
        session_id: str,
        user_id: str,
        memory: Any,
    ) -> dict[str, Any]:
        plugin = self.plugins[name]
        return plugin.execute(text, session_id=session_id, user_id=user_id, memory=memory)


def build_builtin_registry() -> PluginRegistry:
    registry = PluginRegistry()
    registry.register(WebLookupPlugin())
    registry.register(NotesLookupPlugin())
    registry.register(ScriptRunnerPlugin())
    return registry

