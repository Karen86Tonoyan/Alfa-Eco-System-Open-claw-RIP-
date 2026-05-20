from __future__ import annotations

from dataclasses import dataclass

from .backends.registry import BackendRegistry, build_public_backend_registry
from .console.service import ALFAConsole
from .core.brain import ALFACoreBrain
from .guard.cerber import CerberGuard
from .guard.guardian import AuditStore, BrainLinker, GuardianEpistemicGate
from .memory.layer import MemoryLayer
from .plugins.registry import PluginRegistry, build_builtin_registry
from .voice.gateway import VoiceGateway


@dataclass
class ALFAEcosystem:
    core: ALFACoreBrain
    voice: VoiceGateway
    plugins: PluginRegistry
    guard: CerberGuard
    memory: MemoryLayer
    console: ALFAConsole
    backends: BackendRegistry


def build_public_ecosystem() -> ALFAEcosystem:
    memory = MemoryLayer()
    plugins = build_builtin_registry()
    guard = CerberGuard(epistemic_gate=GuardianEpistemicGate())
    audit_store = AuditStore(memory=memory)
    brain_linker = BrainLinker()
    core = ALFACoreBrain()
    voice = VoiceGateway()
    backends = build_public_backend_registry()
    console = ALFAConsole(
        core=core,
        guard=guard,
        plugins=plugins,
        memory=memory,
        audit_store=audit_store,
        brain_linker=brain_linker,
    )
    return ALFAEcosystem(
        core=core,
        voice=voice,
        plugins=plugins,
        guard=guard,
        memory=memory,
        console=console,
        backends=backends,
    )

