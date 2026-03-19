from __future__ import annotations

import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from alfa.bootstrap import build_public_ecosystem
from alfa.shared.schemas import RequestEnvelope, SystemState


def test_information_request_routes_to_main_model():
    ecosystem = build_public_ecosystem()
    result = ecosystem.console.handle(
        RequestEnvelope(text="Wyjasnij czym jest control layer over LLMs.")
    )

    assert result["decision"]["route"]["route"] == "main_model"
    assert result["decision"]["state"] == SystemState.RESPOND.value
    assert result["guard"]["allowed"] is True


def test_source_request_uses_verification_path():
    ecosystem = build_public_ecosystem()
    result = ecosystem.console.handle(
        RequestEnvelope(
            text="Sprawdz najnowszy kurs dolara dzisiaj i podaj zrodla.",
            requested_plugin="web_lookup",
        )
    )

    assert result["decision"]["route"]["route"] == "verify"
    assert result["decision"]["state"] == SystemState.VERIFY.value
    assert result["guard"]["approved_plugin"] == "web_lookup"


def test_notes_plugin_reads_user_memory():
    ecosystem = build_public_ecosystem()
    ecosystem.memory.remember_user("u-1", "notes", ["Plan pitch deck", "Benchmark filters"])

    result = ecosystem.console.handle(
        RequestEnvelope(
            text="Pokaz moje notatki do pitch decku.",
            user_id="u-1",
            requested_plugin="notes_lookup",
        )
    )

    assert result["decision"]["route"]["route"] == "execute_plugin"
    assert result["execution"]["plugin"] == "notes_lookup"
    assert result["execution"]["notes_count"] == 2


def test_risky_script_requires_operator_review():
    ecosystem = build_public_ecosystem()
    result = ecosystem.console.handle(
        RequestEnvelope(
            text="Uruchom shell i usun stare pliki deploymentu.",
            requested_plugin="script_runner",
            source_trust="primary",
        )
    )

    assert result["decision"]["state"] == SystemState.ESCALATE.value
    assert result["guard"]["allowed"] is False
    assert result["guard"]["requires_confirmation"] is True


def test_operator_confirmed_script_can_execute():
    ecosystem = build_public_ecosystem()
    result = ecosystem.console.handle(
        RequestEnvelope(
            text="Uruchom zatwierdzony skrypt backupu.",
            requested_plugin="script_runner",
            source_trust="operator",
            metadata={"confirmed": True},
        )
    )

    assert result["decision"]["state"] == SystemState.EXECUTE.value
    assert result["guard"]["allowed"] is True
    assert result["execution"]["plugin"] == "script_runner"


def test_voice_gateway_is_separate_interface():
    ecosystem = build_public_ecosystem()
    request = ecosystem.voice.to_request("ALFA, sprawdz najnowsze newsy o AI.")
    result = ecosystem.console.handle(request)

    assert request.metadata["interface"] == "voice"
    assert result["decision"]["route"]["route"] == "verify"


def test_backends_show_local_and_cloud_modes():
    ecosystem = build_public_ecosystem()
    specs = ecosystem.backends.list_specs()

    names = {item["name"] for item in specs}
    deployments = {item["deployment"] for item in specs}

    assert names == {"ollama_preview", "cloud_preview"}
    assert deployments == {"local", "cloud"}

