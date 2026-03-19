from __future__ import annotations

import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from alfa.console.demo import run_selected_scenes


def test_demo_block_scene_is_blocked_by_guard():
    results = run_selected_scenes(["block"])

    assert len(results) == 1
    assert results[0]["scene"] == "block"
    assert results[0]["guard"]["allowed"] is False
    assert results[0]["guard"]["mode"] == "escalate"
    assert results[0]["guard"]["approved_plugin"] == "script_runner"


def test_demo_approve_scene_executes_script_runner():
    results = run_selected_scenes(["approve"])

    assert len(results) == 1
    assert results[0]["scene"] == "approve"
    assert results[0]["guard"]["allowed"] is True
    assert results[0]["execution"]["plugin"] == "script_runner"


def test_demo_notes_scene_returns_seeded_notes():
    results = run_selected_scenes(["notes"])

    assert len(results) == 1
    assert results[0]["scene"] == "notes"
    assert results[0]["guard"]["allowed"] is True
    assert results[0]["execution"]["plugin"] == "notes_lookup"
    assert results[0]["execution"]["notes_count"] == 3
