from __future__ import annotations

import json
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from alfa.memory.claude_image_history import collect_prompt_pack, extract_history_fragments


def test_extract_history_prefers_projects_and_paste_cache(tmp_path):
    claude_dir = tmp_path / ".claude"
    projects = claude_dir / "projects" / "demo"
    paste_cache = claude_dir / "paste-cache"
    projects.mkdir(parents=True)
    paste_cache.mkdir(parents=True)

    history = claude_dir / "history.jsonl"
    history.write_text(
        json.dumps(
            {
                "display": "[Pasted text #1 +5 lines]",
                "timestamp": 1_778_003_377_603,
                "sessionId": "hist-session",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    project_line = {
        "timestamp": "2026-05-20T10:00:00Z",
        "sessionId": "proj-session",
        "message": {
            "role": "user",
            "content": (
                "Midjourney prompt:\n"
                "cinematic portrait, Dave Hill realism, hyperdetail, moody contrast --ar 3:4"
            ),
        },
    }
    (projects / "session.jsonl").write_text(json.dumps(project_line) + "\n", encoding="utf-8")
    (paste_cache / "abc.txt").write_text("Identity lock system with 50 personal photographs", encoding="utf-8")

    fragments = extract_history_fragments(claude_dir)
    assert any("projects" in fragment.source_file for fragment in fragments)
    assert any("paste-cache" in fragment.source_file for fragment in fragments)
    assert not any(fragment.source_file.endswith(".claude.json") for fragment in fragments)


def test_collect_prompt_pack_renders_sections_and_confidence(tmp_path):
    claude_dir = tmp_path / ".claude"
    projects = claude_dir / "projects" / "demo"
    paste_cache = claude_dir / "paste-cache"
    projects.mkdir(parents=True)
    paste_cache.mkdir(parents=True)

    project_lines = [
        {
            "timestamp": "2026-05-20T10:00:00Z",
            "sessionId": "proj-session",
            "attachment": {
                "type": "queued_command",
                "prompt": (
                    "Midjourney prompt:\n"
                    "cinematic portrait, Midjourney, Dave Hill realism, hyperdetail, hard rim light --ar 3:4"
                ),
            },
        },
        {
            "timestamp": "2026-05-20T10:05:00Z",
            "sessionId": "proj-session",
            "message": {
                "role": "user",
                "content": "Identity lock setup, 50 personal photographs, consistent face geometry",
            },
        },
    ]
    (projects / "session.jsonl").write_text(
        "\n".join(json.dumps(line) for line in project_lines) + "\n",
        encoding="utf-8",
    )
    (claude_dir / "history.jsonl").write_text("", encoding="utf-8")
    (paste_cache / "abc.txt").write_text("Flux batch prompt for realism and identity lock", encoding="utf-8")

    _, candidates, rendered = collect_prompt_pack(claude_dir)

    assert candidates
    assert "## Core Midjourney prompts" in rendered
    assert "## Gamma realism / Dave Hill style prompts" in rendered
    assert "## Identity-lock setup" in rendered
    assert "`exact`" in rendered or "`partial`" in rendered or "`inferred`" in rendered
    assert "Appendix" in rendered
