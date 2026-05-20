from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


TARGET_PATTERNS: dict[str, tuple[str, ...]] = {
    "midjourney": ("midjourney",),
    "gamma-realism": ("gamma realism", "gamma image"),
    "dave-hill": ("dave hill",),
    "realism": ("realism", "photorealistic", "photo realism"),
    "hyperdetail": ("hyperdetail", "hyper detail", "ultra detailed"),
    "identity-lock": ("identity lock",),
    "personal-photographs": ("personal photographs", "reference photos", "reference photographs"),
    "character-design": ("cinematic portrait", "portrait", "character"),
}

ANCHOR_TAGS = {
    "midjourney",
    "flux",
    "gamma-realism",
    "dave-hill",
    "realism",
    "hyperdetail",
    "identity-lock",
    "personal-photographs",
}

IMAGE_CONTEXT_TERMS = (
    "image",
    "prompt",
    "portrait",
    "photo",
    "photograph",
    "style",
    "render",
    "generation",
    "visual",
)

SKIP_ATTACHMENT_TYPES = {
    "skill_listing",
    "hook_success",
    "hook_additional_context",
    "permission-mode",
    "file-history-snapshot",
}

SKIP_TEXT_PATTERNS = (
    "Select-String -Path",
    "claude-image-history.txt",
    "AUDITSTORE",
    "AuditStore wiring",
    "systematic-debugging",
    "Traceback (most recent call last):",
    "UnicodeEncodeError:",
    "Exit code",
    "Co Ty widzisz jako REAL next?",
    "OPCJE:",
    "Tell me.",
)

SECTION_ORDER = (
    "Core Midjourney prompts",
    "Gamma realism / Dave Hill style prompts",
    "Identity-lock setup",
)


@dataclass(slots=True)
class SourceReference:
    source_file: str
    line_number: int | None
    session_id: str | None

    def label(self) -> str:
        line = f":{self.line_number}" if self.line_number else ""
        session = f" [{self.session_id}]" if self.session_id else ""
        return f"{self.source_file}{line}{session}"


@dataclass(slots=True)
class HistoryFragment:
    timestamp: datetime | None
    source_file: str
    session_id: str | None
    line_number: int | None
    raw_text: str
    recovered_text: str
    tags: list[str]


@dataclass(slots=True)
class PromptCandidate:
    section: str
    timestamp: datetime | None
    session_id: str | None
    prompt: str
    tags: list[str]
    confidence: str
    sources: list[SourceReference] = field(default_factory=list)

    def source_key(self) -> tuple[str | None, str]:
        stamp = self.timestamp.isoformat() if self.timestamp else ""
        return (stamp, self.prompt)


def _repair_mojibake(text: str) -> str:
    if not text:
        return text
    suspicious = ("Ã", "â", "Ä", "Ĺ", "ď", "Ź")
    if not any(char in text for char in suspicious):
        return text
    try:
        fixed = text.encode("latin1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text
    return fixed if fixed.count("�") <= text.count("�") else text


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    if isinstance(value, str):
        try:
            if value.endswith("Z"):
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _iter_text_values(obj: Any, *, current_key: str | None = None) -> Iterable[str]:
    if isinstance(obj, str):
        if current_key in {None, "content", "prompt", "text", "display", "stdout"}:
            yield obj
        return
    if isinstance(obj, list):
        for item in obj:
            yield from _iter_text_values(item, current_key=current_key)
        return
    if isinstance(obj, dict):
        attachment_type = obj.get("type")
        if attachment_type in SKIP_ATTACHMENT_TYPES:
            return
        if attachment_type == "text" and isinstance(obj.get("text"), str):
            yield obj["text"]
        if attachment_type == "tool_result" and isinstance(obj.get("content"), str):
            yield obj["content"]
        if attachment_type == "queued_command" and isinstance(obj.get("prompt"), str):
            yield obj["prompt"]
        for key, value in obj.items():
            yield from _iter_text_values(value, current_key=key)


def _match_tags(text: str) -> list[str]:
    lowered = text.casefold()
    tags: list[str] = []
    for tag, patterns in TARGET_PATTERNS.items():
        if tag == "character-design":
            continue
        if any(pattern in lowered for pattern in patterns):
            tags.append(tag)
    if tags and any(pattern in lowered for pattern in TARGET_PATTERNS["character-design"]):
        tags.append("character-design")
    if re.search(r"\bflux\b", lowered) and any(term in lowered for term in IMAGE_CONTEXT_TERMS):
        tags.append("flux")
    return tags


def _looks_relevant(text: str, tags: list[str]) -> bool:
    if not tags:
        return False
    lowered = text.casefold()
    if any(marker.casefold() in lowered for marker in SKIP_TEXT_PATTERNS):
        return False
    if "skill_listing" in lowered or "superpowers:" in lowered:
        return False
    if not (set(tags) & ANCHOR_TAGS):
        return False
    if text.count("├") >= 2 or text.count("###") >= 2:
        return False
    return True


def _extract_candidate_text(text: str) -> str:
    text = _repair_mojibake(text).replace("\r\n", "\n").strip()
    code_blocks = re.findall(r"```(?:[\w-]+)?\n(.*?)```", text, flags=re.DOTALL)
    for block in code_blocks:
        if _match_tags(block):
            return _clean_excerpt(block)

    paragraphs = [chunk.strip() for chunk in re.split(r"\n\s*\n", text) if chunk.strip()]
    relevant = [chunk for chunk in paragraphs if _match_tags(chunk)]
    if relevant:
        best = max(relevant, key=lambda chunk: (len(_match_tags(chunk)), len(chunk)))
        return _clean_excerpt(best)

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    hit_indexes = [idx for idx, line in enumerate(lines) if _match_tags(line)]
    if hit_indexes:
        start = max(0, hit_indexes[0] - 2)
        end = min(len(lines), hit_indexes[-1] + 3)
        return _clean_excerpt("\n".join(lines[start:end]))

    return _clean_excerpt(text)


def _clean_excerpt(text: str, limit: int = 900) -> str:
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _classify_section(tags: list[str]) -> str:
    tagset = set(tags)
    if {"identity-lock", "personal-photographs"} & tagset:
        return "Identity-lock setup"
    if {"gamma-realism", "dave-hill", "realism", "hyperdetail"} & tagset:
        return "Gamma realism / Dave Hill style prompts"
    return "Core Midjourney prompts"


def _classify_confidence(text: str, tags: list[str], source_file: str) -> str:
    lowered = text.casefold()
    if "```" in text or "--ar" in lowered or "--stylize" in lowered or len(tags) >= 3:
        return "exact"
    if "paste-cache" in source_file.replace("\\", "/"):
        return "partial"
    return "partial"


def _source_sort_key(path: Path) -> tuple[int, str]:
    normalized = path.as_posix()
    if "/projects/" in normalized:
        return (0, normalized)
    if normalized.endswith("/history.jsonl"):
        return (1, normalized)
    return (2, normalized)


def discover_source_files(claude_dir: Path) -> list[Path]:
    return sorted(
        [
            *claude_dir.joinpath("projects").rglob("*.jsonl"),
            claude_dir.joinpath("history.jsonl"),
            *claude_dir.joinpath("paste-cache").glob("*.txt"),
        ],
        key=_source_sort_key,
    )


def extract_history_fragments(claude_dir: Path) -> list[HistoryFragment]:
    fragments: list[HistoryFragment] = []

    for path in discover_source_files(claude_dir):
        if not path.exists():
            continue
        normalized = path.as_posix()

        if normalized.endswith("/history.jsonl") or normalized.endswith(".jsonl"):
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    timestamp = _parse_timestamp(payload.get("timestamp"))
                    session_id = payload.get("sessionId") or payload.get("session_id")
                    for blob in _iter_text_values(payload):
                        repaired = _repair_mojibake(blob)
                        tags = _match_tags(repaired)
                        if not _looks_relevant(repaired, tags):
                            continue
                        recovered_text = _extract_candidate_text(repaired)
                        recovered_tags = _match_tags(recovered_text)
                        if not _looks_relevant(recovered_text, recovered_tags):
                            continue
                        fragments.append(
                            HistoryFragment(
                                timestamp=timestamp,
                                source_file=str(path),
                                session_id=session_id,
                                line_number=line_number,
                                raw_text=blob,
                                recovered_text=recovered_text,
                                tags=recovered_tags,
                            )
                        )
        else:
            text = path.read_text(encoding="utf-8", errors="replace")
            repaired = _repair_mojibake(text)
            tags = _match_tags(repaired)
            if not _looks_relevant(repaired, tags):
                continue
            recovered_text = _extract_candidate_text(repaired)
            recovered_tags = _match_tags(recovered_text)
            if not _looks_relevant(recovered_text, recovered_tags):
                continue
            fragments.append(
                HistoryFragment(
                    timestamp=None,
                    source_file=str(path),
                    session_id=None,
                    line_number=None,
                    raw_text=text,
                    recovered_text=recovered_text,
                    tags=recovered_tags,
                )
            )

    return fragments


def build_prompt_candidates(fragments: list[HistoryFragment]) -> list[PromptCandidate]:
    candidates: list[PromptCandidate] = []
    seen: set[tuple[str, str, str | None]] = set()

    for fragment in fragments:
        section = _classify_section(fragment.tags)
        confidence = _classify_confidence(fragment.recovered_text, fragment.tags, fragment.source_file)
        key = (section, fragment.recovered_text, fragment.session_id)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            PromptCandidate(
                section=section,
                timestamp=fragment.timestamp,
                session_id=fragment.session_id,
                prompt=fragment.recovered_text,
                tags=fragment.tags,
                confidence=confidence,
                sources=[
                    SourceReference(
                        source_file=fragment.source_file,
                        line_number=fragment.line_number,
                        session_id=fragment.session_id,
                    )
                ],
            )
        )

    candidates.extend(_build_inferred_candidates(candidates))
    return sorted(
        candidates,
        key=lambda item: (
            SECTION_ORDER.index(item.section),
            item.timestamp or datetime.max.replace(tzinfo=timezone.utc),
            item.prompt,
        ),
    )


def _build_inferred_candidates(candidates: list[PromptCandidate]) -> list[PromptCandidate]:
    inferred: list[PromptCandidate] = []
    grouped: dict[tuple[str, str | None], list[PromptCandidate]] = defaultdict(list)
    for candidate in candidates:
        grouped[(candidate.section, candidate.session_id)].append(candidate)

    for (section, session_id), items in grouped.items():
        if any(item.confidence == "exact" for item in items):
            continue
        if len(items) < 2:
            continue
        tag_counts = Counter(tag for item in items for tag in item.tags)
        common_tags = [tag for tag, _ in tag_counts.most_common(5)]
        lines: list[str] = []
        for item in items[:3]:
            first_line = item.prompt.splitlines()[0].strip()
            if first_line:
                lines.append(first_line)
        if not lines:
            continue
        prompt = _synthesize_prompt(section, common_tags, lines)
        sources = [source for item in items for source in item.sources]
        inferred.append(
            PromptCandidate(
                section=section,
                timestamp=min((item.timestamp for item in items if item.timestamp), default=None),
                session_id=session_id,
                prompt=prompt,
                tags=common_tags,
                confidence="inferred",
                sources=sources,
            )
        )
    return inferred


def _synthesize_prompt(section: str, tags: list[str], lines: list[str]) -> str:
    style_map = {
        "Core Midjourney prompts": "Midjourney-focused visual prompt",
        "Gamma realism / Dave Hill style prompts": "Gamma realism prompt with dramatic Dave Hill energy",
        "Identity-lock setup": "Identity-lock reconstruction prompt for consistent face and reference-photo fidelity",
    }
    descriptors = ", ".join(tag.replace("-", " ") for tag in tags[:4]) or "image prompt"
    fragments = "; ".join(lines[:3])
    return f"{style_map[section]}: {descriptors}. Recovered cues: {fragments}"


def render_prompt_pack(candidates: list[PromptCandidate]) -> str:
    sections: dict[str, list[PromptCandidate]] = defaultdict(list)
    for candidate in candidates:
        sections[candidate.section].append(candidate)

    lines = [
        "# Claude Midjourney Prompt Pack",
        "",
        "Recovered from `projects/*.jsonl`, `history.jsonl`, and `paste-cache/*.txt`.",
        "",
    ]

    for section in SECTION_ORDER:
        lines.append(f"## {section}")
        lines.append("")
        items = sections.get(section, [])
        if not items:
            lines.append("_No recovered prompts in this section._")
            lines.append("")
            continue
        for item in items:
            when = item.timestamp.isoformat() if item.timestamp else "unknown-time"
            session = item.session_id or "no-session"
            tag_text = ", ".join(item.tags) if item.tags else "no-tags"
            lines.extend(
                [
                    f"### {when} / {session}",
                    f"- status: `{item.confidence}`",
                    f"- tags: `{tag_text}`",
                    "- prompt:",
                    "",
                    "```text",
                    item.prompt,
                    "```",
                    "",
                ]
            )

    lines.extend(["## Appendix", ""])
    for item in candidates:
        lines.append(f"### {item.section} :: {item.confidence}")
        for source in item.sources:
            lines.append(f"- {source.label()}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def collect_prompt_pack(claude_dir: Path) -> tuple[list[HistoryFragment], list[PromptCandidate], str]:
    fragments = extract_history_fragments(claude_dir)
    candidates = build_prompt_candidates(fragments)
    rendered = render_prompt_pack(candidates)
    return fragments, candidates, rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recover Midjourney-related prompts from local Claude history.")
    parser.add_argument(
        "--claude-dir",
        type=Path,
        default=Path.home() / ".claude",
        help="Path to the local Claude data directory.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/claude_midjourney_prompt_pack.md"),
        help="Where to write the batch-ready prompt pack.",
    )
    args = parser.parse_args(argv)

    _, candidates, rendered = collect_prompt_pack(args.claude_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"Wrote {len(candidates)} prompt candidates to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
