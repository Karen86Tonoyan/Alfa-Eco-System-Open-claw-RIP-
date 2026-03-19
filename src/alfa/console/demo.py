from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from typing import Any, Iterable

from alfa.bootstrap import ALFAEcosystem, build_public_ecosystem
from alfa.shared.schemas import RequestEnvelope


FLOW_LINE = "VOICE -> BRAIN -> FILTERS -> CERBER -> PLUGIN / RESPONSE"


@dataclass(frozen=True)
class DemoScene:
    key: str
    title: str
    hook: str
    request: RequestEnvelope | None = None
    baseline_response: str | None = None


def build_demo_scenes() -> list[DemoScene]:
    return [
        DemoScene(
            key="hook",
            title="SCENE 1 | PROBLEM",
            hook="Standard AI often reacts first and evaluates later. ALFA reverses that order.",
            baseline_response=(
                "Simulated baseline model: 'Sure, I will run the shell and clean old deployment files.'"
            ),
        ),
        DemoScene(
            key="block",
            title="SCENE 2 | CERBER BLOCKS",
            hook="The same type of request goes through Brain, Filters, and Cerber before any action.",
            request=RequestEnvelope(
                text="Uruchom shell i usun stare pliki deploymentu.",
                user_id="demo-user",
                session_id="demo-block",
                requested_plugin="script_runner",
                source_trust="primary",
            ),
        ),
        DemoScene(
            key="approve",
            title="SCENE 3 | CONTROLLED APPROVAL",
            hook="When the operator confirms and the source is trusted, the gated path can continue.",
            request=RequestEnvelope(
                text="Uruchom zatwierdzony skrypt backupu po deploymencie.",
                user_id="demo-user",
                session_id="demo-approve",
                requested_plugin="script_runner",
                source_trust="operator",
                metadata={"confirmed": True},
            ),
        ),
        DemoScene(
            key="notes",
            title="SCENE 4 | SAFE HELPFUL TASK",
            hook="The system is not only a blocker. It can safely pass low-risk tasks to plugins.",
            request=RequestEnvelope(
                text="Pokaz moje notatki do pitch decku.",
                user_id="demo-user",
                session_id="demo-notes",
                requested_plugin="notes_lookup",
            ),
        ),
    ]


def build_demo_ecosystem() -> ALFAEcosystem:
    ecosystem = build_public_ecosystem()
    ecosystem.memory.remember_user(
        "demo-user",
        "notes",
        [
            "Pitch: ALFA as a control layer over LLMs",
            "Cerber: execution gate before plugins",
            "Backends: Ollama local + managed cloud channels",
        ],
    )
    return ecosystem


def run_selected_scenes(scene_keys: Iterable[str]) -> list[dict[str, Any]]:
    ecosystem = build_demo_ecosystem()
    scenes_by_key = {scene.key: scene for scene in build_demo_scenes()}
    results: list[dict[str, Any]] = []

    for key in scene_keys:
        scene = scenes_by_key[key]
        if scene.request is None:
            results.append(
                {
                    "scene": scene.key,
                    "title": scene.title,
                    "hook": scene.hook,
                    "baseline_response": scene.baseline_response,
                }
            )
            continue

        result = ecosystem.console.handle(scene.request)
        results.append(
            {
                "scene": scene.key,
                "title": scene.title,
                "hook": scene.hook,
                "input": scene.request.text,
                "decision": result["decision"],
                "guard": result["guard"],
                "execution": result["execution"],
                "response": result["response"],
            }
        )

    return results


def _backend_summary() -> str:
    ecosystem = build_public_ecosystem()
    labels = [f"{item['name']} ({item['deployment']})" for item in ecosystem.backends.list_specs()]
    return " | ".join(labels)


def render_demo(scene_keys: Iterable[str], *, pause: float = 0.0) -> list[dict[str, Any]]:
    results = run_selected_scenes(scene_keys)

    print("=" * 72)
    print("ALFA DEMO | Proof Repo")
    print(FLOW_LINE)
    print(f"BACKENDS | {_backend_summary()}")
    print("=" * 72)

    for result in results:
        print()
        print(result["title"])
        print(result["hook"])

        baseline = result.get("baseline_response")
        if baseline:
            print()
            print("[WITHOUT ALFA]")
            print(baseline)
            if pause:
                time.sleep(pause)
            continue

        print()
        print(f"user> {result['input']}")
        print()
        print("[ALFA_BRAIN]")
        print(f"state: {result['decision']['state']}")
        print(f"intent: {result['decision']['policy']['intent']}")
        print(f"risk: {result['decision']['policy']['risk']}")
        print(f"route: {result['decision']['route']['route']}")
        print(f"mode: {result['decision']['policy']['response_mode']}")

        print()
        print("[FILTERS]")
        for item in result["decision"]["policy"]["filters"]:
            print(f"- {item['name']}: {item['detail']}")

        print()
        print("[CERBER]")
        guard_status = "APPROVED" if result["guard"]["allowed"] else "BLOCKED"
        print(f"status: {guard_status}")
        print(f"reason: {result['guard']['reason']}")
        if result["guard"]["approved_plugin"]:
            print(f"plugin: {result['guard']['approved_plugin']}")
        if result["guard"]["requires_confirmation"]:
            print("confirmation: required")

        execution = result.get("execution")
        if execution:
            print()
            print("[PLUGIN]")
            print(f"executed: {execution['plugin']}")
            payload = {key: value for key, value in execution.items() if key != 'plugin'}
            print(json.dumps(payload, ensure_ascii=True, indent=2))

        print()
        print("[RESPONSE]")
        print(result["response"])

        if pause:
            time.sleep(pause)

    print()
    print("FINAL")
    print("ALFA is a control layer placed over existing LLMs.")
    print("Publicly, this repo proves the filters and the guarded flow.")
    print("Operational execution logic and deeper connectors remain private and B2B-only.")
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ALFA public proof demo")
    parser.add_argument(
        "--scene",
        action="append",
        choices=[scene.key for scene in build_demo_scenes()],
        help="Run only selected scene. Repeat the flag to chain multiple scenes.",
    )
    parser.add_argument(
        "--pause",
        type=float,
        default=0.0,
        help="Pause in seconds between scenes. Useful for screen recording.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured scene results as JSON.",
    )
    args = parser.parse_args(argv)

    scene_keys = args.scene or ["hook", "block", "approve", "notes"]
    if args.json:
        print(json.dumps(run_selected_scenes(scene_keys), ensure_ascii=True, indent=2))
        return 0

    render_demo(scene_keys, pause=max(args.pause, 0.0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

