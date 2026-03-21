from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CoreLockLogger:
    """Append-only style logger with hash chaining for CORE_LOCK events.

    This public implementation is intentionally simple and uses a local file.
    Production deployments should replace the storage backend with immutable or
    append-only infrastructure.
    """

    def __init__(self, log_dir: str | Path = ".alfa_logs") -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "core_lock.log"
        self.last_hash = self._get_last_hash()

    def log(self, request: Any, score: float, correlation_id: str) -> str:
        payload = self._serialize_request(request)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request": payload,
            "score": float(score),
            "prev_hash": self.last_hash,
            "correlation_id": correlation_id,
        }
        canonical = json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        entry["entry_hash"] = entry_hash
        final = json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        with self.log_file.open("a", encoding="utf-8") as handle:
            handle.write(final + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.last_hash = entry_hash
        return entry_hash

    def _get_last_hash(self) -> str:
        if not self.log_file.exists():
            return "0" * 64
        last_line = ""
        with self.log_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last_line = line.strip()
        if not last_line:
            return "0" * 64
        try:
            parsed = json.loads(last_line)
        except json.JSONDecodeError:
            return "0" * 64
        return str(parsed.get("entry_hash", "0" * 64))

    @staticmethod
    def _serialize_request(request: Any) -> dict[str, Any]:
        if is_dataclass(request):
            return asdict(request)
        if isinstance(request, dict):
            return request
        if hasattr(request, "__dict__"):
            return dict(request.__dict__)
        return {"value": repr(request)}
