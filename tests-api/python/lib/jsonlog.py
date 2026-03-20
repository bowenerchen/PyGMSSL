"""Append structured test records as JSON lines + optional aggregate JSON."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class CaseRecord:
    id: str
    tool: str
    inputs: dict[str, Any] = field(default_factory=dict)
    stdout_capture: str | None = None
    parsed: dict[str, Any] | None = None
    pass_: bool = field(default=True, metadata={"json": "pass"})
    error: str | None = None
    duration_ms: float | None = None

    def to_json_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "tool": self.tool,
            "inputs": self.inputs,
            "stdout_capture": self.stdout_capture,
            "parsed": self.parsed,
            "pass": self.pass_,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }
        return d


def results_dir(base: Path | None = None) -> Path:
    root = base or Path(__file__).resolve().parents[2]
    d = root / "results"
    d.mkdir(parents=True, exist_ok=True)
    return d


def append_jsonl(record: CaseRecord, filename: str = "cases.jsonl") -> None:
    path = results_dir() / filename
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record.to_json_dict(), ensure_ascii=False) + "\n")


def write_aggregate(cases: list[dict[str, Any]], filename: str = "aggregate.json") -> Path:
    path = results_dir() / filename
    summary = {
        "generated_at_ms": time.time() * 1000,
        "total": len(cases),
        "passed": sum(1 for c in cases if c.get("pass")),
        "failed": sum(1 for c in cases if not c.get("pass")),
        "cases": cases,
    }
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def timed_block():
    """Context manager yielding list of one float [duration_ms] set on exit."""
    t0 = time.perf_counter()
    dur = [0.0]

    class _CM:
        def __enter__(self):
            return dur

        def __exit__(self, *args):
            dur[0] = (time.perf_counter() - t0) * 1000

    return _CM()
