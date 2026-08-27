"""Licensed dataset adapters. Corpora are downloaded on demand and never committed."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "benchmarks" / "manifest.json"
CACHE = ROOT / "benchmarks" / ".cache"


@dataclass
class DatasetSpec:
    name: str
    license: str
    url: str
    version: str
    notes: str


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def fixture_path(name: str) -> Path:
    return ROOT / "benchmarks" / "fixtures" / name
