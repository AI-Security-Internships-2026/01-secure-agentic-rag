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


def main() -> None:
    import argparse
    from secure_rag.benchmark.adapters import build_authinject_cases

    parser = argparse.ArgumentParser(description="Deterministic AuthInject benchmark dataset generator.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--version", type=str, default="2.0", help="Fixture version")
    parser.add_argument("--size", type=int, default=160, help="Total number of cases")
    args = parser.parse_args()

    built = build_authinject_cases(seed=args.seed, version=args.version, size=args.size)
    print(f"Generated v{args.version} benchmark fixture with {len(built)} cases.")


if __name__ == "__main__":
    main()

