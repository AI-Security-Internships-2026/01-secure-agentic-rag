from __future__ import annotations

import argparse
import json
from pathlib import Path

from secure_rag.benchmark.scoring import summarize


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("jsonl")
    parser.add_argument("--out", default="experiments/results/authinject_tables.json")
    args = parser.parse_args()
    rows = load_jsonl(Path(args.jsonl))
    by_config: dict[str, list[dict]] = {}
    for row in rows:
        by_config.setdefault(row.get("config", "unknown"), []).append(row)
    tables = {name: summarize(items) for name, items in by_config.items()}
    Path(args.out).write_text(json.dumps(tables, indent=2), encoding="utf-8")
    print(json.dumps(tables, indent=2))


if __name__ == "__main__":
    main()
