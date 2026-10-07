#!/usr/bin/env python3
"""
generate_results.py
Derives every reported number from one scored-rows JSONL: per-config tables with Wilson CIs,
paired McNemar tests, a failure-rate figure, a hypothesis-check report and a SHA-256 manifest.

Nothing in the outputs is typed by hand. `--check` re-derives from the committed JSONL and
fails if any committed derived file has drifted, so CI can enforce it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from secure_rag.benchmark.runner import run_matrix
from secure_rag.benchmark.scoring import dump_jsonl, mcnemar_test, summarize

RESULTS = Path("experiments/results")
FIXTURE = Path("benchmarks/fixtures/authinject_cases.json")
PRIMARY_CONFIGS = [
    "B0_ungated",
    "B1_postfilter",
    "B2_afr_only",
    "B3_afr_scan",
    "P1_continuous_auth",
    "P2_full_stack",
    "A1_no_datamarking",
    "A2_no_scanner",
    "A3_no_context_isolation",
    "A4_no_tool_authz",
    "A5_no_continuous_auth",
]
TABLE_METRICS = [
    ("unauthorized_context_exposure", "Exposure"),
    ("behavioral_leakage", "Leakage"),
    ("xpia_success", "XPIA"),
    ("tool_action_asr", "Tool ASR"),
    ("utility_marker_correct", "Utility"),
    ("combined_failure", "Combined failure"),
]
# (label, config A, config B, metric, attack family or None)
PAIRED_TESTS = [
    ("b2_vs_p1_cross_turn_exposure", "B2_afr_only", "P1_continuous_auth", "unauthorized_context_exposure", "cross_turn"),
    ("b2_vs_p1_stale_acl_exposure", "B2_afr_only", "P1_continuous_auth", "unauthorized_context_exposure", "stale_acl"),
    ("b2_vs_p1_combined_failure", "B2_afr_only", "P1_continuous_auth", "combined_failure", None),
    ("b0_vs_p2_combined_failure", "B0_ungated", "P2_full_stack", "combined_failure", None),
    ("b1_vs_b2_same_tenant_bait_exposure", "B1_postfilter", "B2_afr_only", "unauthorized_context_exposure", "same_tenant_bait"),
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_evaluation(out_jsonl: Path, generator: str, models: list[str], repeats: int, seed: int) -> list[dict[str, Any]]:
    result = run_matrix(
        repeats=repeats,
        split="all",
        generator=generator,
        models=models,
        configs=PRIMARY_CONFIGS,
        seed=seed,
    )
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    dump_jsonl(out_jsonl, result["rows"])
    return result["rows"]


def paired_series(rows: list[dict], cfg_a: str, cfg_b: str, metric: str, family: str | None) -> tuple[list[int], list[int]]:
    def index(cfg: str) -> dict[tuple, int]:
        return {
            (r["id"], r.get("repeat", 0), r.get("model_id", "")): int(r.get(metric, 0))
            for r in rows
            if r.get("config") == cfg and (family is None or r.get("attack_family") == family)
        }

    a, b = index(cfg_a), index(cfg_b)
    keys = sorted(set(a) & set(b))
    return [a[k] for k in keys], [b[k] for k in keys]


def analyze(rows: list[dict[str, Any]], fixture_sha: str) -> dict[str, Any]:
    by_config: dict[str, list[dict]] = {}
    by_family: dict[str, dict[str, list[dict]]] = {}
    for r in rows:
        by_config.setdefault(r["config"], []).append(r)
        by_family.setdefault(r["config"], {}).setdefault(r.get("attack_family", "unknown"), []).append(r)

    tests = {}
    for label, cfg_a, cfg_b, metric, family in PAIRED_TESTS:
        a, b = paired_series(rows, cfg_a, cfg_b, metric, family)
        tests[label] = {"config_a": cfg_a, "config_b": cfg_b, "metric": metric, "family": family, "n_pairs": len(a), **mcnemar_test(a, b)}

    return {
        "source_jsonl_rows": len(rows),
        "fixture_sha256": fixture_sha,
        "generators": sorted({r.get("generator", "") for r in rows}),
        "models": sorted({r.get("model_id", "") for r in rows}),
        "repeats": len({r.get("repeat", 0) for r in rows}),
        "table_summary": {cfg: summarize(by_config[cfg]) for cfg in PRIMARY_CONFIGS if cfg in by_config},
        "by_attack_family": {
            cfg: {fam: summarize(fam_rows) for fam, fam_rows in sorted(fams.items())}
            for cfg, fams in by_family.items()
        },
        "statistical_tests": tests,
    }


def _pct(metric: dict[str, Any]) -> str:
    if not metric.get("denominator"):
        return "n/a"
    lo, hi = metric["ci95"]
    return f"{metric['rate'] * 100:.1f} [{lo * 100:.1f}, {hi * 100:.1f}]"


def render_tables(analysis: dict[str, Any]) -> str:
    header = "| Config | " + " | ".join(name for _, name in TABLE_METRICS) + " | p50 ms | p95 ms |"
    lines = [
        "# AuthInject-RAG results (generated, do not edit)",
        "",
        f"Source: {analysis['source_jsonl_rows']} scored rows; generator(s) {', '.join(analysis['generators'])}; "
        f"model(s) {', '.join(analysis['models'])}; {analysis['repeats']} repeat(s).",
        f"Fixture SHA-256: `{analysis['fixture_sha256']}`",
        "",
        "Rates in %, Wilson 95% CI in brackets. Tool ASR is over `tool` family cases only.",
        "",
        header,
        "|" + "---|" * (len(TABLE_METRICS) + 3),
    ]
    for cfg, s in analysis["table_summary"].items():
        lat = s.get("latency_ms", {})
        cells = [_pct(s[key]) for key, _ in TABLE_METRICS]
        lines.append(f"| {cfg} | " + " | ".join(cells) + f" | {lat.get('p50', 'n/a')} | {lat.get('p95', 'n/a')} |")

    lines += ["", "## Paired McNemar tests", "", "| Test | Pairs | b (A fail, B pass) | c (A pass, B fail) | chi2 | p |", "|---|---|---|---|---|---|"]
    for label, t in analysis["statistical_tests"].items():
        lines.append(f"| {label} | {t['n_pairs']} | {t['b']} | {t['c']} | {t['statistic']} | {t['p_value']:.3g} |")
    return "\n".join(lines) + "\n"


def render_failure_figure(analysis: dict[str, Any]) -> str:
    summary = analysis["table_summary"]
    width, height, left, top, bottom = 960, 420, 70, 40, 120
    plot_h = height - top - bottom
    slot = (width - left - 20) / max(1, len(summary))
    bars = []
    for i, (cfg, s) in enumerate(summary.items()):
        rate = s["combined_failure"]["rate"]
        bar_h = rate * plot_h
        x = left + i * slot + slot * 0.15
        y = top + plot_h - bar_h
        label_x = x + slot * 0.35
        bars.append(
            f'  <rect x="{x:.1f}" y="{y:.1f}" width="{slot * 0.7:.1f}" height="{bar_h:.1f}" fill="#3b82f6"/>\n'
            f'  <text x="{label_x:.1f}" y="{y - 4:.1f}" font-size="11" text-anchor="middle">{rate * 100:.1f}%</text>\n'
            f'  <text x="{label_x:.1f}" y="{top + plot_h + 14}" font-size="11" text-anchor="end" '
            f'transform="rotate(-40 {label_x:.1f} {top + plot_h + 14})">{cfg}</text>'
        )
    ticks = "\n".join(
        f'  <text x="{left - 6}" y="{top + plot_h - f * plot_h + 4:.1f}" font-size="11" text-anchor="end">{int(f * 100)}%</text>'
        for f in (0, 0.25, 0.5, 0.75, 1.0)
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" font-family="Arial, sans-serif">\n'
        f'  <rect width="100%" height="100%" fill="#ffffff"/>\n'
        f'  <text x="{width / 2}" y="22" font-size="15" text-anchor="middle">Combined failure rate by configuration (generated from scored rows)</text>\n'
        f'  <line x1="{left}" y1="{top + plot_h}" x2="{width - 20}" y2="{top + plot_h}" stroke="#9ca3af"/>\n'
        f'  <line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#9ca3af"/>\n'
        f"{ticks}\n" + "\n".join(bars) + "\n</svg>\n"
    )


def render_hypothesis_report(analysis: dict[str, Any]) -> str:
    """Directional checks of the paper's claims. Informational: a FAIL is a finding, not a build error."""
    s = analysis["table_summary"]
    t = analysis["statistical_tests"]

    def rate(cfg: str, metric: str) -> float | None:
        return s.get(cfg, {}).get(metric, {}).get("rate")

    def lower(cfg_a: str, cfg_b: str, metric: str) -> tuple[bool, str]:
        a, b = rate(cfg_a, metric), rate(cfg_b, metric)
        if a is None or b is None:
            return False, "missing config"
        return a < b, f"{cfg_a}={a * 100:.1f}% vs {cfg_b}={b * 100:.1f}%"

    def significant(label: str) -> tuple[bool, str]:
        test = t[label]
        return test["significant"] and test["b"] > test["c"], f"b={test['b']} c={test['c']} p={test['p_value']:.3g} ({test['n_pairs']} pairs)"

    checks = [
        ("H1 P1 reduces cross-turn exposure vs B2 (McNemar)", significant("b2_vs_p1_cross_turn_exposure")),
        ("H2 P1 reduces stale-ACL exposure vs B2 (McNemar)", significant("b2_vs_p1_stale_acl_exposure")),
        ("H3 B2 reduces same-tenant bait exposure vs B1 (McNemar)", significant("b1_vs_b2_same_tenant_bait_exposure")),
        ("H4 P2 tool ASR below B0", lower("P2_full_stack", "B0_ungated", "tool_action_asr")),
        ("H5 P2 combined failure below B0", lower("P2_full_stack", "B0_ungated", "combined_failure")),
    ]
    lines = [
        "AuthInject-RAG hypothesis checks (generated from scored rows, informational)",
        f"Rows: {analysis['source_jsonl_rows']} | generator(s): {', '.join(analysis['generators'])} | model(s): {', '.join(analysis['models'])}",
        "",
    ]
    lines += [f"{'PASS' if ok else 'FAIL'}  {name}: {detail}" for name, (ok, detail) in checks]
    return "\n".join(lines) + "\n"


def derived_outputs(rows: list[dict[str, Any]]) -> dict[Path, str]:
    analysis = analyze(rows, sha256_file(FIXTURE))
    return {
        RESULTS / "authinject_v2_analysis.json": json.dumps(analysis, indent=2) + "\n",
        RESULTS / "authinject_v2_tables.md": render_tables(analysis),
        RESULTS / "hypothesis-report.txt": render_hypothesis_report(analysis),
        RESULTS / "figures" / "combined_failure_by_config.svg": render_failure_figure(analysis),
    }


def manifest_text(paths: list[Path]) -> str:
    return "".join(f"{sha256_file(p)}  {p.as_posix()}\n" for p in paths)


def main() -> None:
    parser = argparse.ArgumentParser(description="Derive all result tables and figures from scored rows.")
    parser.add_argument("--jsonl", type=Path, default=RESULTS / "authinject_v2_rows.jsonl")
    parser.add_argument("--run", action="store_true", help="Run the evaluation first and overwrite --jsonl")
    parser.add_argument("--generator", default="extractive", choices=["extractive", "llm"])
    parser.add_argument("--models", nargs="+", default=["llama-3.3-70b-versatile"])
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--check", action="store_true", help="Fail if committed derived files differ from a fresh derivation")
    args = parser.parse_args()

    if args.run:
        run_evaluation(args.jsonl, args.generator, args.models, args.repeats, args.seed)
    rows = load_rows(args.jsonl)
    outputs = derived_outputs(rows)
    manifest_path = RESULTS / "SHA256SUMS"

    if args.check:
        drifted = [str(p) for p, text in outputs.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
        expected_manifest = manifest_text([FIXTURE, args.jsonl, *outputs])
        if not manifest_path.exists() or manifest_path.read_text(encoding="utf-8") != expected_manifest:
            drifted.append(str(manifest_path))
        if drifted:
            sys.exit("FATAL: derived results drifted from the scored rows; run `python generate_results.py` and commit:\n  " + "\n  ".join(drifted))
        print("Derived results match the committed scored rows.")
        return

    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    manifest_path.write_text(manifest_text([FIXTURE, args.jsonl, *outputs]), encoding="utf-8")
    print(outputs[RESULTS / "hypothesis-report.txt"])
    print(f"Wrote {len(outputs)} derived files and {manifest_path}")


if __name__ == "__main__":
    main()
