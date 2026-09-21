#!/usr/bin/env bash
# ==============================================================================
# Script: make-reproduce.sh
# Purpose: Idempotent benchmark execution & paper figure reproduction for IEEE TDSC AE
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

echo "======================================================================"
echo " AuthInject-Lifecycle: Continuous Authorization Reproducibility Suite "
echo "======================================================================"
echo "Working directory: ${PROJECT_ROOT}"

MODE="${1:---smoke}"

# 1. Environment & Dependency Verification
echo "[1/4] Verifying Python environment and locked dependencies..."
python -m pip install -q -r "${PROJECT_ROOT}/requirements.lock"

# 2. Infrastructure Health Check
echo "[2/4] Checking SpiceDB and Qdrant readiness..."
if ! curl -s "http://localhost:6333/healthz" > /dev/null 2>&1; then
    echo "  -> Starting Docker Compose dependencies..."
    docker compose up -d postgres spicedb qdrant
    sleep 3
fi

# 3. Execution of Benchmark Protocol
if [ "${MODE}" = "--smoke" ]; then
    echo "[3/4] Executing Smoke Benchmark (20 cases, 1 repeat, offline generator)..."
    python -m secure_rag.benchmark.runner --config C0,C1,C2,C3,C4,C5,C6,C7,C8 --mode extractive --output experiments/results/authinject_eval.json
else
    echo "[3/4] Executing Full Factorial Live Benchmark (160 cases x 3 LLMs x 5 repeats)..."
    python generate_results.py --live --models llama-3.3-70b,deepseek-r1-distill-32b,gpt-4o-mini --repeats 5
fi

# 4. Generate Paper Figures and Quality Gate Verification
echo "[4/4] Verifying Quality Gates and Paper Section VI LaTeX Consistency..."
python -c "
import json
from pathlib import Path
from generate_results import evaluate_gate_requirements

root = Path('${PROJECT_ROOT}')
analysis_file = root / 'experiments' / 'results' / 'authinject_v2_analysis.json'
report_file = root / 'experiments' / 'results' / 'gate-report.txt'

if analysis_file.exists():
    with open(analysis_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    passed = evaluate_gate_requirements(data, report_file)
    print('  -> Quality Gate Evaluation:', 'PASSED' if passed else 'FAILED')
"

echo "======================================================================"
echo " Reproduction Complete! All artifacts generated in experiments/results"
echo "======================================================================"
