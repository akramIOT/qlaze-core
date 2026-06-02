#!/usr/bin/env bash
# Reproduce QLAZE-core microbenchmarks (paper Table tab:micro subset).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt
export PYTHONPATH="${ROOT}/src"

mkdir -p artifacts
python -m qlaze.bench -n 10000 -o artifacts/bench_results.csv
python -m qlaze.harness_latency -n 1000 -o artifacts/latency_harness.csv
echo "Done."
echo "  artifacts/bench_results.csv"
echo "  artifacts/latency_harness.csv"
