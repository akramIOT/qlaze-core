# QLAZE-core (v0.9)

Reference implementation of **QLAZE** protocols from the accompanying papers:

- **EP-HS** — ML-KEM-768 handshake + HMAC key confirmation
- **AuthBind** — ML-DSA-65 binding of handshake transcript to coalition key
- **ZTARP** — 96-byte DPR encode/decode + cache fast-path verification

This is a **research prototype** (Python). Production deployments should use the MPC threshold ML-DSA construction cited in the paper (Mithril / Efficient Threshold ML-DSA).

## Quick start

```bash
cd qlaze-core
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export PYTHONPATH=src
python -m qlaze.bench -n 1000
python -m qlaze.harness_latency -n 200
```

Full reproduction (10,000 microbench trials + latency harness):

```bash
./scripts/reproduce.sh
```

Maintainer: [@akramIOT](https://github.com/akramIOT)

Repository: [https://github.com/akramIOT/qlaze-core](https://github.com/akramIOT/qlaze-core) (tag `v0.9.0`).

## Layout

```
src/qlaze/
  ephs.py      # EP-HS session + HMAC tags
  authbind.py  # AuthBind ML-DSA signatures
  ztarp.py     # DPR wire format + verifier cache
  bench.py     # Microbenchmarks → artifacts/bench_results.csv
scripts/
  reproduce.sh
artifacts/     # generated CSV (gitignored except sample)
```

## Citation

Akram Sheriff, *QLAZE: Quantum-Resistant Lattice-Anchored Zero-Trust Ephemeral Identity for Multi-Agent Orchestration*, 2026.

## License

Apache-2.0
