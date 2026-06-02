#!/usr/bin/env python3
"""QLAZE-core microbenchmarks (reproduces Table tab:micro subset)."""

from __future__ import annotations

import argparse
import csv
import hashlib
import statistics
import sys
import time
from pathlib import Path

from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65

from qlaze.authbind import authbind_keygen, authbind_sign, authbind_verify, h_bind
from qlaze.ephs import ephs_session, key_confirm_tag, derive_ck, build_transcript, _hkdf_expand
import hashlib
from qlaze.ztarp import DPR, DPRVerifier, edge_hash, sig_fingerprint


def percentile(samples: list[float], p: float) -> float:
    if not samples:
        return 0.0
    xs = sorted(samples)
    k = (len(xs) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return xs[f]
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def bench(name: str, fn, n: int) -> dict:
    # warmup
    for _ in range(min(50, n // 10)):
        fn()
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1000.0)
    return {
        "operation": name,
        "n": n,
        "median_us": statistics.median(samples),
        "p98_us": percentile(samples, 98),
        "p999_us": percentile(samples, 99.9),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="QLAZE-core benchmarks")
    parser.add_argument("-n", type=int, default=1000, help="trials per op (use 10000 for paper)")
    parser.add_argument("-o", type=Path, default=Path("artifacts/bench_results.csv"))
    args = parser.parse_args()
    n = args.n
    args.o.parent.mkdir(parents=True, exist_ok=True)

    kem = ML_KEM_768
    dsa = ML_DSA_65
    pk_k, sk_k = kem.keygen()
    pk_d, sk_d = dsa.keygen()
    _, c = kem.encaps(pk_k)
    msg = b"bench"

    rows = []

    rows.append(bench("ML-KEM-768 KeyGen", lambda: kem.keygen(), n))
    rows.append(bench("ML-KEM-768 Encaps", lambda: kem.encaps(pk_k), n))
    rows.append(bench("ML-KEM-768 Decaps", lambda: kem.decaps(sk_k, c), n))

    keys, _ = ephs_session()
    rows.append(
        bench(
            "EP-HS full (CPU)",
            lambda: ephs_session(),
            min(n, 500),
        )
    )
    rows.append(
        bench(
            "HKDF-SHA384 (transcript)",
            lambda: _hkdf_expand(
                hashlib.sha3_256(b"ms").digest(), keys.transcript, 32
            ),
            n,
        )
    )
    rows.append(
        bench(
            "HMAC key confirm",
            lambda: key_confirm_tag(keys.ck, b"QLAZE-EPHS-init", keys.transcript),
            n,
        )
    )

    sig = dsa.sign(sk_d, msg)
    rows.append(bench("ML-DSA-65 Sign", lambda: dsa.sign(sk_d, msg), min(n, 500)))
    rows.append(bench("ML-DSA-65 Verify", lambda: dsa.verify(pk_d, msg, sig), n))

    gpk, _gsk = authbind_keygen()
    tr = keys.transcript
    rows.append(
        bench(
            "AuthBind sign",
            lambda: authbind_sign(_gsk, tr, gpk, b"A" * 16, b"B" * 16),
            min(n, 300),
        )
    )
    bind_sig = authbind_sign(_gsk, tr, gpk, b"A" * 16, b"B" * 16)
    rows.append(
        bench(
            "AuthBind verify",
            lambda: authbind_verify(gpk, bind_sig, tr, gpk, b"A" * 16, b"B" * 16),
            n,
        )
    )

    sigma = dsa.sign(sk_d, b"edge")
    fp = sig_fingerprint(sigma)
    parent = hashlib.sha3_256(b"root").digest()
    eh = edge_hash(parent, b"C" * 16, b"\x00" * 32, int(time.time()))
    dpr = DPR(b"R" * 16, b"C" * 16, eh, 1, 1, fp)
    ver = DPRVerifier()
    ver.cache_insert(fp, eh, sigma)
    rows.append(bench("DPR verify fast", lambda: ver.verify_fast(dpr), n))
    rows.append(
        bench(
            "DPR verify slow",
            lambda: ver.verify_slow(
                dpr,
                pk_d,
                lambda pk, meta, s: dsa.verify(pk, b"edge", s),
            ),
            n,
        )
    )

    with args.o.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["operation", "n", "median_us", "p98_us", "p999_us"],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"Wrote {args.o}")
    for r in rows:
        print(
            f"{r['operation']:24} median={r['median_us']:8.1f} us  p98={r['p98_us']:8.1f} us"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
