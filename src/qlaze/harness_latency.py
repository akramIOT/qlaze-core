#!/usr/bin/env python3
"""Measure EP-HS + AuthBind CPU wall time and model WAN latency."""

from __future__ import annotations

import argparse
import csv
import statistics
import time
from pathlib import Path

from qlaze.authbind import authbind_keygen, authbind_sign, authbind_verify
from qlaze.ephs import ephs_session


def percentile(samples: list[float], p: float) -> float:
    xs = sorted(samples)
    k = (len(xs) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return xs[f]
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def ep_hs_authbind_once() -> None:
    keys, _ = ephs_session()
    gpk, gsk = authbind_keygen()
    id_a, id_b = b"A" * 16, b"B" * 16
    sig = authbind_sign(gsk, keys.transcript, gpk, id_a, id_b)
    if not authbind_verify(gpk, sig, keys.transcript, gpk, id_a, id_b):
        raise RuntimeError("AuthBind failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", type=int, default=1000)
    parser.add_argument("-o", type=Path, default=Path("artifacts/latency_harness.csv"))
    parser.add_argument("--rtt-ms", type=float, default=20.0, help="WAN RTT per hop (ms)")
    args = parser.parse_args()

    for _ in range(min(20, args.n // 10)):
        ep_hs_authbind_once()

    cpu_ms = []
    for _ in range(args.n):
        t0 = time.perf_counter_ns()
        ep_hs_authbind_once()
        cpu_ms.append((time.perf_counter_ns() - t0) / 1e6)

    med = statistics.median(cpu_ms)
    p98 = percentile(cpu_ms, 98)
    p999 = percentile(cpu_ms, 99.9)
    # 2-RTT EP-HS + 1-RTT AuthBind bind ≈ 3 RTT hops on WAN
    wan_p98 = 3 * args.rtt_ms + p98

    args.o.parent.mkdir(parents=True, exist_ok=True)
    with args.o.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "metric",
                "n",
                "median_ms",
                "p98_ms",
                "p999_ms",
                "rtt_ms",
                "wan_p98_ms",
            ],
        )
        w.writeheader()
        w.writerow(
            {
                "metric": "EP-HS+AuthBind CPU",
                "n": args.n,
                "median_ms": round(med, 2),
                "p98_ms": round(p98, 2),
                "p999_ms": round(p999, 2),
                "rtt_ms": args.rtt_ms,
                "wan_p98_ms": round(wan_p98, 2),
            }
        )

    print(f"CPU median={med:.2f} ms  p98={p98:.2f} ms  WAN p98 (3×RTT+CPU)={wan_p98:.2f} ms")
    print(f"Wrote {args.o}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
