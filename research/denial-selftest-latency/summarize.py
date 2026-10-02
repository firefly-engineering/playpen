#!/usr/bin/env python3
"""Summarise probe CSVs: found rate and latency percentiles (ms)."""
import csv
import sys


def pct(xs, p):
    if not xs:
        return float("nan")
    xs = sorted(xs)
    k = min(len(xs) - 1, max(0, round(p / 100 * (len(xs) - 1))))
    return xs[k]


print("file | n | found | reader p50 / p90 / p99 / max (ms) | journal-recv p50 / p99 / max (ms)")
for path in sys.argv[1:]:
    rows = list(csv.DictReader(open(path)))
    found = [r for r in rows if r["found"] == "1"]
    lat = [int(r["latency_us"]) / 1000 for r in found]
    rec = [int(r["journal_recv_minus_t0_us"]) / 1000 for r in found
           if r["journal_recv_minus_t0_us"] != "-1"]
    f = lambda v: f"{v:.2f}"
    print(f"{path} | {len(rows)} | {len(found)} | "
          f"{f(pct(lat,50))} / {f(pct(lat,90))} / {f(pct(lat,99))} / {f(max(lat) if lat else float('nan'))} | "
          f"{f(pct(rec,50))} / {f(pct(rec,99))} / {f(max(rec) if rec else float('nan'))}")
