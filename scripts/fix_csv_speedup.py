#!/usr/bin/env python3
"""One-shot repair of results/benchmark.csv + console tables.

The original run wrote speedup_vs_cpu1 inverted (engine_time / cpu_time).
This script recomputes the correct speedup = cpu1_time / engine_time from the
measured time_s column (no benchmark re-run required) and regenerates the
console table artifacts.
"""

import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
CSV = os.path.join(ROOT, "results", "benchmark.csv")

LABELS = {
    "cpu_1thread": "CPU (1-Thread)",
    "cpu_openmp":  "CPU (OpenMP)",
    "cuda_kernel": "CUDA (Kernel Only)",
    "cuda_e2e":    "CUDA (End-to-End)",
}
ALGO_NAMES = {"sha256": "SHA-256", "md5": "MD5"}


def comma(v):
    return f"{int(v):,}"


def main():
    with open(CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    for r in rows:
        r["length"] = int(r["length"])
        r["time_s"] = float(r["time_s"])
        r["rate_mhps"] = float(r["rate_mhps"])
        r["hashes"] = float(r["hashes"])

    # baseline time per (algo, charset, length)
    base = {}
    for r in rows:
        if r["engine"] == "cpu_1thread":
            base[(r["algo"], r["charset"], r["length"])] = r["time_s"]

    for r in rows:
        b = base[(r["algo"], r["charset"], r["length"])]
        r["speedup_vs_cpu1"] = b / r["time_s"] if r["time_s"] > 0 else 0.0

    with open(CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["algo", "charset", "length", "engine", "hashes", "time_s", "rate_mhps", "speedup_vs_cpu1"])
        for r in rows:
            w.writerow([r["algo"], r["charset"], r["length"], r["engine"],
                        int(r["hashes"]), f"{r['time_s']:.6f}",
                        f"{r['rate_mhps']:.3f}", f"{r['speedup_vs_cpu1']:.3f}"])
    print(f"[fix] rewrote {CSV} with corrected speedup column")

    # Regenerate console tables for each (algo, charset) group present.
    groups = sorted({(r["algo"], r["charset"]) for r in rows})
    for algo, charset in groups:
        lines = []
        lines.append("=" * 118)
        lines.append(f"  Benchmark: {ALGO_NAMES[algo]} brute force | charset: {charset} | GPU: NVIDIA GeForce RTX 3050 6GB Laptop GPU")
        lines.append("  Full-keyspace worst case: target = last candidate of each length")
        lines.append("-" * 118)
        lines.append(f"  {'Len':<4} | {'Engine':<22} | {'Candidates':>14} | {'Time (s)':>12} | {'Thru (MH/s)':>17} | {'Speedup':>10}")
        lines.append("-" * 118)
        for L in (4, 5, 6):
            sel = [r for r in rows if r["algo"] == algo and r["charset"] == charset and r["length"] == L]
            sel.sort(key=lambda r: ["cpu_1thread", "cpu_openmp", "cuda_kernel", "cuda_e2e"].index(r["engine"]))
            for r in sel:
                first = f"{L:<4}" if r is sel[0] else "    "
                lines.append(f"  {first} | {LABELS[r['engine']]:<22} | {comma(r['hashes']):>14} | "
                             f"{r['time_s']:>12.6f} | {r['rate_mhps']:>17.3f} | {r['speedup_vs_cpu1']:>9.1f}x")
            lines.append("-" * 118)
        out = os.path.join(ROOT, "results", f"{algo}_benchmark_console.txt")
        with open(out, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"[fix] regenerated {out}")


if __name__ == "__main__":
    main()
