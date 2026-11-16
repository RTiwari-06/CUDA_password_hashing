#!/usr/bin/env python3
"""Visualization for the CUDA Password Hashing benchmark.

Reads results/benchmark.csv (written by cuda_cracker.exe --mode benchmark) and
generates:
  results/throughput_comparison.png - grouped bars: throughput vs password
                                      length for the 4 engines (per algorithm)
  results/speedup_scaling.png       - line plot: speedup vs CPU(1-Thread)
                                      as password length grows (log scale)
"""

import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
CSV = os.path.join(ROOT, "results", "benchmark.csv")

ENGINE_LABELS = {
    "cpu_1thread": "CPU (1-Thread)",
    "cpu_openmp":  "CPU (OpenMP)",
    "cuda_kernel": "CUDA (Kernel Only)",
    "cuda_e2e":    "CUDA (End-to-End)",
}
ENGINE_COLORS = {
    "cpu_1thread": "#8c8c8c",
    "cpu_openmp":  "#2f6fdf",
    "cuda_kernel": "#e0641f",
    "cuda_e2e":    "#f2a541",
}
LENGTHS = [4, 5, 6]
ENGINES = ["cpu_1thread", "cpu_openmp", "cuda_kernel", "cuda_e2e"]


def load_rows():
    rows = []
    if not os.path.exists(CSV):
        sys.exit(f"error: {CSV} not found - run the benchmark first")
    with open(CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try:
                rows.append({
                    "algo":    r["algo"].strip(),
                    "charset": r["charset"].strip(),
                    "length":  int(r["length"]),
                    "engine":  r["engine"].strip(),
                    "hashes":  float(r["hashes"]),
                    "time_s":  float(r["time_s"]),
                    "rate":    float(r["rate_mhps"]),
                    "speedup": float(r["speedup_vs_cpu1"]),
                })
            except (KeyError, ValueError):
                continue  # skip header leftovers / malformed rows
    return rows


def latest_per_cell(rows):
    """Keep the most recent row per (algo, charset, length, engine)."""
    cell = {}
    for r in rows:  # CSV is append-only, so last write wins
        cell[(r["algo"], r["charset"], r["length"], r["engine"])] = r
    return cell


def throughput_chart(cell, algos, out_path):
    n_algo = len(algos)
    fig, axes = plt.subplots(1, n_algo, figsize=(7.5 * n_algo, 5.2), squeeze=False)
    for ax, algo in zip(axes[0], algos):
        width = 0.2
        xs = range(len(LENGTHS))
        for j, eng in enumerate(ENGINES):
            vals = []
            for L in LENGTHS:
                r = cell.get((algo, "lower", L, eng))
                vals.append(r["rate"] if r else 0.0)
            pos = [x + (j - (len(ENGINES) - 1) / 2) * width for x in xs]
            bars = ax.bar(pos, vals, width, label=ENGINE_LABELS[eng],
                          color=ENGINE_COLORS[eng], edgecolor="black", linewidth=0.4)
            for b, v in zip(bars, vals):
                if v > 0:
                    ax.annotate(f"{v:,.1f}", (b.get_x() + b.get_width() / 2, v),
                                ha="center", va="bottom", fontsize=7)
        ax.set_xticks(list(xs))
        ax.set_xticklabels([f"Length {L}" for L in LENGTHS])
        ax.set_ylabel("Throughput (MH/s)")
        title = {"sha256": "SHA-256", "md5": "MD5"}[algo]
        ax.set_title(f"{title} - brute-force throughput (full keyspace scan)")
        ax.set_yscale("log")
        ax.grid(axis="y", alpha=0.3, which="both")
        ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[plot] wrote {out_path}")


def speedup_chart(cell, algos, out_path):
    fig, ax = plt.subplots(figsize=(8.4, 5.6))
    markers = {"cpu_openmp": "o", "cuda_kernel": "s", "cuda_e2e": "^"}
    for algo in algos:
        for eng in ENGINES[1:]:
            xs, ys = [], []
            for L in LENGTHS:
                r = cell.get((algo, "lower", L, eng))
                if r and r["speedup"] > 0:
                    xs.append(L)
                    ys.append(r["speedup"])
            if xs:
                ax.plot(xs, ys, marker=markers.get(eng, "o"), linewidth=2,
                        label=f"{ENGINE_LABELS[eng]} [{algo.upper()}]")
    ax.axhline(1.0, color="gray", linestyle="--", linewidth=1, label="CPU 1-Thread baseline")
    ax.set_xticks(LENGTHS)
    ax.set_xticklabels([f"Length {L}" for L in LENGTHS])
    ax.set_xlabel("Password length (full keyspace scanned)")
    ax.set_ylabel("Speedup vs CPU (1-Thread)  [x]")
    ax.set_yscale("log")
    ax.set_title("GPU/OpenMP speedup scaling on RTX 3050 6GB Laptop")
    ax.grid(alpha=0.3, which="both")
    ax.legend(fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[plot] wrote {out_path}")


def main():
    rows = load_rows()
    cell = latest_per_cell(rows)
    algos = sorted({r["algo"] for r in rows})
    if not algos:
        sys.exit("error: no benchmark rows found in CSV")
    throughput_chart(cell, algos, os.path.join(ROOT, "results", "throughput_comparison.png"))
    speedup_chart(cell, algos, os.path.join(ROOT, "results", "speedup_scaling.png"))
    print("[plot] done")


if __name__ == "__main__":
    main()
