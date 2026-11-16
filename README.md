# CUDA Password Hashing & Brute-Force Benchmark

A self-contained educational project that shows — with real, reproducible numbers —
why fast, non-memory-hard password hashes (SHA-256, MD5) are unsuitable for password
storage. It implements **pure bitwise SHA-256 and MD5 from scratch** (no OpenSSL,
zero external C++ dependencies), verifies both against **NIST test vectors on the CPU
and the GPU**, and then races four cracking engines against each other:

| Engine | What it measures |
|---|---|
| CPU (1-Thread) | Sequential C++ brute force |
| CPU (OpenMP) | 16-thread OpenMP brute force with atomic early exit |
| CUDA (Kernel Only) | GPU execution time, bracketed by `cudaEvent_t` |
| CUDA (End-to-End) | PCIe host→device transfers + kernels + copyback |

> ⚠️ **Ethics / scope:** everything here targets *passwords the project itself
> generates and hashes locally* — this is a benchmark and a defensive-security
> teaching tool, not an attack tool. Do not use it against systems or hashes you
> don't own.

---

## Headline results (RTX 3050 6GB Laptop GPU)

Full-keyspace worst-case scans, lowercase charset (26 symbols):

| Length | Candidates | CPU 1-Thread | CUDA Kernel | Speedup |
|---:|---:|---:|---:|---:|
| 4 | 475,254 | 5.07 MH/s | 348 MH/s | **69x** |
| 5 | 12,356,630 | 4.86 MH/s | 357 MH/s | **73x** |
| 6 | 321,272,406 | 0.90 MH/s *(sustained)* | 290 MH/s | **322x** |

| Length | MD5 CPU 1-Thread | MD5 CUDA Kernel | Speedup |
|---:|---:|---:|---:|
| 4 | 9.95 MH/s | 979 MH/s | **99x** |
| 5 | 9.35 MH/s | 1,307 MH/s | **140x** |
| 6 | 1.95 MH/s *(sustained)* | 761 MH/s | **389x** |

A 6-character lowercase password's entire 321-million-keyspace falls in
**1.1 s (SHA-256) / 0.42 s (MD5)** on the GPU. The full analysis — including the
PCIe transfer-overhead amortization study and why memory-hard hashes (Argon2,
bcrypt, scrypt) neutralize GPU parallelism — lives in
**[CODEBASE_ANALYSIS.md](CODEBASE_ANALYSIS.md)**.

---

## Project layout

```
├── AGENTS.md                     # Agent environment/build contract
├── build.ps1                     # Windows build (auto-loads vcvars64 + CUDA)
├── Makefile                      # Linux/Colab build (sm_75 + sm_86, -fopenmp)
├── dashboard.py                  # Zero-dependency local web dashboard (stdlib only)
├── START_DEMO.bat                # One-click dashboard launcher (Windows)
├── CODEBASE_ANALYSIS.md          # Full technical breakdown
├── include/
│   ├── cuda_utils.cuh            # CUDA_CHECK macro + CudaTimer (cudaEvent_t)
│   ├── sha256.cuh                # __host__ __device__ SHA-256 (FIPS 180-4)
│   ├── md5.cuh                   # __host__ __device__ MD5 (RFC 1321)
│   ├── cpu_cracker.hpp           # CPU cracker API (HashAlgo, CrackStats)
│   └── gpu_cracker.hpp           # GPU cracker API (GpuCrackStats)
├── src/
│   ├── test_crypto.cu            # NIST test-vector suite (host + device, 12 tests)
│   ├── cpu_cracker.cpp           # 1-thread + OpenMP brute-force/dictionary
│   ├── gpu_cracker.cu            # CUDA kernels: __constant__, grid-stride, atomicExch
│   └── main.cu                   # CLI orchestrator + benchmark/CSV export
├── scripts/
│   ├── gen_wordlist.py           # Generates the 5,000-entry data/wordlist.txt
│   ├── plot_results.py           # matplotlib charts (throughput + speedup)
│   └── fix_csv_speedup.py        # CSV repair utility (provenance)
├── data/wordlist.txt             # 5,000 unique entries (targets at lines 4950/4951)
├── results/                      # benchmark.csv + .png charts + console captures
└── build/                        # Binaries (generated)
```

---

## Requirements

| | Windows (primary) | Linux / Google Colab |
|---|---|---|
| GPU | NVIDIA, Compute Capability 8.6 (Ampere) built for `sm_86` | any (Makefile targets `sm_75` + `sm_86`) |
| Compiler | CUDA Toolkit 13.5 (`nvcc`) + MSVC 14.51 (VS Build Tools) | `nvcc` + g++ |
| Python (optional) | 3.8+ — matplotlib for plots, stdlib only for dashboard | same |
| Libraries | **none** (OpenMP comes with the compiler) | **none** |

---

## Build & run

### Windows (one command)

```powershell
.\build.ps1          # compiles build\test_crypto.exe + build\cuda_cracker.exe
.\build\test_crypto.exe
```

`build.ps1` automatically loads `vcvars64.bat` if `cl.exe` is not in PATH and adds
the CUDA toolkit. Flags used:

```
nvcc -std=c++17 -O3 -arch=sm_86 -Xcompiler "/openmp /EHsc" -allow-unsupported-compiler
```

### Linux / Colab

```bash
make                 # builds both binaries
make wordlist        # regenerates data/wordlist.txt (5,000 entries)
make test            # runs the NIST verification suite
```

### Expected verification output

```
 [PASS] HOST  SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 [PASS] GPU   MD-5   ("password123") = 482c811da5d5b4bc6d497ffa98491e38
 ...
 12/12 tests passed, 0 failed
```

---

## CLI usage

```
cuda_cracker.exe --algo [sha256|md5] --mode [bruteforce|dict|benchmark]
                [--password <str>] [--charset [lower|alnum]]
                [--length <int>] [--threads <int>] [--block <int>]
                [--wordlist <path>]
```

```powershell
# Dictionary attack (GPU + CPU-OMP side by side)
.\build\cuda_cracker.exe --algo sha256 --mode dict --password shadow99

# Brute force: the target password is hashed locally, then recovered
.\build\cuda_cracker.exe --algo sha256 --mode bruteforce --password abc1 --charset alnum --length 4

# Full benchmark: lengths 4/5/6 x 4 engines -> ASCII table + results/benchmark.csv
.\build\cuda_cracker.exe --algo sha256 --mode benchmark --charset lower
.\build\cuda_cracker.exe --algo md5    --mode benchmark --charset lower
```

Benchmark targets are the **last candidate** of each length (e.g. `zzzz`), forcing a
complete keyspace scan so CPU and GPU timings are directly comparable worst-case
numbers.

### Plots

```powershell
python .\scripts\plot_results.py
```
Generates `results/throughput_comparison.png` (log-scale grouped bars per algorithm)
and `results/speedup_scaling.png` (speedup vs CPU 1-Thread across lengths).

---

## Web dashboard (zero dependencies)

```powershell
python dashboard.py        # or double-click START_DEMO.bat
```

Opens `http://127.0.0.1:8080` automatically — a dark-mode single page to pick
algorithm/mode/charset/length, upload a custom `.txt` wordlist, run the cracker or
the NIST suite, inspect the live output console, and render `benchmark.csv` as a
table. **Python standard library only**; binaries are executed locally and nothing
leaves the machine.

---

## Technical highlights

- **Pure bitwise crypto** — identical `__host__ __device__` source compiled for both
  MSVC and SASS; single-block scope (passwords ≤ 55 bytes) halves the register
  footprint.
- **`__constant__` memory** — target digest + charset uploaded once, broadcast-cached
  by all SMs, zero DRAM traffic in the hot loop.
- **Base-N index→password mapping** — the keyspace is the integer range `[0, N^L)`;
  each GPU thread decodes its grid-stride index with repeated `%`/`/`.
- **Grid-stride loops** — one launch configuration (SM×8 blocks × 256 threads) covers
  any keyspace from 26 candidates to 56 billion.
- **`atomicExch` early exit** — the winner publishes its index into a
  `volatile __device__` slot; every thread re-reads it per iteration (warp-uniform,
  branch-free digest comparison elsewhere).
- **Three-clock `cudaEvent_t` timing** — kernel-only, PCIe H2D, and end-to-end
  measured simultaneously in-stream, after a 60 ms clock warm-up (laptop GPUs idle
  at ~210 MHz between runs).
- **Honest benchmarking notes** — the sustained CPU collapse documented in the
  analysis (5.0 → 0.9 MH/s) is real thermal/power clamping on this laptop chassis,
  diagnosed live and explained; a Windows power-plan cap found during debugging
  (45% max processor state on AC) was fixed and recorded.

---

## License

MIT — see [LICENSE](LICENSE). Educational use only; crack responsibly.
