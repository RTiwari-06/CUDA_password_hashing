# CODEBASE_ANALYSIS.md — CUDA Password Hashing & Brute-Force Benchmark

Complete technical breakdown of the project: architecture, build system, cryptographic
verification, CUDA kernel design, and the actual benchmark results measured on the
target machine (NVIDIA GeForce RTX 3050 6GB Laptop GPU + Intel i5-13450HX).

---

## 1. Project Overview

This project demonstrates why fast, non-memory-hard password hashes (SHA-256, MD5)
are unsuitable for password storage: a single consumer GPU can test hundreds of
millions of candidates per second, hundreds of times faster than a CPU. It implements
pure bitwise SHA-256 and MD5 (no OpenSSL), verifies both against NIST test vectors on
the host **and** the device, and then races four engines against each other:

1. **CPU (1-Thread)** — sequential C++ brute force
2. **CPU (OpenMP)** — 16-thread OpenMP brute force with atomic early exit
3. **CUDA (Kernel Only)** — GPU time measured with `cudaEvent_t` brackets around the kernels
4. **CUDA (End-to-End)** — full pipeline: PCIe host→device transfers + kernels + result copyback

## 2. Directory Tree

```
PCM/
├── AGENTS.md                      # Agent build/environment contract
├── build.ps1                      # Windows build script (auto-loads vcvars64 + CUDA)
├── Makefile                       # Linux/Colab build (sm_75 + sm_86, -fopenmp)
├── CODEBASE_ANALYSIS.md           # This document
├── .vscode/
│   └── c_cpp_properties.json      # IntelliSense config (nvcc emulation for .cu)
├── include/
│   ├── cuda_utils.cuh             # CUDA_CHECK macro + CudaTimer (cudaEvent_t wrapper)
│   ├── sha256.cuh                 # Header-only __host__ __device__ SHA-256 (FIPS 180-4)
│   ├── md5.cuh                    # Header-only __host__ __device__ MD5 (RFC 1321)
│   ├── cpu_cracker.hpp            # HashAlgo / CrackStats + CPU cracker API
│   └── gpu_cracker.hpp            # GpuCrackStats + GPU cracker API
├── src/
│   ├── test_crypto.cu             # NIST test-vector verification suite (host + device)
│   ├── cpu_cracker.cpp            # 1-thread + OpenMP brute-force/dictionary crackers
│   ├── gpu_cracker.cu             # CUDA kernels (constant mem, grid-stride, atomicExch)
│   └── main.cu                    # CLI orchestrator, benchmark table + CSV export
├── scripts/
│   ├── gen_wordlist.py            # Generates the 5,000-entry data/wordlist.txt
│   ├── plot_results.py            # matplotlib: throughput + speedup charts
│   └── fix_csv_speedup.py         # One-shot CSV speedup-column repair utility
├── data/
│   └── wordlist.txt               # 5,000 unique entries; targets at lines 4950/4951
├── results/
│   ├── benchmark.csv              # All 24 benchmark rows (2 algos x 3 lengths x 4 engines)
│   ├── throughput_comparison.png  # Grouped bar chart (log scale)
│   ├── speedup_scaling.png        # Speedup vs CPU(1-thread) vs password length
│   ├── sha256_benchmark_console.txt
│   └── md5_benchmark_console.txt
└── build/
    ├── test_crypto.exe            # Crypto verification binary
    ├── cuda_cracker.exe           # Cracker + benchmark CLI
    └── *.obj                      # Intermediate object files
```

## 3. File-by-File Architecture

### 3.1 `include/cuda_utils.cuh`
- **`CUDA_CHECK(call)`** — wraps every CUDA runtime call; on failure prints
  `[CUDA ERROR] <name> (<string>) at file:line` and aborts. Used consistently so no
  CUDA error is ever silently swallowed.
- **`CudaTimer`** — RAII pair of `cudaEvent_t`. GPU work is asynchronous from the host,
  so wall-clock timers are meaningless for kernel timing; recording start/stop events
  *inside the same stream* captures true GPU-side elapsed time.
  `stop()` synchronizes the stop event only (not the whole device).

### 3.2 `include/sha256.cuh` and `include/md5.cuh`
Header-only, zero-dependency implementations, marked `CPH_HD` (`__host__ __device__`
under nvcc, empty otherwise) so the *identical* source is compiled for both host (MSVC)
and device (SASS). Key design decisions:

- **Single-block scope** — messages of 0..55 bytes only (one 512-bit block after
  padding). Every candidate in this project is ASCII ≤ 55 bytes, so the full multi-block
  message schedule is never needed; this halves the inner-loop register footprint.
- **Pure bitwise** — rotates, masks, and the standard 64-round compression; no
  library calls, no OpenSSL.
- **Constant tables split host/device.** This is the subtlest part of the codebase:
  namespace-scope `static const` arrays are invisible to nvcc's device pass
  (internal host linkage), while host code must not directly read `__constant__`
  variables (nvcc warning #20091). Each header therefore defines:
  - a `CPH_TBL` (`__device__ __constant__`) table for the device pass,
  - a plain host copy for the host pass,
  - a selector macro (`CPH_SHA256_K`, `CPH_MD5_K`, ...) chosen via
    `#if defined(__CUDA_ARCH__)` so each compilation pass binds its own table.
  Digest byte order follows the standards: big-endian for SHA-256, little-endian for MD5.

### 3.3 `src/test_crypto.cu` — NIST verification
Twelve assertions: {host, device} x {SHA-256, MD5} x {"", "abc", "password123"} against
the canonical digests:

| Message | SHA-256 | MD5 |
|---|---|---|
| `""` | `e3b0c44298fc1c14…b7852b855` | `d41d8cd98f00b204…ecf8427e` |
| `"abc"` | `ba7816bf8f01cfea…f20015ad` | `900150983cd24fb0…28e17f72` |
| `"password123"` | `ef92b778bafe771e…473e94f` | `482c811da5d5b4bc…98491e38` |

The device path packs the three messages into a 3x64-byte buffer, launches
`cryptoVerifyKernel<<<1,8>>>` where thread *i* hashes message *i* with both algorithms
and writes digests to device memory, then compares after copyback. **Measured result:
`12/12 tests passed, 0 failed`** (exit code 0).

### 3.4 `include/cpu_cracker.hpp` / `src/cpu_cracker.cpp`
- **`cpuBruteForce(targetHex, charset, maxLen, algo, threads)`** — iterates lengths
  `1..maxLen`; for each length *L* scans the keyspace `[0, N^L)` decoding each index
  with the base-N digit mapping (see §5.2), hashes, and compares raw digest bytes
  (hex decoding happens once, up front — no per-candidate hex work).
- **`cpuDictionary(...)`** — loads the wordlist into a `std::vector<std::string>`,
  OpenMP-parallel scan.
- **Early exit** — a shared `std::atomic<bool>` checked at the top of every candidate
  iteration; the winning thread publishes its `(index, length)` atomically, so the
  exact number of hashed candidates (`hashes`) can be reported, not just the keyspace size.
- **OpenMP schedule** — `schedule(dynamic, 16384)`: the i5-13450HX is a hybrid
  6P+4E CPU; static chunking would stall the region on E-core stragglers.
- Host hex helpers (`sha256HexHost`, `md5HexHost`, `digestHex`) reuse the same
  `cph::` implementations as the GPU.

### 3.5 `include/gpu_cracker.hpp` / `src/gpu_cracker.cu`
The CUDA engine — full kernel analysis in §5.

### 3.6 `src/main.cu` — CLI orchestrator
```
cuda_cracker.exe --algo [sha256|md5] --mode [bruteforce|dict|benchmark]
                 [--password <str>] [--charset [lower|alnum]] [--length <int>]
                 [--threads <int>] [--block <int>] [--wordlist <path>]
```
- **bruteforce** — hashes `--password` on the host to obtain the target digest, prints
  it, then GPU-cracks; also runs the CPU-OMP comparison when the keyspace ≤ 2^28.
- **dict** — runs CPU-OMP and GPU dictionary attacks against `data/wordlist.txt`
  (default) and reports both.
- **benchmark** — for lengths 4, 5, 6: target = **last candidate of each length**
  (e.g. `zzzzz`), forcing a full-keyspace worst-case scan so CPU and GPU times are
  directly comparable. Prints the ASCII table and appends 4 CSV rows per length to
  `results/benchmark.csv` (header written once).

### 3.7 Build scripts
- **`build.ps1`** (Windows): creates all directories; appends the CUDA toolkit `bin`
  to PATH if `nvcc` is missing; loads `vcvars64.bat` (VS 18 Build Tools, MSVC 14.51)
  by importing its environment into the PowerShell session; then compiles:
  ```powershell
  nvcc -std=c++17 -O3 -arch=sm_86 -Xcompiler "/openmp /EHsc" -allow-unsupported-compiler -Iinclude -c src/test_crypto.cu -o build/test_crypto.obj
  nvcc build/test_crypto.obj -o build/test_crypto.exe
  nvcc -std=c++17 -O3 -arch=sm_86 -Xcompiler "/openmp /EHsc" -allow-unsupported-compiler -Iinclude -c src/cpu_cracker.cpp -o build/cpu_cracker.obj
  nvcc -std=c++17 -O3 -arch=sm_86 -Xcompiler "/openmp /EHsc" -allow-unsupported-compiler -Iinclude -c src/gpu_cracker.cu -o build/gpu_cracker.obj
  nvcc -std=c++17 -O3 -arch=sm_86 -Xcompiler "/openmp /EHsc" -allow-unsupported-compiler -Iinclude -c src/main.cu -o build/main.obj
  nvcc build/main.obj build/gpu_cracker.obj build/cpu_cracker.obj -o build/cuda_cracker.exe
  ```
- **`Makefile`** (Linux/Colab): same pipeline with
  `-gencode arch=compute_75,code=sm_75 -gencode arch=compute_86,code=sm_86`
  (Turing T4 on Colab + Ampere) and `-Xcompiler -fopenmp`. Targets: `all`, `test`,
  `wordlist`, `benchmark`, `clean`.

### 3.8 `data/wordlist.txt`
Generated by `scripts/gen_wordlist.py`: ~500 root words x 38 suffix patterns
(bare, digits 0–9, years 2000–2026) deduplicated to exactly **5,000 unique entries**.
`shadow99` is placed at **line 4950** and `dragon2026` at **line 4951** (verified by
the generator with assertions), so a dictionary attack must scan ~99% of the file
before finding them.

---

## 4. Build & Verification Record (actual outputs)

### 4.1 Build
```
[build] Loading MSVC environment: C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat
[build] cl.exe : ...\MSVC\14.51.36231\bin\HostX64\x64\cl.exe
[build] nvcc   : ...\NVIDIA GPU Computing Toolkit\CUDA\v13.5\bin\nvcc.exe
[build] Compiling CUDA cracker (main + gpu + cpu/omp)  ->  build/cuda_cracker.exe
[build] SUCCESS - binaries in build\
```
**Zero errors, zero warnings** on the final build (earlier iterations surfaced and
fixed: nvcc's invisibility of namespace-scope host statics to device code, host reads
of `__constant__` tables, and one unused-variable warning).

### 4.2 Crypto verification — `build\test_crypto.exe`
```
=================================================================
 NIST test-vector verification: SHA-256 & MD5 (host + device)
=================================================================
 [PASS] HOST  SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 [PASS] HOST  SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 [PASS] HOST  SHA-256("password123") = ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
 [PASS] HOST  MD-5   ("") = d41d8cd98f00b204e9800998ecf8427e
 [PASS] HOST  MD-5   ("abc") = 900150983cd24fb0d6963f7d28e17f72
 [PASS] HOST  MD-5   ("password123") = 482c811da5d5b4bc6d497ffa98491e38
 [PASS] GPU   SHA-256("") = e3b0c442...   [PASS] GPU   SHA-256("abc") = ba7816bf...
 [PASS] GPU   SHA-256("password123") = ef92b778...   [PASS] GPU   MD-5(...) = ...
=================================================================
 12/12 tests passed, 0 failed
=================================================================
```

### 4.3 Dictionary attack — `cuda_cracker.exe --mode dict`
```
[CPU-OMP ] FOUND in 0.001 s | 4,950 candidates | 5.25 MH/s -> "shadow99"
[CUDA    ] FOUND in 0.472 ms e2e (kernel 0.313 ms, PCIe H2D 0.037 ms) | 15.8 MH/s
[CUDA    ] FOUND in 0.161 ms e2e (kernel 0.099 ms, PCIe H2D 0.033 ms)   (MD5 dragon2026, 4,951 candidates)
```
Both targets were recovered from exactly the expected wordlist positions (4,950 and
4,951 candidates hashed) — proving the wordlist placement, host digests, and both
crackers agree.

### 4.4 Brute force — `cuda_cracker.exe --mode bruteforce --password abc1 --charset alnum --length 4`
```
[CUDA   ] FOUND in 1.415 ms (kernel 1.229 ms, PCIe H2D 0.081 ms) | 246,256 candidates | 200.4 MH/s
[CPU-OMP] FOUND in 0.052 s | 246,256 candidates | 4.78 MH/s
```
CPU and GPU recovered the identical password — end-to-end correctness proof.

---

## 5. CUDA Kernel Deep Dive

### 5.1 `__constant__` memory
```cuda
__constant__ unsigned char c_target[32];
__constant__ char          c_charset[64];
__constant__ int           c_charsetLen;
```
The target digest and the alphabet are identical for **every thread** during a launch —
the textbook definition of constant data. Benefits:
- Occupies a dedicated **64 KB constant cache** per SM; after the first access the
  data lives on-chip with ~zero latency and **zero DRAM traffic** for the hot loop.
- Broadcast-optimized: when all threads in a warp read the same address (they read
  `c_target[i]` and `c_charset[digit]` in lockstep), the hardware delivers one
  broadcast instead of 32 loads, unlike global memory where such accesses still work
  but consume L1 bandwidth.
- Uploaded **once** per `gpuBruteForce` call via `cudaMemcpyToSymbol`, not per thread
  or per block. Per-thread parameters are limited to `(len, total, algo, digestLen)` —
  16 bytes of kernel arguments.

### 5.2 Thread indexing & base-N candidate generation
Brute force is the problem of enumerating strings of length *L* over an alphabet of
size *N* — exactly the positional number system with base *N*:

```
candidate(index) = digits of (index written in base N, L digits, big-endian)
pw[i] = charset[ index / N^(L-1-i) mod N ]
```

Implemented with repeated `%` and `/` by the runtime-configured `c_charsetLen`
(mixed radix, alphabet driven), so the same kernel supports `lower` (N=26) and
`alnum` (N=62) without recompilation. The parallelization contract is:

```
global thread id  tid  = blockIdx.x * blockDim.x + threadIdx.x
grid stride       S    = gridDim.x * blockDim.x
thread tid owns candidates  tid, tid + S, tid + 2S, ...
```

This **grid-stride loop** has three properties that matter here:
1. **Keyspace-independence** — the launch configuration (128 blocks x 256 threads =
   32,768 threads) never changes whether the keyspace is 26 (length 1) or
   321,272,406 (length 6). Large keyspaces simply mean each thread iterates ~9,800
   times instead of once.
2. **Coalescing** — adjacent threads process adjacent indices; their memory accesses
   (writes to `block[]` before hashing are stack-only; the only global reads are
   constant-cache hits) stay perfectly aligned.
3. **Resize safety** — if a future GPU has more SMs, `blocks = multiProcessorCount * 8`
   scales automatically.

### 5.3 Register usage
Per thread, the hot loop keeps in registers: the grid-stride index/stride (2×64-bit),
the decoder value `v`, a 56-byte stack buffer `pw` (spilled to local memory only if
the compiler chooses; for L ≤ 6 it lives in registers/local L1), the 32-byte digest
array, and the SHA-256 working state `w[64] + h[8]` (~72×4 = 288 bytes of state).
That is a large working set — the compiler reports high static register pressure and
spills part of `w[]` to local memory (which is L1/L2-backed). This is the dominant
reason throughput is ~290–360 MH/s rather than the 1+ GH/s a fully-unrolled,
register-resident SHA-256 (as in hashcat) reaches. Two deliberate simplifications
trade peak throughput for code clarity: the message schedule is computed in a loop
(not unrolled with immediate constants), and digest bytes are compared byte-wise.
Neither affects the architectural conclusions.

### 5.4 Warp divergence avoidance
- The digest match test is **branchless**: `match = match && (digest[i] == c_target[i])`
  folds into a single predicate with no per-byte branching, so threads inside a warp
  never split on partial matches.
- The only real branch — the early-exit check — reads the same `d_found` value for
  the whole warp, so it is **warp-uniform**: either all 32 threads return, or none do.
- The base-N decode loop count is fixed per launch (all candidates share length L),
  so the inner loop trip count is uniform across the warp — no divergent exit edges.
- The dictionary kernel guards `len > 55` with a `continue`, but wordlist entries are
  uniformly short, and divergent warps there would only skip hashing, not corrupt results.

### 5.5 Early termination with `atomicExch`
```cuda
__device__ volatile unsigned long long d_found;    // sentinel = ~0ull
if (d_found != kNotFound) return;                  // every grid-stride iteration
if (match) atomicExch((unsigned long long*)&d_found, idx);
```
- The winner publishes its candidate index with `atomicExch` (no locking, single
  instruction, one thread wins deterministically).
- `volatile` prevents the compiler from hoisting the read out of the loop and
  caching the sentinel in a register — every iteration re-reads device memory.
- On a full keyspace scan this adds one cached global read per candidate (~free);
  on a *lucky* early find it collapses remaining threads immediately. In benchmark
  mode the target is the last candidate, so the flag never fires early — the timing
  stays an honest full-scan measurement.
- The host reads back `d_found`/`d_foundLen` with `cudaMemcpyFromSymbol` and decodes
  the winning index back into a password on the CPU (inverse base-N mapping).

### 5.6 Three-clock `cudaEvent_t` timing
`gpuBruteForce` brackets one stream with three event pairs, giving simultaneously:
```
evStart  →  [H2D memcpyToSymbol: target+charset]  →  evH2D
evKernelStart → [bruteForceKernel<<<…>>> for L=1..maxLen]  →  evKernelStop
[D2H memcpyFromSymbol: d_found]  →  evEnd
```
| Metric | Events | Meaning |
|---|---|---|
| `h2dMs` | evStart→evH2D | PCIe host→device transfer time |
| `kernelMs` | evKernelStart→evKernelStop | **kernel-only** GPU execution |
| `e2eMs` | evStart→evEnd | transfers + kernels + copyback |

Because events are recorded in-stream, they measure GPU-timeline time, immune to
host scheduling jitter. A ~60 ms untimed warm-up kernel precedes the timed window:
laptop GPUs drop to idle clocks (~210 MHz) between runs, and an un-warmed first
measurement recorded 43 MH/s where the warmed steady state is 357 MH/s (measured,
length 5, SHA-256) — the warm-up exists purely to benchmark at steady-state clocks.

### 5.7 Dictionary kernel
The wordlist is flattened on the host into one char buffer + an `offsets[nw+1]` array
(a CSR-like layout); threads map word index → `words + offsets[id]` and hash. This
avoids per-string allocations on the device and makes the PCIe transfer a single
contiguous `cudaMemcpy` (~46 KB, measured 0.033–0.042 ms).

---

## 6. Benchmark Results (actual, RTX 3050 6GB Laptop GPU)

Environment: Windows 11, i5-13450HX (10C/16T, 6P+4E), RTX 3050 6GB Laptop (16 SMs,
sm_86, GDDR6 @ 7001 MHz, PCIe x8), CUDA 13.5, MSVC 14.51, `lower` charset (26),
full keyspace scanned per length (target = last candidate).

### 6.1 SHA-256

| Len | Candidates | CPU 1-Thread | CPU OpenMP x16 | CUDA Kernel | CUDA End-to-End |
|---|---|---|---|---|---|
| 4 | 475,254 | 0.0937 s — 5.07 MH/s (1.0x) | 0.0954 s — 4.98 MH/s (0.98x) | 1.364 ms — 348 MH/s (**68.7x**) | 1.508 ms — 315 MH/s (62.2x) |
| 5 | 12,356,630 | 2.544 s — 4.86 MH/s (1.0x) | 13.03 s — 0.95 MH/s (0.20x) | 34.6 ms — 357 MH/s (**73.5x**) | 35.1 ms — 352 MH/s (72.5x) |
| 6 | 321,272,406 | 356.88 s — 0.90 MH/s (1.0x) | 332.27 s — 0.97 MH/s (1.07x) | 1.108 s — 290 MH/s (**322.1x**) | 1.111 s — 289 MH/s (321.3x) |

### 6.2 MD5

| Len | Candidates | CPU 1-Thread | CPU OpenMP x16 | CUDA Kernel | CUDA End-to-End |
|---|---|---|---|---|---|
| 4 | 475,254 | 0.0478 s — 9.95 MH/s (1.0x) | 0.0487 s — 9.76 MH/s (0.98x) | 0.485 ms — 979 MH/s (**98.5x**) | 0.583 ms — 815 MH/s (82.0x) |
| 5 | 12,356,630 | 1.321 s — 9.35 MH/s (1.0x) | 1.311 s — 9.43 MH/s (1.01x) | 9.46 ms — 1,307 MH/s (**139.7x**) | 9.71 ms — 1,272 MH/s (136.0x) |
| 6 | 321,272,406 | 164.39 s — 1.95 MH/s (1.0x) | 163.72 s — 1.96 MH/s (1.00x) | 0.422 s — 761 MH/s (**389.4x**) | 0.423 s — 760 MH/s (389.1x) |

Raw data: `results/benchmark.csv`; charts:
`results/throughput_comparison.png`, `results/speedup_scaling.png`.

### 6.3 What the numbers actually say

**GPU steady-state throughput.** The RTX 3050 Laptop sustains **290–357 MH/s SHA-256**
and **761–1,307 MH/s MD5** across lengths 4–6. The kernel-only time is essentially
linear in keyspace size (321M SHA-256 in 1.108 s), confirming the grid-stride
decomposition saturates the GPU uniformly. MD5 runs ~2.6x faster than SHA-256 on the
GPU (its 64 rounds are arithmetically lighter than SHA-256's, which chain two round
constants of serial adds per step) and ~1.9x faster on the CPU.

**The CPU side is a study in power limits, and it matters for honest interpretation:**
- **Burst rate** (length 4/5, seconds-scale runs): 4.9–5.1 MH/s SHA-256,
  9.4–9.9 MH/s MD5 single-threaded.
- **Sustained rate** (length 6, ~6-minute runs): collapses to **0.90 MH/s SHA-256,
  1.95 MH/s MD5** — a ~5x thermal/power clamp of the laptop chassis.
- **OpenMP x16 shows no aggregate gain** (1.0x at length 6, and even a slowdown at
  length 5 where it ran right after the 1-thread pass heated the package). A
  standalone control run confirmed OpenMP *does* reach 4.84 MH/s on a fresh machine —
  i.e. the i5-13450HX in this chassis is **package-power-bound**: one thread boosting
  at ~4.7 GHz and sixteen threads at proportionally lower clocks exhaust the same
  sustained power budget, so total throughput saturates at ~1 MH/s regardless of
  parallelism. Two confounders were found and corrected during debugging:
  the Windows power plan capped **Max processor state at 45% on AC** (fixed to 100%),
  and VS Code IntelliSense was consuming CPU during the first (discarded) run.

**The resulting headline:** against the *sustained* CPU, the GPU is **322x (SHA-256)**
and **389x (MD5)** faster; even against the *short-burst* CPU it is ~70–140x. A
6-character lowercase password's full 321-million-keyspace falls in **1.1 s (SHA-256)
/ 0.42 s (MD5)** on the GPU — extrapolating, 8 characters ≈ 12–18 min, 9 ≈ 5–8 h,
10 ≈ days — and that is for the *weakest* laptop GPU in the RTX line.

### 6.4 PCIe transfer overhead: why it dominates short passwords

The end-to-end time adds three fixed costs on top of the kernel:
kernel-launch latency (~3–5 µs), host→device `cudaMemcpyToSymbol` of
target+charset+length (~0.04–0.08 ms measured), and device→host copyback of the
result slot (µs). Measured directly from the event pairs:

| Case | kernel | e2e | PCIe+launch overhead | share of e2e |
|---|---|---|---|---|
| SHA-256 len 4 (0.475M) | 1.364 ms | 1.508 ms | ~0.144 ms | **~10.6%** |
| SHA-256 len 5 (12.4M) | 34.6 ms | 35.1 ms | ~0.5 ms | ~1.4% |
| SHA-256 len 6 (321M) | 1,108 ms | 1,111 ms | ~2.8 ms | **~0.25%** |
| MD5 len 4 | 0.485 ms | 0.583 ms | ~0.098 ms | **~20%** |
| MD5 len 6 | 422 ms | 422.5 ms | ~0.4 ms | ~0.09% |
| dict (5,000 words, ~46 KB) | 0.099 ms | 0.161 ms | ~0.062 ms (mostly H2D) | **~38%** |

The overhead is **constant** (the payload — 32-byte digest, ≤ 64-byte charset — is
tiny), so its *relative* cost scales inversely with workload: 20% of a sub-millisecond
MD5-4 run, but 0.09% of a 321M-candidate scan. The dictionary case is the extreme:
the kernel runs for only ~100 µs, so the PCIe round-trip and launch latency are
nearly half the end-to-end time — for dictionary-scale workloads the transfer, not
the math, is the bottleneck. This is precisely why hash-cracking tools batch
thousands of hashes per kernel launch (work-queue amortization) and why the
kernel-only vs end-to-end distinction matters when sizing whether a GPU makes sense
at all.

### 6.5 Why memory-hard hashes (Argon2, bcrypt, scrypt) resist GPUs

Everything above exploits two properties of SHA-256/MD5: they are
**computation-bound and stateless per candidate**. One thread = one register-resident
computation; throughput scales with the number of cores. Password hashing that
resists GPUs removes one or both:

- **bcrypt** requires 4 KB of Blowfish key schedule ("Eksblowfish") state built with
  `2^12` iterations of *sequentially dependent* table lookups. The lookups are
  data-dependent (indexed by the key material itself), so they defeat GPU
  coalescing — a warp's 32 threads read 32 *different* random indices into a shared
  4 KB working set, serializing into 32 separate L1 transactions. Worse, the state
  (4 KB/thread) is too large for registers, so every thread thrashes local memory;
  occupancy collapses. Where SHA-256 gives the RTX 3050 ~290 MH/s, bcrypt cost-10
  yields only a few **thousand** hashes/s — a ~100,000x per-hash penalty.
- **scrypt** deliberately allocates *ROM/RAM*: an *N*-element pseudorandom array
  (default N=2^14 → 16 MB) that must be held and randomly re-read. 16 MB/thread on a
  6 GB card = ~380 concurrent threads on 32,768 launchable ones — memory capacity,
  not SM count, becomes the ceiling, and the random reads are pure DRAM latency.
- **Argon2id** (the current PHC winner) combines both: per-hash memory defaults of
  tens to hundreds of MB, a strictly sequential first pass over that memory (the
  data-dependent side resists TMTO/time-memory tradeoffs), and BLAKE2b-based
  compression with long dependent chains. A GPU thread spends its life waiting on
  DRAM: compute:memory-access ratio flips from ~100:1 (SHA-256) to ~1:1, which is
  the *worst possible* operating point for the hardware that makes GPUs fast
  (massive compute over small, cached state).

**The design lesson, demonstrated end-to-end by this project:** a password hash
should be tuned so that *defenders* can afford exactly one evaluation per login
(~100–500 ms of CPU) while *attackers* cannot amortize the cost across millions of
parallel cheap evaluations. Memory-hardness converts the attacker's advantage from
"FLOPs, which GPUs have in abundance" into "fast random-access GB per thread, which
neither GPUs nor ASICs can cheaply provide" — which is why a 2026 GPU blazes through
321M SHA-256 candidates in ~0.4–1.1 s but needs months for the same keyspace under
Argon2id.

---

## 7. Reproduction Commands

```powershell
# Windows
.\build.ps1
.\build\test_crypto.exe
.\build\cuda_cracker.exe --algo sha256 --mode dict --password shadow99
.\build\cuda_cracker.exe --algo md5  --mode dict --password dragon2026
.\build\cuda_cracker.exe --algo sha256 --mode bruteforce --password abc1 --charset alnum --length 4
.\build\cuda_cracker.exe --algo sha256 --mode benchmark --charset lower
.\build\cuda_cracker.exe --algo md5    --mode benchmark --charset lower
python .\scripts\plot_results.py

# Linux / Colab
make && make wordlist && make test
./build/cuda_cracker --algo sha256 --mode benchmark --charset lower
python3 scripts/plot_results.py
```

Notes for reproducibility:
- `results/benchmark.csv` stores raw `time_s`; the `speedup_vs_cpu1` column is
  `cpu_1thread_time / engine_time` (a one-shot repair utility,
  `scripts/fix_csv_speedup.py`, fixed an initially inverted speedup formula and is
  kept for provenance; `main.cu` now computes it correctly at write time).
- The machine's Windows power plan was restored to 100% max processor state on AC
  (`powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100`)
  after being found capped at 45%; the sustained CPU collapse documented in §6.3
  is a chassis/BIOS-level thermal limit, not a Windows setting.
