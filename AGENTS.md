# AGENTS.md — CUDA Password Hashing & Brute-Force Benchmark

## Environment & Build Configuration
- OS: Windows 11 (PowerShell)
- GPU: NVIDIA GeForce RTX 3050 (Ampere, Compute Capability `sm_86`)
- Compiler: NVIDIA CUDA Toolkit 13.5 (`nvcc`) + MSVC 14.51 (`cl.exe`)
- Compile Flags: `nvcc -std=c++17 -O3 -arch=sm_86 -Xcompiler "/openmp /EHsc" -allow-unsupported-compiler`
- Cross-Platform Support: Also provide a `Makefile` targeting `sm_75` and `sm_86` with `-Xcompiler -fopenmp` for Linux/Google Colab.

## Architecture & File Layout
- `include/cuda_utils.cuh` — `CUDA_CHECK` error-handling macro and `CudaTimer` event wrapper.
- `include/sha256.cuh` — Header-only, zero-dependency `__host__ __device__` SHA-256 implementation.
- `include/md5.cuh` — Header-only, zero-dependency `__host__ __device__` MD5 implementation.
- `include/cpu_cracker.hpp` & `src/cpu_cracker.cpp` — Sequential (1-thread) and OpenMP multi-threaded CPU brute-force and dictionary crackers.
- `include/gpu_cracker.hpp` & `src/gpu_cracker.cu` — CUDA kernels using `__constant__` memory for target hashes/charsets, grid-stride loops for arbitrary keyspaces, and `atomicExch` early termination.
- `src/test_crypto.cu` — Automated NIST test vector verification suite for both host and device implementations.
- `src/main.cu` — CLI orchestrator (`--algo`, `--mode`, `--password`, `--charset`, `--length`) exporting structured metrics to `results/benchmark.csv`.
- `scripts/plot_results.py` — Python visualization script generating `results/throughput_comparison.png` and `results/speedup_scaling.png`.
- `data/wordlist.txt` — 5,000-entry dictionary file with known test targets near the end.
- `build.ps1` & `Makefile` — Automated build scripts.
- `CODEBASE_ANALYSIS.md` — Comprehensive technical breakdown of every file, kernel optimization, memory hierarchy usage, and verification result.

## Strict Rules
1. Do NOT use OpenSSL or external C++ libraries; implement pure bitwise SHA-256 and MD5.
2. You MUST compile and run `test_crypto.exe` and `cuda_cracker.exe` yourself to verify zero compiler errors and passing assertions before finishing.
3. Measure both CUDA kernel-only execution time and end-to-end time (including PCIe host-to-device memory transfers) using `cudaEvent_t`.
