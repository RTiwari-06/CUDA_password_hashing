// gpu_cracker.hpp - CUDA brute-force and dictionary crackers.
// Target digest + charset live in __constant__ memory; kernels use
// grid-stride loops over arbitrarily large keyspaces and atomicExch-based
// early termination. cudaEvent_t timing separates kernel-only execution
// from the PCIe host<->device transfer cost (end-to-end).
#pragma once

#include "cpu_cracker.hpp"   // HashAlgo, CrackStats
#include <string>
#include <vector>

struct GpuCrackStats {
    bool        found      = false;
    std::string password   = "";
    uint64_t    hashes     = 0;      // candidates actually hashed
    float       kernelMs   = 0.0f;   // GPU kernel execution only
    float       h2dMs      = 0.0f;   // PCIe host->device transfers
    float       e2eMs      = 0.0f;   // end-to-end: transfers + kernel + copyback
    double kernelMhps() const { return kernelMs > 0 ? (double)hashes / (kernelMs * 1e-3) / 1e6 : 0.0; }
    double e2eMhps()    const { return e2eMs    > 0 ? (double)hashes / (e2eMs    * 1e-3) / 1e6 : 0.0; }
};

// Brute-force all passwords of length 1..maxLen over `charset`.
GpuCrackStats gpuBruteForce(const std::string& targetHex, const std::string& charset,
                            int maxLen, HashAlgo algo, int blockSize = 256);

// Dictionary attack over a pre-loaded word vector.
GpuCrackStats gpuDictionary(const std::string& targetHex, const std::vector<std::string>& words,
                            HashAlgo algo, int blockSize = 256);

// Convenience: name of device 0 (for reporting).
const char* gpuDeviceName();
