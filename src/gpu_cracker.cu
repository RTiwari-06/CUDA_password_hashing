// gpu_cracker.cu - CUDA brute-force and dictionary cracking kernels.
//
// Design notes (detailed analysis in CODEBASE_ANALYSIS.md):
//  - Target digest and charset are uploaded ONCE into __constant__ memory.
//    Every thread reads them via the constant cache (broadcast-friendly,
//    no DRAM traffic, ~no latency after first access).
//  - Brute-force kernel is a grid-stride loop: any grid size can cover any
//    keyspace size (uint64 candidate index), and the same kernel works for
//    a tiny test keyspace and a 62^6 keyspace alike.
//  - Early termination: a __device__ volatile "found" slot. The winning
//    thread publishes its candidate index with atomicExch; all other threads
//    read the volatile slot at the top of every grid-stride iteration and
//    bail out immediately (drastically cutting wasted work on big keyspaces).
//  - Timing: three cudaEvent_t pairs inside one stream give kernel-only ms,
//    PCIe H2D ms, and end-to-end ms (transfers + kernels + copyback).
//  - Warp divergence: the digest comparison is branchless (flag accumulated
//    over all digest bytes), so threads in a warp do not split on the match
//    test; the only early-out branch is warp-uniform in practice because
//    neighbors exit on the same found-flag read.

#include "gpu_cracker.hpp"

#include "sha256.cuh"
#include "md5.cuh"
#include "cuda_utils.cuh"

#include <cuda_runtime.h>
#include <cstdio>
#include <cstring>
#include <chrono>

namespace {

constexpr int kMaxPasswordLen = 55;
constexpr unsigned long long kNotFound = 0xFFFFFFFFFFFFFFFFull;

// ---- __constant__ memory: broadcast-read by every thread --------------------
__constant__ unsigned char c_target[32];   // target digest (MD5 uses bytes 0..15)
__constant__ char          c_charset[64];  // candidate alphabet
__constant__ int           c_charsetLen;   // N of the base-N mapping

// ---- early-exit slots (device-scope, volatile so reads are not cached) ------
__device__ volatile unsigned long long d_found    = kNotFound;
__device__ volatile int                d_foundLen = -1;

__device__ inline bool digestMatches(const uint8_t* digest, int digestLenBytes)
{
    bool match = true;
    for (int i = 0; i < digestLenBytes; ++i)   // branchless reduce -> no warp split
        match = match && (digest[i] == c_target[i]);
    return match;
}

__device__ inline void publish(unsigned long long idx, int len)
{
    atomicExch((unsigned long long*)&d_found, idx);
    atomicExch((int*)&d_foundLen, len);
}

// ---------------------------------------------------------------------------
// Brute-force kernel for a FIXED candidate length L.
// Each thread hashes candidates idx, idx+stride, ... (grid-stride) of the
// [0, N^L) keyspace, decoding idx with the base-N digit mapping.
// ---------------------------------------------------------------------------
__global__ void bruteForceKernel(int len, unsigned long long total, int algo, int digestLen)
{
    const unsigned long long stride = (unsigned long long)gridDim.x * blockDim.x;
    for (unsigned long long idx = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
         idx < total;
         idx += stride)
    {
        if (d_found != kNotFound) return;         // cooperative early exit

        char pw[kMaxPasswordLen + 1];
        unsigned long long v = idx;
        for (int i = len - 1; i >= 0; --i) {      // base-N index -> password
            pw[i] = c_charset[v % c_charsetLen];
            v /= c_charsetLen;
        }

        uint8_t digest[32];
        if (algo == 0) cph::sha256((const uint8_t*)pw, (uint32_t)len, digest);
        else           cph::md5  ((const uint8_t*)pw, (uint32_t)len, digest);

        if (digestMatches(digest, digestLen)) publish(idx, len);
    }
}

// ---------------------------------------------------------------------------
// Dictionary kernel: wordlist is uploaded as one flat char buffer plus an
// offsets array; thread i hashes words[i]. Grid-stride over numWords.
// ---------------------------------------------------------------------------
__global__ void dictKernel(const char* words, const unsigned int* offsets,
                           int numWords, int algo, int digestLen)
{
    const int stride = gridDim.x * blockDim.x;
    for (int id = blockIdx.x * blockDim.x + threadIdx.x; id < numWords; id += stride)
    {
        if (d_found != kNotFound) return;         // cooperative early exit

        const int start = (int)offsets[id];
        const int len   = (int)offsets[id + 1] - start;
        if (len <= 0 || len > kMaxPasswordLen) continue;

        uint8_t digest[32];
        if (algo == 0) cph::sha256((const uint8_t*)(words + start), (uint32_t)len, digest);
        else           cph::md5  ((const uint8_t*)(words + start), (uint32_t)len, digest);

        if (digestMatches(digest, digestLen)) publish((unsigned long long)id, len);
    }
}

} // namespace

// ----------------------------------------------------------------- helpers

static void hexToBytesDevice(const std::string& hex, unsigned char* out, int bytes)
{
    if ((int)hex.size() != bytes * 2) {
        fprintf(stderr, "[gpu] invalid target digest hex (need %d bytes): %s\n", bytes, hex.c_str());
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < bytes; ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "[gpu] invalid hex digit in target digest\n");
            exit(EXIT_FAILURE);
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
}

static int deviceBlockCount(int blockSize)
{
    cudaDeviceProp prop;
    int dev = 0;
    CUDA_CHECK(cudaGetDevice(&dev));
    CUDA_CHECK(cudaGetDeviceProperties(&prop, dev));
    // Enough waves to saturate the SMs; grid-stride covers the rest.
    return prop.multiProcessorCount * 8;
}

const char* gpuDeviceName()
{
    static cudaDeviceProp prop;
    int dev = 0;
    CUDA_CHECK(cudaGetDevice(&dev));
    CUDA_CHECK(cudaGetDeviceProperties(&prop, dev));
    return prop.name;
}

// ------------------------------------------------------------- brute force

GpuCrackStats gpuBruteForce(const std::string& targetHex, const std::string& charset,
                            int maxLen, HashAlgo algo, int blockSize)
{
    GpuCrackStats stats;
    const int algoId  = (algo == HashAlgo::SHA256) ? 0 : 1;
    const int dlen    = (algo == HashAlgo::SHA256) ? 32 : 16;
    const int n       = (int)charset.size();
    const int blocks  = deviceBlockCount(blockSize);

    // Host-side keyspaces: count[L] = N^L, offset[L] = sum of count[1..L-1].
    unsigned long long count[64]  = {0}, offset[64] = {0};
    {
        unsigned long long p = 1, acc = 0;
        for (int L = 1; L <= maxLen; ++L) {
            p *= (unsigned long long)n;
            count[L] = p;
            offset[L] = acc;
            acc += p;
        }
    }
    const unsigned long long total = offset[maxLen] + count[maxLen];

    // ---- staging buffers (host) ------------------------------------------
    unsigned char hTarget[32];
    memset(hTarget, 0, sizeof(hTarget));
    hexToBytesDevice(targetHex, hTarget, dlen);

    // ---- single timed pipeline:  H2D -> kernels (all lengths) -> D2H -------
    cudaEvent_t evStart, evH2D, evKernelStart, evKernelStop, evEnd;
    CUDA_CHECK(cudaEventCreate(&evStart));
    CUDA_CHECK(cudaEventCreate(&evH2D));
    CUDA_CHECK(cudaEventCreate(&evKernelStart));
    CUDA_CHECK(cudaEventCreate(&evKernelStop));
    CUDA_CHECK(cudaEventCreate(&evEnd));

    // Reset early-exit slots (untimed: host-side prepare step).
    unsigned long long none = kNotFound;
    int minusOne = -1;
    CUDA_CHECK(cudaMemcpyToSymbol(d_found,    &none,     sizeof(none)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_foundLen, &minusOne, sizeof(minusOne)));
    CUDA_CHECK(cudaDeviceSynchronize());

    // ---- untimed warm-up (~60 ms of real GPU load) -------------------------
    // Laptop GPUs drop to their idle power state between runs; the first
    // timed kernel would otherwise execute at ~1/7 of boost clock and
    // poison the measurement. This burns real candidates until the clock
    // has ramped, then resets state before the timed window.
    {
        const int wL = maxLen < 4 ? maxLen : 4;
        unsigned long long wTotal = count[wL] < 500000ull ? count[wL] : 500000ull;
        auto wT0 = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - wT0).count() < 60) {
            bruteForceKernel<<<blocks, blockSize>>>(wL, wTotal, algoId, dlen);
            CUDA_CHECK(cudaDeviceSynchronize());
        }
        CUDA_CHECK(cudaMemcpyToSymbol(d_found,    &none,     sizeof(none)));
        CUDA_CHECK(cudaMemcpyToSymbol(d_foundLen, &minusOne, sizeof(minusOne)));
        CUDA_CHECK(cudaDeviceSynchronize());
    }

    CUDA_CHECK(cudaEventRecord(evStart));
    CUDA_CHECK(cudaMemcpyToSymbol(c_target,     hTarget,          32));
    CUDA_CHECK(cudaMemcpyToSymbol(c_charset,    charset.c_str(),  (size_t)n));
    CUDA_CHECK(cudaMemcpyToSymbol(c_charsetLen, &n,               sizeof(int)));
    CUDA_CHECK(cudaEventRecord(evH2D));                    // PCIe transfer measured here

    CUDA_CHECK(cudaEventRecord(evKernelStart));
    for (int L = 1; L <= maxLen; ++L) {
        bruteForceKernel<<<blocks, blockSize>>>(L, count[L], algoId, dlen);
    }
    CUDA_CHECK(cudaEventRecord(evKernelStop));             // kernel-only time bracket

    // Copy results back (inside the end-to-end window).
    unsigned long long hFound = kNotFound;
    int hFoundLen = -1;
    CUDA_CHECK(cudaMemcpyFromSymbol(&hFound, d_found, sizeof(hFound)));
    CUDA_CHECK(cudaMemcpyFromSymbol(&hFoundLen, d_foundLen, sizeof(hFoundLen)));
    CUDA_CHECK(cudaEventRecord(evEnd));

    CUDA_CHECK(cudaEventSynchronize(evEnd));
    CUDA_CHECK(cudaGetLastError());

    float e2e = 0, h2d = 0, ker = 0;
    CUDA_CHECK(cudaEventElapsedTime(&e2e, evStart,       evEnd));
    CUDA_CHECK(cudaEventElapsedTime(&h2d, evStart,       evH2D));
    CUDA_CHECK(cudaEventElapsedTime(&ker, evKernelStart, evKernelStop));
    stats.e2eMs = e2e; stats.h2dMs = h2d; stats.kernelMs = ker;

    if (hFound != kNotFound) {
        stats.found = true;
        // Decode the winning index back into a password on the host.
        char pw[kMaxPasswordLen + 1];
        unsigned long long v = hFound;
        for (int i = hFoundLen - 1; i >= 0; --i) { pw[i] = charset[v % n]; v /= (unsigned long long)n; }
        pw[hFoundLen] = '\0';
        stats.password.assign(pw, (size_t)hFoundLen);
        stats.hashes = offset[hFoundLen] + hFound + 1;
    } else {
        stats.hashes = total;
    }

    cudaEventDestroy(evStart); cudaEventDestroy(evH2D);
    cudaEventDestroy(evKernelStart); cudaEventDestroy(evKernelStop);
    cudaEventDestroy(evEnd);
    return stats;
}

// --------------------------------------------------------------- dictionary

GpuCrackStats gpuDictionary(const std::string& targetHex, const std::vector<std::string>& words,
                            HashAlgo algo, int blockSize)
{
    GpuCrackStats stats;
    const int algoId = (algo == HashAlgo::SHA256) ? 0 : 1;
    const int dlen   = (algo == HashAlgo::SHA256) ? 32 : 16;
    const int nw     = (int)words.size();
    if (nw == 0) return stats;

    // Flatten the wordlist: one char buffer + (nw+1) offsets.
    std::vector<unsigned int> hOffsets(nw + 1);
    size_t totalChars = 0;
    for (int i = 0; i < nw; ++i) {
        hOffsets[i] = (unsigned int)totalChars;
        totalChars += words[i].size();
    }
    hOffsets[nw] = (unsigned int)totalChars;

    std::vector<char> hWords(totalChars);
    for (int i = 0; i < nw; ++i)
        memcpy(hWords.data() + hOffsets[i], words[i].data(), words[i].size());

    unsigned char hTarget[32];
    memset(hTarget, 0, sizeof(hTarget));
    hexToBytesDevice(targetHex, hTarget, dlen);

    char*           dWords    = nullptr;
    unsigned int*   dOffsets  = nullptr;
    CUDA_CHECK(cudaMalloc(&dWords,   totalChars));
    CUDA_CHECK(cudaMalloc(&dOffsets, sizeof(unsigned int) * (nw + 1)));

    const int blocks = (nw + blockSize - 1) / blockSize;

    cudaEvent_t evStart, evH2D, evKernelStart, evKernelStop, evEnd;
    CUDA_CHECK(cudaEventCreate(&evStart));
    CUDA_CHECK(cudaEventCreate(&evH2D));
    CUDA_CHECK(cudaEventCreate(&evKernelStart));
    CUDA_CHECK(cudaEventCreate(&evKernelStop));
    CUDA_CHECK(cudaEventCreate(&evEnd));

    unsigned long long none = kNotFound;
    int minusOne = -1;
    CUDA_CHECK(cudaMemcpyToSymbol(d_found,    &none,     sizeof(none)));
    CUDA_CHECK(cudaMemcpyToSymbol(d_foundLen, &minusOne, sizeof(minusOne)));
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaEventRecord(evStart));
    CUDA_CHECK(cudaMemcpy(dWords,   hWords.data(),    totalChars, cudaMemcpyHostToDevice)); // PCIe: wordlist
    CUDA_CHECK(cudaMemcpy(dOffsets, hOffsets.data(),  sizeof(unsigned int) * (nw + 1), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpyToSymbol(c_target, hTarget, 32));
    CUDA_CHECK(cudaEventRecord(evH2D));                    // PCIe transfer measured here

    CUDA_CHECK(cudaEventRecord(evKernelStart));
    dictKernel<<<blocks, blockSize>>>(dWords, dOffsets, nw, algoId, dlen);
    CUDA_CHECK(cudaEventRecord(evKernelStop));             // kernel-only time bracket

    unsigned long long hFound = kNotFound;
    CUDA_CHECK(cudaMemcpyFromSymbol(&hFound, d_found, sizeof(hFound)));      // D2H result
    CUDA_CHECK(cudaEventRecord(evEnd));

    CUDA_CHECK(cudaEventSynchronize(evEnd));
    CUDA_CHECK(cudaGetLastError());

    float e2e = 0, h2d = 0, ker = 0;
    CUDA_CHECK(cudaEventElapsedTime(&e2e, evStart,       evEnd));
    CUDA_CHECK(cudaEventElapsedTime(&h2d, evStart,       evH2D));
    CUDA_CHECK(cudaEventElapsedTime(&ker, evKernelStart, evKernelStop));
    stats.e2eMs = e2e; stats.h2dMs = h2d; stats.kernelMs = ker;

    if (hFound != kNotFound) {
        stats.found = true;
        stats.password = words[(size_t)hFound];
        stats.hashes = hFound + 1;
    } else {
        stats.hashes = (unsigned long long)nw;
    }

    CUDA_CHECK(cudaFree(dWords));
    CUDA_CHECK(cudaFree(dOffsets));
    cudaEventDestroy(evStart); cudaEventDestroy(evH2D);
    cudaEventDestroy(evKernelStart); cudaEventDestroy(evKernelStop);
    cudaEventDestroy(evEnd);
    return stats;
}
