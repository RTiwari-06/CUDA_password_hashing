// cpu_cracker.cpp - CPU brute-force and dictionary crackers (1-thread + OpenMP).
//
// Brute force uses the standard base-N index-to-password mapping:
//   candidate(index, L): for i = L-1 .. 0:
//       pw[i] = charset[index % N];  index /= N;
// so the whole keyspace of length L is the half-open range [0, N^L) and
// length prefix sums let a single monotonic index cover all lengths.
//
// Early exit: a shared std::atomic<bool>. Worker threads check the flag once
// per candidate and stop immediately when another thread found the target.
// The winner records its (index, length) atomically so the exact number of
// hashed candidates can be reported.

#include "cpu_cracker.hpp"

#include "sha256.cuh"
#include "md5.cuh"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>
#include <fstream>

#if defined(_OPENMP)
#include <omp.h>
#endif

namespace {

constexpr int kMaxPasswordLen = 55;   // single-block hashing limit

using Clock = std::chrono::steady_clock;

inline void hashMsg(const char* msg, int len, HashAlgo algo, uint8_t out[32])
{
    if (algo == HashAlgo::SHA256) cph::sha256((const uint8_t*)msg, (uint32_t)len, out);
    else                          cph::md5  ((const uint8_t*)msg, (uint32_t)len, out);
}

inline int digestLen(HashAlgo algo) { return algo == HashAlgo::SHA256 ? 32 : 16; }

// Decode hex digest string into a byte array. Returns false on bad input.
inline bool hexToBytes(const std::string& hex, uint8_t* out, int want)
{
    if ((int)hex.size() != want * 2) return false;
    for (int i = 0; i < want; ++i) {
        int hi, lo;
        char c1 = hex[2 * i], c2 = hex[2 * i + 1];
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        hi = nib(c1); lo = nib(c2);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

// Base-N decode: index in [0, N^L) -> password chars into pw[0..L-1].
inline void indexToPassword(uint64_t index, int len, const std::string& charset, char* pw)
{
    const int n = (int)charset.size();
    for (int i = len - 1; i >= 0; --i) {
        pw[i] = charset[index % (uint64_t)n];
        index /= (uint64_t)n;
    }
}

} // namespace

// ---------------------------------------------------------------- public API

std::string sha256HexHost(const std::string& msg)
{
    uint8_t d[32];
    cph::sha256((const uint8_t*)msg.data(), (uint32_t)msg.size(), d);
    static const char* hex = "0123456789abcdef";
    std::string s; s.reserve(64);
    for (uint8_t b : d) { s += hex[b >> 4]; s += hex[b & 0xF]; }
    return s;
}

std::string md5HexHost(const std::string& msg)
{
    uint8_t d[32];
    cph::md5((const uint8_t*)msg.data(), (uint32_t)msg.size(), d);
    static const char* hex = "0123456789abcdef";
    std::string s; s.reserve(32);
    for (int i = 0; i < 16; ++i) { s += hex[d[i] >> 4]; s += hex[d[i] & 0xF]; }
    return s;
}

std::string digestHex(HashAlgo algo, const std::string& msg)
{
    return algo == HashAlgo::SHA256 ? sha256HexHost(msg) : md5HexHost(msg);
}

CrackStats cpuBruteForce(const std::string& targetHex, const std::string& charset,
                         int maxLen, HashAlgo algo, int threads)
{
    CrackStats stats;
    const int dlen = digestLen(algo);

    uint8_t target[32];
    if (!hexToBytes(targetHex, target, dlen)) {
        fprintf(stderr, "[cpu] invalid target digest hex: %s\n", targetHex.c_str());
        return stats;
    }

    const int n = (int)charset.size();
    if (maxLen < 1 || maxLen > kMaxPasswordLen || n < 1) return stats;

    // Per-length candidate counts (uint64; overflow beyond 2^64 is not a
    // practical concern for CPU lengths).
    std::vector<uint64_t> count(maxLen + 1, 0);
    std::vector<uint64_t> offset(maxLen + 1, 0);   // prefix sums
    for (int L = 1; L <= maxLen; ++L) count[L] = (uint64_t)n;   // scale below
    // count[L] = n^L, offset[L] = sum of count[1..L-1]
    {
        uint64_t p = 1;
        uint64_t acc = 0;
        for (int L = 1; L <= maxLen; ++L) {
            p *= (uint64_t)n;
            count[L] = p;
            offset[L] = acc;
            acc += p;
        }
    }
    const uint64_t total = offset[maxLen] + count[maxLen];

    // Shared state for early exit.
    std::atomic<bool>     foundFlag{false};
    std::atomic<uint64_t> foundIdx {~0ull};
    std::atomic<uint32_t> foundLen {0u};

    auto t0 = Clock::now();

    for (int L = 1; L <= maxLen && !foundFlag.load(std::memory_order_relaxed); ++L) {
        const uint64_t cnt = count[L];
        const int nt = (threads > 1) ? threads : 1;
        // Dynamic chunks: hybrid CPUs (P+E cores) finish unequal shares at
        // unequal speeds; static splits would wait on the slowest straggler.
        #pragma omp parallel for schedule(dynamic, 16384) num_threads(nt)
        for (long long i = 0; i < (long long)cnt; ++i) {
            if (foundFlag.load(std::memory_order_relaxed)) continue;   // early exit
            char pw[kMaxPasswordLen + 1];
            indexToPassword((uint64_t)i, L, charset, pw);
            uint8_t d[32];
            hashMsg(pw, L, algo, d);
            bool match = memcmp(d, target, (size_t)dlen) == 0;
            if (match) {
                // One winner wins the race; early-exit flag released others.
                foundFlag.store(true, std::memory_order_relaxed);
                foundIdx.store((uint64_t)i, std::memory_order_relaxed);
                foundLen.store((uint32_t)L, std::memory_order_relaxed);
            }
        }
        if (foundFlag.load(std::memory_order_relaxed)) break;
    }

    auto t1 = Clock::now();

    if (foundFlag.load()) {
        uint32_t L = foundLen.load();
        uint64_t i = foundIdx.load();
        char pw[kMaxPasswordLen + 1];
        indexToPassword(i, (int)L, charset, pw);
        pw[L] = '\0';
        stats.found = true;
        stats.password = std::string(pw, L);
        stats.hashes = offset[L] + i + 1;   // exact candidates hashed
    } else {
        stats.hashes = total;
    }
    stats.seconds = std::chrono::duration<double>(t1 - t0).count();
    return stats;
}

CrackStats cpuDictionary(const std::string& targetHex, const std::string& wordlistPath,
                         HashAlgo algo, int threads)
{
    CrackStats stats;
    const int dlen = digestLen(algo);

    uint8_t target[32];
    if (!hexToBytes(targetHex, target, dlen)) {
        fprintf(stderr, "[cpu] invalid target digest hex: %s\n", targetHex.c_str());
        return stats;
    }

    // Load the whole wordlist into memory (one candidate per line).
    std::vector<std::string> words;
    {
        std::ifstream in(wordlistPath);
        if (!in) {
            fprintf(stderr, "[cpu] cannot open wordlist: %s\n", wordlistPath.c_str());
            return stats;
        }
        std::string line;
        while (std::getline(in, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            if (!line.empty() && line.size() <= kMaxPasswordLen) words.push_back(line);
        }
    }
    if (words.empty()) return stats;

    std::atomic<bool>      foundFlag{false};
    std::atomic<long long> foundLine{-1};

    auto t0 = Clock::now();

    const long long nw = (long long)words.size();
    const int nt = (threads > 1) ? threads : 1;
    #pragma omp parallel for schedule(static) num_threads(nt)
    for (long long i = 0; i < nw; ++i) {
        if (foundFlag.load(std::memory_order_relaxed)) continue;   // early exit
        const std::string& w = words[(size_t)i];
        uint8_t d[32];
        hashMsg(w.c_str(), (int)w.size(), algo, d);
        if (memcmp(d, target, (size_t)dlen) == 0) {
            foundFlag.store(true, std::memory_order_relaxed);
            foundLine.store(i, std::memory_order_relaxed);
        }
    }

    auto t1 = Clock::now();

    long long line = foundLine.load();
    if (line >= 0) {
        stats.found = true;
        stats.password = words[(size_t)line];
        stats.hashes = (uint64_t)line + 1;   // candidates hashed up to winner
    } else {
        stats.hashes = (uint64_t)nw;
    }
    stats.seconds = std::chrono::duration<double>(t1 - t0).count();
    return stats;
}
