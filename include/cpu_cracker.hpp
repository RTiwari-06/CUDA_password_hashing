// cpu_cracker.hpp - CPU brute-force and dictionary crackers.
// Sequential (1-thread) and OpenMP multi-threaded modes, with a
// std::atomic<bool> early-exit flag shared across worker threads.
#pragma once

#include <cstdint>
#include <string>

// Supported hash algorithms.
enum class HashAlgo { SHA256 = 0, MD5 = 1 };

// Metrics returned by every cracker variant.
struct CrackStats {
    bool       found    = false;   // target recovered?
    std::string password;         // recovered plaintext ("" if not found)
    uint64_t   hashes   = 0;       // candidates actually hashed
    double     seconds  = 0.0;     // wall-clock duration
    double     mhps() const { return seconds > 0.0 ? (double)hashes / seconds / 1e6 : 0.0; }
};

// Brute-force every candidate of length 1..maxLen over `charset` (base-N
// index-to-password mapping) until the target digest hex matches.
// `threads` = 1 -> sequential; > 1 -> OpenMP parallel-for.
CrackStats cpuBruteForce(const std::string& targetHex, const std::string& charset,
                         int maxLen, HashAlgo algo, int threads);

// Scan `wordlistPath` line-by-line (one candidate per line) until a match.
// `threads` = 1 -> sequential; > 1 -> OpenMP parallel-for over the word array.
CrackStats cpuDictionary(const std::string& targetHex, const std::string& wordlistPath,
                         HashAlgo algo, int threads);

// Host-side hex digest helpers (implemented in cpu_cracker.cpp).
std::string sha256HexHost(const std::string& msg);
std::string md5HexHost(const std::string& msg);
std::string digestHex(HashAlgo algo, const std::string& msg);
