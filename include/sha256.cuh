// sha256.cuh - Header-only, zero-dependency SHA-256 (FIPS 180-4).
// Pure bitwise implementation: no OpenSSL, no external libraries.
// Identical code path on host (MSVC/gcc) and device (CUDA) via CPH_HD.
//
// Scope: single-block hashing for messages of 0..55 bytes, which covers every
// ASCII password candidate this cracker generates (max length clamp = 55).
//
// Constant tables: under nvcc the device pass needs the K/H0 tables in
// __constant__ memory (host namespace-scope statics are invisible to device
// code), while the host pass reads plain .rodata copies. Non-CUDA builds
// (MSVC/gcc) alias the host names onto a single plain table.
#pragma once

#include <cstdint>
#include <cstddef>

#if defined(__CUDACC__)
#define CPH_HD __host__ __device__
#else
#define CPH_HD
#endif

CPH_HD inline uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u - n)); }
CPH_HD inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)    { return (x & y) ^ (~x & z); }
CPH_HD inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z)   { return (x & y) ^ (x & z) ^ (y & z); }
CPH_HD inline uint32_t bsig0(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
CPH_HD inline uint32_t bsig1(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
CPH_HD inline uint32_t ssig0(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
CPH_HD inline uint32_t ssig1(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }

namespace cph {

#if defined(__CUDACC__)
#define CPH_TBL __device__ __constant__
#else
#define CPH_TBL
#endif

// First 32 bits of the fractional parts of the square roots of the first 8
// primes (FIPS 180-4 section 4.2.2). DEVICE table (__constant__ under nvcc).
CPH_TBL static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};
CPH_TBL static const uint32_t SHA256_H0[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

#if defined(__CUDACC__)
// HOST-pass copies (plain .rodata) - host code must not read __constant__.
static const uint32_t SHA256_K_H[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};
static const uint32_t SHA256_H0_H[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};
#else
#define SHA256_K_H  SHA256_K
#define SHA256_H0_H SHA256_H0
#endif

// Table selector: device compilation pass -> __constant__ table; host pass
// (and non-CUDA compilers) -> plain host table.
#if defined(__CUDA_ARCH__)
#define CPH_SHA256_K  SHA256_K
#define CPH_SHA256_H0 SHA256_H0
#else
#define CPH_SHA256_K  SHA256_K_H
#define CPH_SHA256_H0 SHA256_H0_H
#endif

// Compute SHA-256 of `len` bytes (len <= 55) into a 32-byte big-endian digest.
CPH_HD inline void sha256(const uint8_t* data, uint32_t len, uint8_t out[32])
{
    uint8_t block[64];

    // ---- padding --------------------------------------------------------
    for (int i = 0; i < 64; ++i) block[i] = 0u;
    for (uint32_t i = 0; i < len; ++i) block[i] = data[i];
    block[len] = 0x80u;                       // 1-bit append marker
    uint64_t bits = (uint64_t)len * 8ull;
    for (int i = 0; i < 8; ++i)               // big-endian message length
        block[63 - i] = (uint8_t)(bits >> (8 * i));

    // ---- message schedule (W[0..63]) ------------------------------------
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = ((uint32_t)block[4 * i + 0] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8)  |  (uint32_t)block[4 * i + 3];
    for (int i = 16; i < 64; ++i)
        w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];

    // ---- 64-round compression --------------------------------------------
    uint32_t h[8];
    for (int i = 0; i < 8; ++i) h[i] = CPH_SHA256_H0[i];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h[7] + bsig1(h[4]) + ch(h[4], h[5], h[6]) + CPH_SHA256_K[i] + w[i];
        uint32_t t2 = bsig0(h[0]) + maj(h[0], h[1], h[2]);
        h[7] = h[6]; h[6] = h[5]; h[5] = h[4]; h[4] = h[3] + t1;
        h[3] = h[2]; h[2] = h[1]; h[1] = h[0]; h[0] = t1 + t2;
    }

    // ---- finalize (big-endian output) ------------------------------------
    for (int i = 0; i < 8; ++i) {
        uint32_t hv = h[i] + CPH_SHA256_H0[i];
        out[4 * i + 0] = (uint8_t)(hv >> 24);
        out[4 * i + 1] = (uint8_t)(hv >> 16);
        out[4 * i + 2] = (uint8_t)(hv >> 8);
        out[4 * i + 3] = (uint8_t)(hv);
    }
}

} // namespace cph
