// md5.cuh - Header-only, zero-dependency MD5 (RFC 1321).
// Pure bitwise implementation: no OpenSSL, no external libraries.
// Identical code path on host (MSVC/gcc) and device (CUDA) via CPH_HD.
//
// Scope: single-block hashing for messages of 0..55 bytes (ASCII passwords).
// Digest bytes are emitted in the little-endian order defined by RFC 1321.
//
// Constant tables follow the same host/device split as sha256.cuh (see the
// CPH_TBL / CPH_MD5_K notes there).
#pragma once

#include <cstdint>
#include <cstddef>

#if defined(__CUDACC__)
#define CPH_HD __host__ __device__
#else
#define CPH_HD
#endif

CPH_HD inline uint32_t rotl32(uint32_t x, uint32_t n) { return (x << n) | (x >> (32u - n)); }

namespace cph {

#if defined(__CUDACC__)
#define CPH_TBL __device__ __constant__
#else
#define CPH_TBL
#endif

// 64 constants: floor(abs(sin(i+1)) * 2^32), i = 0..63 (RFC 1321 section 3.4).
// DEVICE table (__constant__ under nvcc).
CPH_TBL static const uint32_t MD5_K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};
// Per-round shift amounts (RFC 1321 section 3.4). DEVICE table.
CPH_TBL static const uint32_t MD5_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

#if defined(__CUDACC__)
// HOST-pass copies (plain .rodata) - host code must not read __constant__.
static const uint32_t MD5_K_H[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};
static const uint32_t MD5_S_H[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};
#else
#define MD5_K_H MD5_K
#define MD5_S_H MD5_S
#endif

// Table selector: device pass -> __constant__; host pass -> plain tables.
#if defined(__CUDA_ARCH__)
#define CPH_MD5_K MD5_K
#define CPH_MD5_S MD5_S
#else
#define CPH_MD5_K MD5_K_H
#define CPH_MD5_S MD5_S_H
#endif

// Compute MD5 of `len` bytes (len <= 55) into a 16-byte digest.
CPH_HD inline void md5(const uint8_t* data, uint32_t len, uint8_t out[16])
{
    uint8_t block[64];

    // ---- padding (little-endian length per RFC 1321) ----------------------
    for (int i = 0; i < 64; ++i) block[i] = 0u;
    for (uint32_t i = 0; i < len; ++i) block[i] = data[i];
    block[len] = 0x80u;
    uint64_t bits = (uint64_t)len * 8ull;
    for (int i = 0; i < 8; ++i)
        block[56 + i] = (uint8_t)(bits >> (8 * i));

    // ---- message words (little-endian load) --------------------------------
    uint32_t m[16];
    for (int i = 0; i < 16; ++i)
        m[i] =  (uint32_t)block[4 * i + 0]        | ((uint32_t)block[4 * i + 1] << 8) |
               ((uint32_t)block[4 * i + 2] << 16) | ((uint32_t)block[4 * i + 3] << 24);

    uint32_t a = 0x67452301u, b = 0xefcdab89u, c = 0x98badcfeu, d = 0x10325476u;

    // ---- 64 rounds ---------------------------------------------------------
    for (int i = 0; i < 64; ++i) {
        uint32_t f; int g;
        if (i < 16)      { f = (b & c) | (~b & d);        g = i;                 }
        else if (i < 32) { f = (d & b) | (~d & c);        g = (5 * i + 1) & 15;  }
        else if (i < 48) { f = b ^ c ^ d;                 g = (3 * i + 5) & 15;  }
        else             { f = c ^ (b | ~d);              g = (7 * i) & 15;      }

        uint32_t tmp = a + f + CPH_MD5_K[i] + m[g];
        a = d; d = c; c = b;
        b = b + rotl32(tmp, CPH_MD5_S[i]);
    }

    a += 0x67452301u; b += 0xefcdab89u; c += 0x98badcfeu; d += 0x10325476u;

    // ---- finalize (little-endian output) ------------------------------------
    out[0]  = (uint8_t)a;  out[1]  = (uint8_t)(a >> 8);  out[2]  = (uint8_t)(a >> 16); out[3]  = (uint8_t)(a >> 24);
    out[4]  = (uint8_t)b;  out[5]  = (uint8_t)(b >> 8);  out[6]  = (uint8_t)(b >> 16); out[7]  = (uint8_t)(b >> 24);
    out[8]  = (uint8_t)c;  out[9]  = (uint8_t)(c >> 8);  out[10] = (uint8_t)(c >> 16); out[11] = (uint8_t)(c >> 24);
    out[12] = (uint8_t)d;  out[13] = (uint8_t)(d >> 8);  out[14] = (uint8_t)(d >> 16); out[15] = (uint8_t)(d >> 24);
}

} // namespace cph
