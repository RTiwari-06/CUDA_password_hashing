// test_crypto.cu - NIST test-vector verification suite.
//
// Verifies that the pure bitwise SHA-256 and MD5 implementations produce the
// correct digests on BOTH the host (CPU) and the device (GPU kernel) for the
// NIST test vectors "", "abc", and "password123".
//
//   SHA-256("")           = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//   SHA-256("abc")        = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
//   SHA-256("password123")= ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
//   MD-5("")              = d41d8cd98f00b204e9800998ecf8427e
//   MD-5("abc")           = 900150983cd24fb0d6963f7d28e17f72
//   MD-5("password123")   = 482c811da5d5b4bc6d497ffa98491e38
//
// Exit code 0 = all tests pass.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "sha256.cuh"
#include "md5.cuh"
#include "cuda_utils.cuh"

static const char* kTestMsgs[3]     = { "", "abc", "password123" };
static const char* kSha256Expected[3] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
};
static const char* kMd5Expected[3] = {
    "d41d8cd98f00b204e9800998ecf8427e",
    "900150983cd24fb0d6963f7d28e17f72",
    "482c811da5d5b4bc6d497ffa98491e38"
};

// Device kernel: thread i hashes messages[i] (64-byte slot) and writes the
// digest to shaOut[i] (32 bytes) / md5Out[i] (16 bytes).
__global__ void cryptoVerifyKernel(const uint8_t* messages, const uint32_t* lengths,
                                   uint8_t* shaOut, uint8_t* md5Out)
{
    int i = threadIdx.x;
    if (i > 2) return;
    uint8_t digest[32];
    cph::sha256(messages + (size_t)i * 64, lengths[i], digest);
    for (int b = 0; b < 32; ++b) shaOut[i * 32 + b] = digest[b];
    cph::md5(messages + (size_t)i * 64, lengths[i], digest);
    for (int b = 0; b < 16; ++b) md5Out[i * 16 + b] = digest[b];
}

static std::string toHex(const uint8_t* d, int n)
{
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < n; ++i) { s += hex[d[i] >> 4]; s += hex[d[i] & 0xF]; }
    return s;
}

int main()
{
    int failures = 0, tests = 0;

    printf("=================================================================\n");
    printf(" NIST test-vector verification: SHA-256 & MD5 (host + device)\n");
    printf("=================================================================\n");

    // ---------------- host-side verification ----------------
    for (int i = 0; i < 3; ++i) {
        uint8_t d[32];
        cph::sha256((const uint8_t*)kTestMsgs[i], (uint32_t)strlen(kTestMsgs[i]), d);
        std::string got = toHex(d, 32);
        bool ok = (got == kSha256Expected[i]); failures += !ok; tests++;
        printf(" [%s] HOST  SHA-256(\"%s\") = %s\n", ok ? "PASS" : "FAIL", kTestMsgs[i], got.c_str());
        if (!ok) printf("        expected              = %s\n", kSha256Expected[i]);
    }
    for (int i = 0; i < 3; ++i) {
        uint8_t d[32];
        cph::md5((const uint8_t*)kTestMsgs[i], (uint32_t)strlen(kTestMsgs[i]), d);
        std::string got = toHex(d, 16);
        bool ok = (got == kMd5Expected[i]); failures += !ok; tests++;
        printf(" [%s] HOST  MD-5   (\"%s\") = %s\n", ok ? "PASS" : "FAIL", kTestMsgs[i], got.c_str());
        if (!ok) printf("        expected              = %s\n", kMd5Expected[i]);
    }

    // ---------------- device-side verification ----------------
    // Pack the 3 messages into a 3x64-byte device buffer.
    uint8_t hMsgs[192];
    memset(hMsgs, 0, sizeof(hMsgs));
    uint32_t hLens[3];
    for (int i = 0; i < 3; ++i) {
        hLens[i] = (uint32_t)strlen(kTestMsgs[i]);
        memcpy(hMsgs + (size_t)i * 64, kTestMsgs[i], hLens[i]);
    }

    uint8_t*  dMsgs  = nullptr; uint32_t* dLens  = nullptr;
    uint8_t*  dSha   = nullptr; uint8_t*  dMd5   = nullptr;
    CUDA_CHECK(cudaMalloc(&dMsgs, sizeof(hMsgs)));
    CUDA_CHECK(cudaMalloc(&dLens, sizeof(hLens)));
    CUDA_CHECK(cudaMalloc(&dSha, 3 * 32));
    CUDA_CHECK(cudaMalloc(&dMd5, 3 * 16));
    CUDA_CHECK(cudaMemcpy(dMsgs, hMsgs, sizeof(hMsgs), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(dLens, hLens, sizeof(hLens), cudaMemcpyHostToDevice));

    cryptoVerifyKernel<<<1, 8>>>(dMsgs, dLens, dSha, dMd5);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    uint8_t hSha[96], hMd5[48];
    CUDA_CHECK(cudaMemcpy(hSha, dSha, sizeof(hSha), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(hMd5, dMd5, sizeof(hMd5), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaFree(dMsgs)); CUDA_CHECK(cudaFree(dLens));
    CUDA_CHECK(cudaFree(dSha));  CUDA_CHECK(cudaFree(dMd5));

    for (int i = 0; i < 3; ++i) {
        std::string got = toHex(hSha + i * 32, 32);
        bool ok = (got == kSha256Expected[i]); failures += !ok; tests++;
        printf(" [%s] GPU   SHA-256(\"%s\") = %s\n", ok ? "PASS" : "FAIL", kTestMsgs[i], got.c_str());
        if (!ok) printf("        expected              = %s\n", kSha256Expected[i]);
    }
    for (int i = 0; i < 3; ++i) {
        std::string got = toHex(hMd5 + i * 16, 16);
        bool ok = (got == kMd5Expected[i]); failures += !ok; tests++;
        printf(" [%s] GPU   MD-5   (\"%s\") = %s\n", ok ? "PASS" : "FAIL", kTestMsgs[i], got.c_str());
        if (!ok) printf("        expected              = %s\n", kMd5Expected[i]);
    }

    printf("=================================================================\n");
    printf(" %d/%d tests passed, %d failed\n", tests - failures, tests, failures);
    printf("=================================================================\n");
    return failures == 0 ? 0 : 1;
}
