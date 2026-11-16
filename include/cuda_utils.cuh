// cuda_utils.cuh - Shared CUDA plumbing: CUDA_CHECK error macro + CudaTimer.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <cuda_runtime.h>

// Wrap every CUDA API call; abort with file/line context on failure.
#define CUDA_CHECK(call)                                                      \
    do {                                                                      \
        cudaError_t err__ = (call);                                           \
        if (err__ != cudaSuccess) {                                           \
            fprintf(stderr, "[CUDA ERROR] %s (%s) at %s:%d\n",                \
                    cudaGetErrorName(err__), cudaGetErrorString(err__),       \
                    __FILE__, __LINE__);                                      \
            exit(EXIT_FAILURE);                                               \
        }                                                                     \
    } while (0)

// cudaEvent_t pair wrapper. Because GPU kernels are asynchronous from the
// host's point of view, wall-clock timing is useless: recording start/stop
// events *inside the same stream* captures the true GPU-side elapsed time.
class CudaTimer {
public:
    CudaTimer()  { CUDA_CHECK(cudaEventCreate(&start_)); CUDA_CHECK(cudaEventCreate(&stop_)); }
    ~CudaTimer() { cudaEventDestroy(start_); cudaEventDestroy(stop_); }

    void start(cudaStream_t stream = 0) { CUDA_CHECK(cudaEventRecord(start_, stream)); }
    void stop(cudaStream_t stream = 0)
    {
        CUDA_CHECK(cudaEventRecord(stop_, stream));
        CUDA_CHECK(cudaEventSynchronize(stop_));   // block host until stop fires
    }
    float ms() const
    {
        float m = 0.0f;
        CUDA_CHECK(cudaEventElapsedTime(&m, start_, stop_));
        return m;
    }

private:
    cudaEvent_t start_;
    cudaEvent_t stop_;
};
