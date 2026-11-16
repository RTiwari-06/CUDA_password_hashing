# Makefile - CUDA Password Hashing & Brute-Force Benchmark (Linux / Google Colab)
# Targets sm_75 (Turing, e.g. T4 on Colab) and sm_86 (Ampere, e.g. RTX 3050 / A5000).
#
# Usage:
#   make                build both binaries
#   make wordlist       generate data/wordlist.txt (5,000 entries)
#   make benchmark      build + wordlist + run full benchmark
#   make test           run the NIST verification suite
#   make clean

NVCC      ?= nvcc
PYTHON    ?= python3

NVCC_FLAGS = -std=c++17 -O3 -Xcompiler -fopenmp -Iinclude \
             -gencode arch=compute_75,code=sm_75 \
             -gencode arch=compute_86,code=sm_86

BUILD_DIR  := build
HDRS       := include/sha256.cuh include/md5.cuh include/cuda_utils.cuh \
              include/cpu_cracker.hpp include/gpu_cracker.hpp

.PHONY: all test wordlist benchmark clean

all: $(BUILD_DIR)/test_crypto $(BUILD_DIR)/cuda_cracker

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR) results data scripts

$(BUILD_DIR)/test_crypto: src/test_crypto.cu $(HDRS) | $(BUILD_DIR)
	$(NVCC) $(NVCC_FLAGS) -o $@ src/test_crypto.cu

$(BUILD_DIR)/cuda_cracker: src/main.cu src/gpu_cracker.cu src/cpu_cracker.cpp $(HDRS) | $(BUILD_DIR)
	$(NVCC) $(NVCC_FLAGS) -o $@ src/main.cu src/gpu_cracker.cu src/cpu_cracker.cpp

wordlist: scripts/gen_wordlist.py
	$(PYTHON) scripts/gen_wordlist.py

test: $(BUILD_DIR)/test_crypto
	./$(BUILD_DIR)/test_crypto

benchmark: $(BUILD_DIR)/cuda_cracker wordlist
	./$(BUILD_DIR)/cuda_cracker --algo sha256 --mode benchmark --charset lower
	$(PYTHON) scripts/plot_results.py

clean:
	rm -rf $(BUILD_DIR) results/benchmark.csv results/*.png
