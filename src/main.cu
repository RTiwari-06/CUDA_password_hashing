// main.cu - CLI orchestrator for the CUDA Password Hashing Demonstration.
//
// Usage:
//   cuda_cracker.exe --algo [sha256|md5] --mode [bruteforce|dict|benchmark]
//                    [--password <str>] [--charset [lower|alnum]]
//                    [--length <int>] [--threads <int>] [--wordlist <path>]
//
// Modes:
//   bruteforce - hash --password on the host to obtain the target digest,
//                then recover it by brute force (GPU primary, CPU comparison
//                when the keyspace is small enough).
//   dict       - same, but scanned against data/wordlist.txt (CPU + GPU).
//   benchmark  - password lengths 4, 5, 6 x {CPU 1-Thread, CPU OpenMP,
//                CUDA Kernel Only, CUDA End-to-End}; prints an ASCII table
//                and appends rows to results/benchmark.csv.
//
// The benchmark always scans the FULL keyspace of each length (target =
// last candidate, e.g. "zzzz.."), so CPU and CUDA times are directly
// comparable worst-case numbers.

#include "cpu_cracker.hpp"
#include "gpu_cracker.hpp"

#include <cuda_runtime.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <string>
#include <vector>
#include <fstream>

#if defined(_OPENMP)
#include <omp.h>
#endif

namespace {

struct Args {
    std::string algo     = "sha256";
    std::string mode     = "benchmark";
    std::string password;                 // required for bruteforce / dict
    std::string charset   = "lower";      // lower | alnum
    std::string wordlist  = "data/wordlist.txt";
    int         length    = 6;
    int         threads   = 0;            // 0 = OpenMP default
    int         blockSize = 256;
};

std::string getCharset(const std::string& name)
{
    if (name == "alnum") return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return "abcdefghijklmnopqrstuvwxyz";   // lower
}

const char* engineCpu1()   { return "CPU (1-Thread)"; }
std::string engineCpuOmp() { 
    static char buf[32];
#if defined(_OPENMP)
    snprintf(buf, sizeof(buf), "CPU (OpenMP x%d)", omp_get_max_threads());
#else
    snprintf(buf, sizeof(buf), "CPU (OpenMP)");
#endif
    return buf;
}
const char* engineCudaK()  { return "CUDA (Kernel Only)"; }
const char* engineCudaE()  { return "CUDA (End-to-End)"; }

// 1234567 -> "1,234,567"
std::string comma(uint64_t v)
{
    std::string s = std::to_string(v), out;
    int c = 0;
    for (int i = (int)s.size() - 1; i >= 0; --i) {
        out += s[i];
        if (++c % 3 == 0 && i > 0) out += ',';
    }
    return std::string(out.rbegin(), out.rend());
}

void appendCsvRow(const std::string& path, const std::string& line)
{
    std::ifstream probe(path);
    bool needHeader = !probe.good();
    probe.close();
    std::ofstream f(path, std::ios::app);
    if (!f) { fprintf(stderr, "cannot open %s for append\n", path.c_str()); return; }
    if (needHeader) f << "algo,charset,length,engine,hashes,time_s,rate_mhps,speedup_vs_cpu1\n";
    f << line << "\n";
}

uint64_t keyspaceSize(const std::string& charset, int maxLen)
{
    uint64_t n = charset.size(), total = 0, p = 1;
    for (int L = 1; L <= maxLen; ++L) { p *= n; total += p; }
    return total;
}

// Print one benchmark table and write CSV rows.
void runBenchmark(HashAlgo algo, const std::string& charsetName, const std::string& charset,
                  int threads, int blockSize, const std::string& csvPath)
{
    const std::string algoName = (algo == HashAlgo::SHA256) ? "SHA-256" : "MD5";
    const char lastChar = charset.back();

    printf("\n=====================================================================================================================\n");
    printf("  Benchmark: %s brute force | charset: %s (%d symbols) | GPU: %s\n",
           algoName.c_str(), charsetName.c_str(), (int)charset.size(), gpuDeviceName());
    printf("  Full-keyspace worst case: target = last candidate of each length\n");
    printf("---------------------------------------------------------------------------------------------------------------------\n");
    printf("  %-4s | %-22s | %14s | %12s | %17s | %12s\n", "Len", "Engine", "Candidates", "Time (s)", "Thru (MH/s)", "Speedup");
    printf("---------------------------------------------------------------------------------------------------------------------\n");

    for (int L = 4; L <= 6; ++L) {
        // Target = LAST candidate of this length -> forces a full scan.
        std::string targetPw((size_t)L, lastChar);
        const std::string targetHex = digestHex(algo, targetPw);
        const uint64_t total = keyspaceSize(charset, L);

        CrackStats      cpu1   = cpuBruteForce(targetHex, charset, L, algo, 1);
        CrackStats      cpuN   = cpuBruteForce(targetHex, charset, L, algo, threads);
        GpuCrackStats   gpu    = gpuBruteForce(targetHex, charset, L, algo, blockSize);

        const double base = cpu1.seconds > 0 ? cpu1.seconds : 1e-9;
        double sp1 = 1.0;
        double spN = cpuN.seconds / base;
        // Speedup = CPU time / engine time (>= 1 means faster than baseline).
        double spK = base / (gpu.kernelMs * 1e-3);
        double spE = base / (gpu.e2eMs * 1e-3);

        printf("  %-4d | %-22s | %14s | %12.6f | %17.3f | %11.1fx\n",
               L, engineCpu1(), comma(cpu1.hashes).c_str(), cpu1.seconds, cpu1.mhps(), sp1);
        printf("  %-4s | %-22s | %14s | %12.6f | %17.3f | %11.1fx\n",
               "", engineCpuOmp().c_str(), comma(cpuN.hashes).c_str(), cpuN.seconds, cpuN.mhps(), spN);
        printf("  %-4s | %-22s | %14s | %12.6f | %17.3f | %11.1fx\n",
               "", engineCudaK(), comma(gpu.hashes).c_str(), gpu.kernelMs * 1e-3, gpu.kernelMhps(), spK);
        printf("  %-4s | %-22s | %14s | %12.6f | %17.3f | %11.1fx\n",
               "", engineCudaE(), comma(gpu.hashes).c_str(), gpu.e2eMs * 1e-3, gpu.e2eMhps(), spE);
        printf("---------------------------------------------------------------------------------------------------------------------\n");

        const std::string a = algo == HashAlgo::SHA256 ? "sha256" : "md5";
        const auto row = [&](const char* eng, double sec, double rate, double sp) {
            appendCsvRow(csvPath, a + "," + charsetName + "," + std::to_string(L) + "," + eng + "," +
                                  std::to_string(total) + "," + std::to_string(sec) + "," +
                                  std::to_string(rate) + "," + std::to_string(sp));
        };
        row("cpu_1thread", cpu1.seconds, cpu1.mhps(), sp1);
        row("cpu_openmp",  cpuN.seconds, cpuN.mhps(), spN);
        row("cuda_kernel", gpu.kernelMs * 1e-3, gpu.kernelMhps(), spK);
        row("cuda_e2e",    gpu.e2eMs * 1e-3, gpu.e2eMhps(), spE);

        if (!cpuN.found || !gpu.found)
            printf("  [WARN] verification issue: cpu found=%d gpu found=%d\n", (int)cpuN.found, (int)gpu.found);
    }
    printf("\n  CSV appended to %s\n", csvPath.c_str());
}

} // namespace

int main(int argc, char** argv)
{
    Args args;
    for (int i = 1; i < argc; ++i) {
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) { fprintf(stderr, "missing value after %s\n", argv[i]); exit(1); }
            return argv[++i];
        };
        std::string k = argv[i];
        if      (k == "--algo")     args.algo = next();
        else if (k == "--mode")     args.mode = next();
        else if (k == "--password") args.password = next();
        else if (k == "--charset")  args.charset = next();
        else if (k == "--length")   args.length = atoi(next());
        else if (k == "--threads")  args.threads = atoi(next());
        else if (k == "--block")    args.blockSize = atoi(next());
        else if (k == "--wordlist") args.wordlist = next();
        else if (k == "--help" || k == "-h") {
            printf("Usage: cuda_cracker --algo [sha256|md5] --mode [bruteforce|dict|benchmark]\n"
                   "                   [--password <str>] [--charset [lower|alnum]]\n"
                   "                   [--length <int>] [--threads <int>] [--block <int>]\n"
                   "                   [--wordlist <path>]\n");
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", k.c_str());
            return 1;
        }
    }

    HashAlgo algo;
    if      (args.algo == "sha256") algo = HashAlgo::SHA256;
    else if (args.algo == "md5")    algo = HashAlgo::MD5;
    else { fprintf(stderr, "--algo must be sha256 or md5\n"); return 1; }

    const std::string charset = getCharset(args.charset);
    const int deviceCount = 0;
    cudaFree(0);   // force CUDA context init early
    (void)deviceCount;
    int ndev = 0;
    cudaGetDeviceCount(&ndev);
    if (ndev <= 0) { fprintf(stderr, "no CUDA device found\n"); return 1; }

#if defined(_OPENMP)
    if (args.threads > 0) omp_set_num_threads(args.threads);
#endif

    const std::string csvPath = "results/benchmark.csv";

    if (args.mode == "benchmark") {
        runBenchmark(algo, args.charset, charset, args.threads, args.blockSize, csvPath);
        return 0;
    }

    if (args.password.empty()) {
        fprintf(stderr, "--password is required for mode %s\n", args.mode.c_str());
        return 1;
    }
    const std::string targetHex = digestHex(algo, args.password);
    const std::string algoName = (algo == HashAlgo::SHA256) ? "SHA-256" : "MD5";

    if (args.mode == "bruteforce") {
        if (args.length < 1 || args.length > 8) { fprintf(stderr, "--length must be 1..8\n"); return 1; }
        const uint64_t total = keyspaceSize(charset, args.length);
        printf("Target   : %s\n", args.password.c_str());
        printf("Digest   : %s(%s) = %s\n", algoName.c_str(), args.password.c_str(), targetHex.c_str());
        printf("Charset  : %s (%d symbols)\n", args.charset.c_str(), (int)charset.size());
        printf("Keyspace : lengths 1..%d -> %s candidates\n\n", args.length, comma(total).c_str());

        GpuCrackStats gpu = gpuBruteForce(targetHex, charset, args.length, algo, args.blockSize);
        printf("[CUDA   ] %s in %.3f ms (kernel %.3f ms, PCIe H2D %.3f ms, e2e %.3f ms) | %s candidates | %.1f MH/s\n",
               gpu.found ? "FOUND" : "not found", gpu.e2eMs, gpu.kernelMs, gpu.h2dMs, gpu.e2eMs,
               comma(gpu.hashes).c_str(), gpu.kernelMhps());
        if (gpu.found) printf("[CUDA   ] recovered password: \"%s\"\n", gpu.password.c_str());

        // CPU comparison only when the keyspace is tractable (< 2^28).
        if (total <= (1ull << 28)) {
            CrackStats cpuN = cpuBruteForce(targetHex, charset, args.length, algo, args.threads);
            printf("[CPU-OMP ] %s in %.3f s | %s candidates | %.2f MH/s\n",
                   cpuN.found ? "FOUND" : "not found", cpuN.seconds,
                   comma(cpuN.hashes).c_str(), cpuN.mhps());
            if (cpuN.found) printf("[CPU-OMP ] recovered password: \"%s\"\n", cpuN.password.c_str());
            if (cpuN.found && gpu.found && cpuN.password != gpu.password)
                printf("[ERROR   ] CPU/GPU disagree: %s vs %s\n", cpuN.password.c_str(), gpu.password.c_str());
        } else {
            printf("[CPU-OMP ] skipped (keyspace %s > 2^28 threshold)\n", comma(total).c_str());
        }
        return gpu.found ? 0 : 2;
    }

    if (args.mode == "dict") {
        // Load the wordlist once for both CPU and GPU attacks.
        std::vector<std::string> words;
        {
            std::ifstream in(args.wordlist);
            if (!in) { fprintf(stderr, "cannot open wordlist: %s\n", args.wordlist.c_str()); return 1; }
            std::string line;
            while (std::getline(in, line)) {
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
                if (!line.empty()) words.push_back(line);
            }
        }
        printf("Target   : %s\n", args.password.c_str());
        printf("Digest   : %s(%s) = %s\n", algoName.c_str(), args.password.c_str(), targetHex.c_str());
        printf("Wordlist : %s (%s entries)\n\n", args.wordlist.c_str(), comma(words.size()).c_str());

        CrackStats cpuN = cpuDictionary(targetHex, args.wordlist, algo, args.threads);
        GpuCrackStats gpu = gpuDictionary(targetHex, words, algo, args.blockSize);

        printf("[CPU-OMP ] %s in %.3f s | %s candidates | %.2f MH/s%s\n",
               cpuN.found ? "FOUND" : "not found", cpuN.seconds,
               comma(cpuN.hashes).c_str(), cpuN.mhps(),
               cpuN.found ? (" -> \"" + cpuN.password + "\"").c_str() : "");
        printf("[CUDA    ] %s in %.3f ms e2e (kernel %.3f ms, PCIe H2D %.3f ms) | %s candidates | %.1f MH/s%s\n",
               gpu.found ? "FOUND" : "not found", gpu.e2eMs, gpu.kernelMs, gpu.h2dMs,
               comma(gpu.hashes).c_str(), gpu.kernelMhps(),
               gpu.found ? (" -> \"" + gpu.password + "\"").c_str() : "");
        return (gpu.found && cpuN.found) ? 0 : 2;
    }

    fprintf(stderr, "--mode must be bruteforce, dict or benchmark\n");
    return 1;
}
