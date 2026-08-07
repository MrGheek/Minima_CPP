/**
 * benchmark_minima.cpp
 *
 * Standalone micro-benchmarks for Pure Minima C++.
 * Measures throughput of critical cryptographic and serialization operations.
 *
 * Build: cmake --build <build-dir> --target benchmark_minima
 * Run:   ./benchmark_minima
 */

#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>

static constexpr int WARMUP_ITERS = 100;
static constexpr int BENCH_ITERS = 10000;

struct BenchResult {
    std::string name;
    double opsPerSec;
    double usPerOp;
    double mbPerSec;
};

static double nowMicros() {
    auto now = std::chrono::high_resolution_clock::now();
    return static_cast<double>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count());
}

static BenchResult runBench(const std::string& name,
                             const std::function<void()>& fn,
                             int iters = BENCH_ITERS) {
    // Warmup
    for (int i = 0; i < WARMUP_ITERS; ++i) fn();

    double start = nowMicros();
    for (int i = 0; i < iters; ++i) fn();
    double end = nowMicros();

    double elapsedUs = end - start;
    double opsPerSec = (static_cast<double>(iters) / elapsedUs) * 1e6;
    double usPerOp = elapsedUs / static_cast<double>(iters);

    return {name, opsPerSec, usPerOp, 0.0};
}

static BenchResult runDataBench(const std::string& name,
                                 const std::function<void()>& fn,
                                 int iters, size_t bytesPerOp) {
    auto result = runBench(name, fn, iters);
    result.mbPerSec = (result.opsPerSec * static_cast<double>(bytesPerOp)) / (1024.0 * 1024.0);
    return result;
}

static void printResult(const BenchResult& r) {
    std::cout << std::left << std::setw(40) << r.name
              << std::right << std::setw(12) << std::fixed << std::setprecision(1)
              << r.opsPerSec << " ops/s"
              << std::setw(10) << std::fixed << std::setprecision(2)
              << r.usPerOp << " us/op";
    if (r.mbPerSec > 0.0) {
        std::cout << std::setw(12) << std::fixed << std::setprecision(2)
                  << r.mbPerSec << " MB/s";
    }
    std::cout << std::endl;
}

// =====================================================================
// SHA3-256 benchmarks
// =====================================================================

static std::vector<unsigned char> sha3_256(const unsigned char* data, size_t len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, &hashLen);
    EVP_MD_CTX_free(ctx);
    return std::vector<unsigned char>(hash, hash + hashLen);
}

static void benchSHA3() {
    std::cout << "\n=== SHA3-256 Benchmarks ===" << std::endl;

    // 32-byte input (typical hash input)
    {
        std::vector<unsigned char> data(32, 0x42);
        auto r = runDataBench("SHA3-256 (32B)", [&]() { sha3_256(data.data(), 32); },
                              BENCH_ITERS, 32);
        printResult(r);
    }

    // 1KB input
    {
        std::vector<unsigned char> data(1024, 0x42);
        auto r = runDataBench("SHA3-256 (1KB)", [&]() { sha3_256(data.data(), 1024); },
                              BENCH_ITERS / 10, 1024);
        printResult(r);
    }

    // 1MB input
    {
        std::vector<unsigned char> data(1024 * 1024, 0x42);
        auto r = runDataBench("SHA3-256 (1MB)", [&]() { sha3_256(data.data(), data.size()); },
                              100, 1024 * 1024);
        printResult(r);
    }
}

// =====================================================================
// Winternitz OTS benchmarks
// =====================================================================

static constexpr int W = 8;
static constexpr int N = 32;
static constexpr int L1 = (N * 8 + W - 1) / W;
static constexpr int MAX_VAL = (1 << W) - 1;

static int getLog(int n) {
    int n2 = 1, n3 = 2;
    while (n3 < n) { n3 <<= 1; ++n2; }
    return n2;
}
static int L2() { return (getLog((L1 << W) + 1) + W - 1) / W; }
static int L_TOTAL() { return L1 + L2(); }

static void benchWinternitz() {
    std::cout << "\n=== Winternitz OTS Benchmarks ===" << std::endl;

    int l_total = L_TOTAL();
    int l2 = L2();

    // Key generation
    {
        auto r = runBench("Winternitz keygen", [&]() {
            std::vector<unsigned char> seed(N, 0x42);
            std::vector<unsigned char> cur = seed;
            for (int i = 0; i < l_total; ++i) {
                auto chain = sha3_256(cur.data(), N);
                for (int j = N - 1; j >= 0; --j) {
                    cur[j]++;
                    if (cur[j] != 0) break;
                }
                // Hash to public key endpoint
                auto pub = chain;
                for (int k = 0; k < MAX_VAL; ++k) {
                    pub = sha3_256(pub.data(), N);
                }
            }
        }, BENCH_ITERS / 10);
        printResult(r);
    }

    // Sign (32-byte message)
    {
        auto r = runBench("Winternitz sign (32B)", [&]() {
            std::vector<unsigned char> seed(N, 0x42);
            std::vector<unsigned char> msg(32, 0x01);
            auto msgHash = sha3_256(msg.data(), 32);

            std::vector<unsigned char> cur = seed;
            for (int i = 0; i < l_total; ++i) {
                auto chain = sha3_256(cur.data(), N);
                int steps = msgHash[i % 32] & 0xFF;
                for (int s = 0; s < steps; ++s) {
                    chain = sha3_256(chain.data(), N);
                }
                for (int j = N - 1; j >= 0; --j) {
                    cur[j]++;
                    if (cur[j] != 0) break;
                }
            }
        }, BENCH_ITERS / 10);
        printResult(r);
    }
}

// =====================================================================
// RAND_bytes benchmark
// =====================================================================

static void benchRandom() {
    std::cout << "\n=== CSPRNG Benchmarks ===" << std::endl;

    // 32 bytes
    {
        std::vector<unsigned char> buf(32);
        auto r = runDataBench("RAND_bytes (32B)", [&]() { RAND_bytes(buf.data(), 32); },
                              BENCH_ITERS * 10, 32);
        printResult(r);
    }

    // 256 bytes
    {
        std::vector<unsigned char> buf(256);
        auto r = runDataBench("RAND_bytes (256B)", [&]() { RAND_bytes(buf.data(), 256); },
                              BENCH_ITERS, 256);
        printResult(r);
    }
}

// =====================================================================
// Main
// =====================================================================

int main() {
    std::cout << "=== Pure Minima C++ Micro-Benchmarks ===" << std::endl;
    std::cout << "Warmup: " << WARMUP_ITERS << " iterations per test" << std::endl;
    std::cout << "Bench:  " << BENCH_ITERS << " iterations per test (adjusted for large inputs)" << std::endl;

    benchSHA3();
    benchWinternitz();
    benchRandom();

    std::cout << "\n=== Done ===" << std::endl;
    return 0;
}
