/**
 * test_sha3.cpp - Standalone SHA3-256 Known-Answer Test
 *
 * Verifies that OpenSSL's SHA3-256 (FIPS 202 / Keccak-based) produces
 * the expected digests for standard NIST test vectors.
 *
 * Build: cmake --build <build-dir> --target test_sha3
 * Run:   ./build/test_sha3
 */

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>

static std::string to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

static bool sha3_256(const unsigned char* msg, size_t msg_len,
                     unsigned char out[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) == 1 &&
              EVP_DigestUpdate(ctx, msg, msg_len) == 1;
    unsigned int dlen = 32;
    ok = ok && (EVP_DigestFinal_ex(ctx, out, &dlen) == 1);
    EVP_MD_CTX_free(ctx);
    return ok && dlen == 32;
}

struct KAT {
    const char* description;
    const char* input_hex; // hex-encoded input ("" for empty)
    const char* expected_hex;
};

// NIST SHA3-256 Known Answer Test vectors (FIPS 202)
static const KAT kats[] = {
    {
        "empty string",
        "",
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    },
    {
        "abc",
        "616263",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    },
    {
        "message digest",
        "6d65737361676520646967657374",
        "edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd"
    },
};

int main() {
    int pass = 0, fail = 0;

    for (const auto& kat : kats) {
        // Decode hex input
        std::string hex_in(kat.input_hex);
        size_t in_len = hex_in.size() / 2;
        unsigned char input[256] = {};
        for (size_t i = 0; i < in_len; ++i) {
            unsigned int byte;
            sscanf(hex_in.c_str() + 2 * i, "%02x", &byte);
            input[i] = static_cast<unsigned char>(byte);
        }

        unsigned char digest[32];
        if (!sha3_256(input, in_len, digest)) {
            printf("[FAIL] %s: sha3_256 returned error\n", kat.description);
            ++fail;
            continue;
        }

        std::string got = to_hex(digest, 32);
        if (got != kat.expected_hex) {
            printf("[FAIL] %s:\n  expected: %s\n  got:      %s\n",
                   kat.description, kat.expected_hex, got.c_str());
            ++fail;
        } else {
            printf("[PASS] SHA3-256(%s)\n", kat.description);
            ++pass;
        }
    }

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
