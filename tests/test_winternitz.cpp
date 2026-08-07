/**
 * test_winternitz.cpp - Standalone Winternitz OTS self-test
 *
 * Implements a minimal Winternitz One-Time Signature (W=16) over SHA3-256
 * using OpenSSL directly, then exercises sign/verify round-trips and
 * checks that tampered messages/signatures fail verification.
 *
 * Build: cmake --build <build-dir> --target test_winternitz
 * Run:   ./build/test_winternitz
 */

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <array>
#include <openssl/evp.h>
#include <openssl/rand.h>

// ---------------------------------------------------------------------------
// Minimal SHA3-256 wrappers
// ---------------------------------------------------------------------------

using Hash256 = std::array<uint8_t, 32>;

static Hash256 sha3_256(const uint8_t* data, size_t len) {
    Hash256 out;
    unsigned int dlen = 32;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out.data(), &dlen);
    EVP_MD_CTX_free(ctx);
    return out;
}

static Hash256 sha3_256(const Hash256& in) {
    return sha3_256(in.data(), 32);
}

// ---------------------------------------------------------------------------
// Winternitz-16 parameters
//   W=16  → each nibble (4 bits) maps to one chain
//   A 32-byte message hash has 64 nibbles → 64 private chains
//   Checksum needs log2(64 * 15) / log2(16) = ~2 more chains → use 4 for safety
//   Total chains = 64 + 4 = 68
// ---------------------------------------------------------------------------

static constexpr int W            = 16;   // alphabet size
static constexpr int MSG_NIBBLES  = 64;   // nibbles in 32-byte hash
static constexpr int CS_CHAINS    = 4;    // checksum chains
static constexpr int NUM_CHAINS   = MSG_NIBBLES + CS_CHAINS;   // 68

// Hash a chain 'steps' times starting from 'in'
static Hash256 chain(Hash256 val, int steps) {
    for (int i = 0; i < steps; ++i)
        val = sha3_256(val);
    return val;
}

struct WinternitzKey {
    std::array<Hash256, NUM_CHAINS> priv;
    std::array<Hash256, NUM_CHAINS> pub;
};

static WinternitzKey keygen(const uint8_t seed[32]) {
    WinternitzKey k;
    // Derive each private chain by hashing seed || index
    for (int i = 0; i < NUM_CHAINS; ++i) {
        uint8_t buf[33];
        memcpy(buf, seed, 32);
        buf[32] = static_cast<uint8_t>(i);
        k.priv[i] = sha3_256(buf, 33);
        k.pub[i]  = chain(k.priv[i], W - 1);
    }
    return k;
}

using Signature = std::array<Hash256, NUM_CHAINS>;

static Signature sign(const WinternitzKey& k, const Hash256& msg_hash) {
    Signature sig;

    // Extract nibbles from msg_hash
    uint8_t nibbles[MSG_NIBBLES];
    for (int i = 0; i < 32; ++i) {
        nibbles[2 * i]     = (msg_hash[i] >> 4) & 0xF;
        nibbles[2 * i + 1] =  msg_hash[i]       & 0xF;
    }

    // Checksum: sum of (W-1 - nibble)
    int cs = 0;
    for (int i = 0; i < MSG_NIBBLES; ++i) cs += (W - 1) - nibbles[i];

    // Encode checksum in CS_CHAINS nibbles (big-endian, base W)
    uint8_t cs_nibbles[CS_CHAINS];
    for (int i = CS_CHAINS - 1; i >= 0; --i) {
        cs_nibbles[i] = static_cast<uint8_t>(cs % W);
        cs /= W;
    }

    // Sign message nibbles
    for (int i = 0; i < MSG_NIBBLES; ++i)
        sig[i] = chain(k.priv[i], nibbles[i]);

    // Sign checksum nibbles
    for (int i = 0; i < CS_CHAINS; ++i)
        sig[MSG_NIBBLES + i] = chain(k.priv[MSG_NIBBLES + i], cs_nibbles[i]);

    return sig;
}

static bool verify(const std::array<Hash256, NUM_CHAINS>& pub,
                   const Hash256& msg_hash,
                   const Signature& sig) {
    uint8_t nibbles[MSG_NIBBLES];
    for (int i = 0; i < 32; ++i) {
        nibbles[2 * i]     = (msg_hash[i] >> 4) & 0xF;
        nibbles[2 * i + 1] =  msg_hash[i]       & 0xF;
    }

    int cs = 0;
    for (int i = 0; i < MSG_NIBBLES; ++i) cs += (W - 1) - nibbles[i];

    uint8_t cs_nibbles[CS_CHAINS];
    for (int i = CS_CHAINS - 1; i >= 0; --i) {
        cs_nibbles[i] = static_cast<uint8_t>(cs % W);
        cs /= W;
    }

    // Complete each chain and compare to public key
    for (int i = 0; i < MSG_NIBBLES; ++i) {
        if (chain(sig[i], (W - 1) - nibbles[i]) != pub[i])
            return false;
    }
    for (int i = 0; i < CS_CHAINS; ++i) {
        if (chain(sig[MSG_NIBBLES + i], (W - 1) - cs_nibbles[i]) != pub[MSG_NIBBLES + i])
            return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

int main() {
    int pass = 0, fail = 0;

    // Generate a random seed
    uint8_t seed[32];
    RAND_bytes(seed, 32);

    WinternitzKey k = keygen(seed);

    // Test 1: sign/verify round-trip
    {
        const char* msg = "Hello, Winternitz!";
        Hash256 h = sha3_256(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
        Signature sig = sign(k, h);
        bool ok = verify(k.pub, h, sig);
        if (ok) { printf("[PASS] sign/verify round-trip\n"); ++pass; }
        else    { printf("[FAIL] sign/verify round-trip\n"); ++fail; }
    }

    // Test 2: tampered message must not verify
    {
        const char* msg = "Hello, Winternitz!";
        Hash256 h = sha3_256(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
        Signature sig = sign(k, h);
        // Flip a bit in the message hash
        h[0] ^= 0xFF;
        bool ok = verify(k.pub, h, sig);
        if (!ok) { printf("[PASS] tampered message rejected\n"); ++pass; }
        else     { printf("[FAIL] tampered message accepted (should fail)\n"); ++fail; }
    }

    // Test 3: tampered signature must not verify
    {
        const char* msg = "Another test message";
        Hash256 h = sha3_256(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
        Signature sig = sign(k, h);
        // Flip a bit in the signature
        sig[0][0] ^= 0x01;
        bool ok = verify(k.pub, h, sig);
        if (!ok) { printf("[PASS] tampered signature rejected\n"); ++pass; }
        else     { printf("[FAIL] tampered signature accepted (should fail)\n"); ++fail; }
    }

    // Test 4: different keys, same message
    {
        uint8_t seed2[32];
        RAND_bytes(seed2, 32);
        WinternitzKey k2 = keygen(seed2);
        const char* msg = "Cross-key test";
        Hash256 h = sha3_256(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
        Signature sig = sign(k, h);
        bool ok = verify(k2.pub, h, sig); // must fail
        if (!ok) { printf("[PASS] signature from different key rejected\n"); ++pass; }
        else     { printf("[FAIL] signature from different key accepted\n"); ++fail; }
    }

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
