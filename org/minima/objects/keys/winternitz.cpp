#include "org/minima/objects/keys/winternitz.hpp"

#include <cstring>
#include <algorithm>
#include <vector>
#include <array>
#include <future>
#include <thread>
#include <iostream>
#include <iomanip>
#include <sstream>

// Use OpenSSL for optimized SHA3-256
#include <openssl/evp.h>

using org::minima::objects::base::MiniData;

namespace org {
namespace minima {
namespace objects {
namespace keys {

namespace {

// DEBUG: Helper to print hex
std::string debug_hex(const std::vector<std::uint8_t>& data, int max_bytes = 16) {
    std::stringstream ss;
    ss << "0x";
    int limit = std::min(static_cast<int>(data.size()), max_bytes);
    for (int i = 0; i < limit; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (data.size() > max_bytes) {
        ss << "...";
    }
    return ss.str();
}

std::string debug_hex(const std::array<std::uint8_t, 32>& data, int max_bytes = 16) {
    std::stringstream ss;
    ss << "0x";
    int limit = std::min(32, max_bytes);
    for (int i = 0; i < limit; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (32 > max_bytes) {
        ss << "...";
    }
    return ss.str();
}

// Fixed-size hash type for better performance
using Hash256 = std::array<std::uint8_t, 32>;

// Convert vector to fixed array
inline Hash256 to_hash256(const std::vector<std::uint8_t>& v) {
    Hash256 result;
    result.fill(0);
    std::copy_n(v.begin(), std::min(v.size(), size_t(32)), result.begin());
    return result;
}

// Optimized SHA3-256 using OpenSSL
inline Hash256 sha3_256_array(const Hash256& in) {
    Hash256 out;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_reset(ctx);
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, in.data(), 32);
    unsigned int len = 32;
    EVP_DigestFinal_ex(ctx, out.data(), &len);
    EVP_MD_CTX_free(ctx);
    return out;
}

inline std::vector<std::uint8_t> sha3_256_bytes(const std::vector<std::uint8_t>& in) {
    std::vector<std::uint8_t> out(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, in.data(), in.size());
    unsigned int len = 32;
    EVP_DigestFinal_ex(ctx, out.data(), &len);
    EVP_MD_CTX_free(ctx);
    return out;
}

/**
 * Replicates Bouncy Castle's GMSSRandom.addOne()
 * Treats byte array as BIG ENDIAN number and increments by 1
 */
inline void add_one_be(std::vector<std::uint8_t>& data) {
    // Increment from the END (big-endian) to match BouncyCastle
    for (int i = data.size() - 1; i >= 0; i--) {
        data[i]++;
        if (data[i] != 0) {
            break;
        }
    }
}

// Winternitz Parameters
constexpr int w_param() { return 8; }
constexpr int n_bytes() { return 32; }

inline int l1() {
    int n = n_bytes() * 8;
    int w = w_param();
    return (n + w - 1) / w;
}

// FIXED: Compute l2 to match BouncyCastle exactly
inline int getLog(int n) {
    int n2 = 1;
    int n3 = 2;
    while (n3 < n) {
        n3 <<= 1;
        ++n2;
    }
    return n2;
}

inline int l2() {
    int w = w_param();
    int messagesize = l1();
    int checksumsize = getLog((messagesize << w) + 1);
    return (checksumsize + w - 1) / w;
}

inline int l_total() {
    return l1() + l2();
}

/**
 * Derives private key chains
 * 
 * BouncyCastle GMSSRandom.nextSeed() does HASH-THEN-INCREMENT:
 *   1. Hash the seed
 *   2. Store the hash as the key
 *   3. Increment the seed (for next iteration)
 *   4. Return the hash
 */
std::vector<Hash256> derive_private_chains(const std::vector<std::uint8_t>& seed, bool debug = false) {
    if (debug) {
        std::cout << "[C++ Winternitz] Deriving private chains" << std::endl;
        std::cout << "[C++ Winternitz]   Input seed: " << debug_hex(seed, 32) << std::endl;
        std::cout << "[C++ Winternitz]   Total chains: " << l_total() << std::endl;
    }
    
    std::vector<Hash256> x;
    int total = l_total();
    x.reserve(total);
    
    // Normalize seed exactly like Java (zero-pad or truncate, NO HASHING)
    std::vector<std::uint8_t> current_seed(n_bytes(), 0);  // Create 32-byte array filled with zeros
    
    // Copy up to 32 bytes from input seed
    size_t copy_len = std::min(seed.size(), static_cast<size_t>(n_bytes()));
    std::copy_n(seed.begin(), copy_len, current_seed.begin());
    
    if (debug) {
        std::cout << "[C++ Winternitz]   Normalized seed: " << debug_hex(current_seed, 32) << std::endl;
    }
    
    // HASH-THEN-INCREMENT (matches GMSSRandom.nextSeed())
    for (int i = 0; i < total; ++i) {
        // 1. Hash the current seed
        std::vector<std::uint8_t> key_part = sha3_256_bytes(current_seed);
        
        if (debug && i < 3) {
            std::cout << "[C++ Winternitz]   Chain[" << i << "] seed (before increment): " 
                      << debug_hex(current_seed, 32) << std::endl;
            std::cout << "[C++ Winternitz]   Chain[" << i << "] key:  " 
                      << debug_hex(key_part, 32) << std::endl;
        }
        
        x.push_back(to_hash256(key_part));
        
        // 2. Increment using BIG-ENDIAN (after hashing)
        add_one_be(current_seed);
    }
    
    if (debug) {
        std::cout << "[C++ Winternitz]   Generated " << x.size() << " private chains" << std::endl;
    }
    
    return x;
}

inline Hash256 chain_hash_opt(Hash256 current, int steps) {
    for (int i = 0; i < steps; ++i) {
        current = sha3_256_array(current);
    }
    return current;
}

std::vector<std::uint8_t> compute_public_key_parallel(const std::vector<Hash256>& x, bool debug = false) {
    const int max_steps = (1 << w_param()) - 1;
    const int num_chains = l_total();
    
    if (debug) {
        std::cout << "[C++ Winternitz] Computing public key" << std::endl;
        std::cout << "[C++ Winternitz]   Chains: " << num_chains << ", Max steps: " << max_steps << std::endl;
    }
    
    const int num_threads = std::min(std::thread::hardware_concurrency(), 
                                     static_cast<unsigned int>(num_chains));
    
    std::vector<Hash256> results(num_chains);
    std::vector<std::future<void>> futures;
    futures.reserve(num_threads);
    
    int chains_per_thread = (num_chains + num_threads - 1) / num_threads;
    
    for (int t = 0; t < num_threads; ++t) {
        int start_idx = t * chains_per_thread;
        int end_idx = std::min(start_idx + chains_per_thread, num_chains);
        
        if (start_idx >= num_chains) break;
        
        futures.push_back(std::async(std::launch::async, 
            [&x, &results, start_idx, end_idx, max_steps]() {
                for (int i = start_idx; i < end_idx; ++i) {
                    results[i] = chain_hash_opt(x[i], max_steps);
                }
            }
        ));
    }
    
    for (auto& fut : futures) {
        fut.get();
    }
    
    std::vector<std::uint8_t> concat;
    concat.reserve(num_chains * n_bytes());
    for (const auto& hash : results) {
        concat.insert(concat.end(), hash.begin(), hash.end());
    }
    
    if (debug) {
        std::cout << "[C++ Winternitz]   First endpoint: " << debug_hex(results[0], 32) << std::endl;
        std::cout << "[C++ Winternitz]   Concat length: " << concat.size() << " bytes" << std::endl;
    }
    
    std::vector<std::uint8_t> pubkey = sha3_256_bytes(concat);
    
    if (debug) {
        std::cout << "[C++ Winternitz]   Final pubkey: " << debug_hex(pubkey, 32) << std::endl;
    }
    
    return pubkey;
}

} // anonymous namespace

Winternitz::Winternitz() = default;

Winternitz::Winternitz(const MiniData& zPrivateSeed)
: mPrivateSeed(zPrivateSeed) {
    const std::vector<std::uint8_t>& seed = mPrivateSeed.getBytes();
    
    // DEBUG: Enable for key generation
    bool debug = false; // Set to true to see debug output
    
    auto x = derive_private_chains(seed, debug);
    std::vector<std::uint8_t> pub = compute_public_key_parallel(x, debug);
    
    mPublicKey = MiniData(pub);
}

MiniData Winternitz::getPublicKey() const {
    return mPublicKey;
}

MiniData Winternitz::sign(const MiniData& zData) const {
    const std::vector<std::uint8_t>& data = zData.getBytes();
    const std::vector<std::uint8_t>& seed = mPrivateSeed.getBytes();
    
    // DEBUG: Enable for signing
    bool debug = false; // Set to true to see debug output during signing
    
    if (debug) {
        std::cout << "\n[C++ Winternitz] ===== SIGNING =====" << std::endl;
        std::cout << "[C++ Winternitz] Data to sign: " << debug_hex(data, 32) << std::endl;
    }
    
    auto x = derive_private_chains(seed, false); // Don't spam chain derivation
    
    std::vector<std::uint8_t> hashed = sha3_256_bytes(data);
    
    if (debug) {
        std::cout << "[C++ Winternitz] Hashed data: " << debug_hex(hashed, 32) << std::endl;
    }
    
    // Convert to base-w - exactly like BouncyCastle for w=8
    int w = w_param();
    int messagesize = l1();
    std::vector<int> msg;
    msg.reserve(messagesize);
    
    // FIXED: Use BouncyCastle's exact logic for w=8 (8 % w == 0 case)
    if (8 % w == 0) {
        int n = 8 / w;  // For w=8, n=1 (one value per byte)
        int mask = (1 << w) - 1;  // 255 for w=8
        int sum = 0;
        
        for (int i = 0; i < static_cast<int>(hashed.size()); ++i) {
            for (int j = 0; j < n; ++j) {
                int val = hashed[i] & mask;
                sum += val;
                msg.push_back(val);
                hashed[i] = (std::uint8_t)(hashed[i] >> w);
            }
        }
        
        if (debug) {
            std::cout << "[C++ Winternitz] Base-w (first 5): ";
            for (int i = 0; i < std::min(5, (int)msg.size()); ++i) {
                std::cout << msg[i] << " ";
            }
            std::cout << std::endl;
        }
        
        // FIXED: Calculate checksum using BouncyCastle formula
        int checksum = (messagesize << w) - sum;
        
        if (debug) {
            std::cout << "[C++ Winternitz] Sum of values: " << sum << std::endl;
            std::cout << "[C++ Winternitz] Checksum ((messagesize << w) - sum): " << checksum << std::endl;
        }
        
        // Convert checksum to base-w
        int checksumsize = getLog((messagesize << w) + 1);
        for (int i = 0; i < checksumsize; i += w) {
            int val = checksum & mask;
            msg.push_back(val);
            checksum >>= w;
        }
    } else {
        // For other w values, use the general case
        // (This branch is not used for w=8, but kept for completeness)
        int bits_per_digit = w;
        int mask = (1 << bits_per_digit) - 1;
        
        for (int i = 0; i < messagesize; ++i) {
            int byte_idx = (i * bits_per_digit) / 8;
            int bit_offset = (i * bits_per_digit) % 8;
            
            if (byte_idx < static_cast<int>(hashed.size())) {
                int val = hashed[byte_idx] >> bit_offset;
                if (bit_offset + bits_per_digit > 8 && byte_idx + 1 < static_cast<int>(hashed.size())) {
                    val |= (hashed[byte_idx + 1] << (8 - bit_offset));
                }
                msg.push_back(val & mask);
            } else {
                msg.push_back(0);
            }
        }
        
        int sum = 0;
        for (int val : msg) {
            sum += val;
        }
        int checksum = (messagesize << w) - sum;
        
        int l2_val = l2();
        for (int i = 0; i < l2_val; ++i) {
            msg.push_back(checksum & mask);
            checksum >>= bits_per_digit;
        }
    }
    
    // Generate signature
    std::vector<std::uint8_t> signature;
    signature.reserve(l_total() * n_bytes());
    
    for (int i = 0; i < l_total(); ++i) {
        Hash256 sig_part = chain_hash_opt(x[i], msg[i]);
        signature.insert(signature.end(), sig_part.begin(), sig_part.end());
    }
    
    if (debug) {
        std::cout << "[C++ Winternitz] Signature length: " << signature.size() << " bytes" << std::endl;
        std::cout << "[C++ Winternitz] Signature (first 32): " << debug_hex(signature, 32) << std::endl;
        std::cout << "[C++ Winternitz] ===== SIGNING COMPLETE =====\n" << std::endl;
    }
    
    return MiniData(signature);
}

bool Winternitz::verify(const MiniData& zPublicKey, const MiniData& zData, const MiniData& zSignature) {
    const std::vector<std::uint8_t>& data = zData.getBytes();
    const std::vector<std::uint8_t>& signature = zSignature.getBytes();
    
    // DEBUG: Enable for verification
    bool debug = false; // Set to true to see debug output during verification
    
    if (debug) {
        std::cout << "\n[C++ Winternitz] ===== VERIFICATION =====" << std::endl;
        std::cout << "[C++ Winternitz] Data to verify: " << debug_hex(data, 32) << std::endl;
        std::cout << "[C++ Winternitz] Expected pubkey: " << debug_hex(zPublicKey.getBytes(), 32) << std::endl;
        std::cout << "[C++ Winternitz] Signature length: " << signature.size() << " bytes" << std::endl;
    }
    
    if (signature.size() != static_cast<size_t>(l_total() * n_bytes())) {
        if (debug) {
            std::cout << "[C++ Winternitz] ERROR: Wrong signature size!" << std::endl;
            std::cout << "[C++ Winternitz]   Expected: " << (l_total() * n_bytes()) << std::endl;
            std::cout << "[C++ Winternitz]   Got: " << signature.size() << std::endl;
        }
        return false;
    }
    
    std::vector<std::uint8_t> hashed = sha3_256_bytes(data);
    
    if (debug) {
        std::cout << "[C++ Winternitz] Hashed data: " << debug_hex(hashed, 32) << std::endl;
    }
    
    // Convert to base-w - exactly like BouncyCastle for w=8
    int w = w_param();
    int messagesize = l1();
    std::vector<int> msg;
    msg.reserve(messagesize);
    
    // FIXED: Use BouncyCastle's exact logic for w=8 (8 % w == 0 case)
    if (8 % w == 0) {
        int n = 8 / w;  // For w=8, n=1 (one value per byte)
        int mask = (1 << w) - 1;  // 255 for w=8
        int sum = 0;
        
        for (int i = 0; i < static_cast<int>(hashed.size()); ++i) {
            for (int j = 0; j < n; ++j) {
                int val = hashed[i] & mask;
                sum += val;
                msg.push_back(val);
                hashed[i] = (std::uint8_t)(hashed[i] >> w);
            }
        }
        
        if (debug) {
            std::cout << "[C++ Winternitz] Base-w (first 5): ";
            for (int i = 0; i < std::min(5, (int)msg.size()); ++i) {
                std::cout << msg[i] << " ";
            }
            std::cout << std::endl;
        }
        
        // FIXED: Calculate checksum using BouncyCastle formula
        int checksum = (messagesize << w) - sum;
        
        if (debug) {
            std::cout << "[C++ Winternitz] Checksum: " << checksum << std::endl;
        }
        
        // Convert checksum to base-w
        int checksumsize = getLog((messagesize << w) + 1);
        for (int i = 0; i < checksumsize; i += w) {
            int val = checksum & mask;
            msg.push_back(val);
            checksum >>= w;
        }
    } else {
        // For other w values, use the general case
        int bits_per_digit = w;
        int mask = (1 << bits_per_digit) - 1;
        
        for (int i = 0; i < messagesize; ++i) {
            int byte_idx = (i * bits_per_digit) / 8;
            int bit_offset = (i * bits_per_digit) % 8;
            
            if (byte_idx < static_cast<int>(hashed.size())) {
                int val = hashed[byte_idx] >> bit_offset;
                if (bit_offset + bits_per_digit > 8 && byte_idx + 1 < static_cast<int>(hashed.size())) {
                    val |= (hashed[byte_idx + 1] << (8 - bit_offset));
                }
                msg.push_back(val & mask);
            } else {
                msg.push_back(0);
            }
        }
        
        int sum = 0;
        for (int val : msg) {
            sum += val;
        }
        int checksum = (messagesize << w) - sum;
        
        int l2_val = l2();
        for (int i = 0; i < l2_val; ++i) {
            msg.push_back(checksum & mask);
            checksum >>= bits_per_digit;
        }
    }
    
    // Verify
    std::vector<std::uint8_t> derived_pubkey;
    derived_pubkey.reserve(l_total() * n_bytes());
    
    int max_val = (1 << w) - 1;
    for (int i = 0; i < l_total(); ++i) {
        int sig_offset = i * n_bytes();
        if (sig_offset + n_bytes() > signature.size()) {
            if (debug) {
                std::cout << "[C++ Winternitz] ERROR: Signature too short at offset " << sig_offset << std::endl;
            }
            return false;
        }
        
        Hash256 sig_part;
        std::copy_n(signature.begin() + sig_offset, n_bytes(), sig_part.begin());
        
        int remaining_steps = max_val - msg[i];
        Hash256 derived = chain_hash_opt(sig_part, remaining_steps);
        
        derived_pubkey.insert(derived_pubkey.end(), derived.begin(), derived.end());
    }
    
    std::vector<std::uint8_t> computed_pubkey = sha3_256_bytes(derived_pubkey);
    
    if (debug) {
        std::cout << "[C++ Winternitz] Computed pubkey: " << debug_hex(computed_pubkey, 32) << std::endl;
    }
    
    bool result = (computed_pubkey == zPublicKey.getBytes());
    
    if (debug) {
        std::cout << "[C++ Winternitz] Result: " << (result ? "SUCCESS ✓" : "FAILED ✗") << std::endl;
        std::cout << "[C++ Winternitz] ===== VERIFICATION COMPLETE =====\n" << std::endl;
    }
    
    return result;
}

} // namespace keys
} // namespace objects
} // namespace minima
} // namespace org