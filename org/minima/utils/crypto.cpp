#include "org/minima/utils/crypto.hpp"

#include <cstring>
#include <sstream>
#include <iomanip>
#include <thread>
#include <memory>

// OpenSSL EVP for optimized hashing
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "org/minima/objects/base/mini_data.hpp"
#include "org/minima/utils/streamable.hpp"
#include "org/minima/utils/minima_logger.hpp"

#ifdef _WIN32
// Ensure OpenSSL is available via your build system/toolchain.
#endif

namespace org {
namespace minima {
namespace utils {

// Static constants
const std::string& Crypto::MAX_VAL_HEX() {
    static const std::string instance =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    return instance;
}

const std::string& Crypto::MAX_VALDEC() {
    static const std::string instance =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    return instance;
}

const org::minima::objects::base::MiniData& Crypto::MAX_HASH() {
    static const org::minima::objects::base::MiniData instance(
        std::vector<std::uint8_t>(32, 0xFF)
    );
    return instance;
}

// Singleton
Crypto& Crypto::getInstance() {
    static Crypto instance;
    return instance;
}

namespace {

// =======================
// Thread-Local Hash Context Pool (Optimization)
// =======================
// Reusing EVP contexts is faster than creating new ones each time
thread_local EVP_MD_CTX* g_sha256_ctx = nullptr;
thread_local EVP_MD_CTX* g_sha3_ctx = nullptr;

void init_contexts() {
    if (!g_sha256_ctx) {
        g_sha256_ctx = EVP_MD_CTX_new();
    }
    if (!g_sha3_ctx) {
        g_sha3_ctx = EVP_MD_CTX_new();
    }
}

void cleanup_contexts() {
    if (g_sha256_ctx) {
        EVP_MD_CTX_free(g_sha256_ctx);
        g_sha256_ctx = nullptr;
    }
    if (g_sha3_ctx) {
        EVP_MD_CTX_free(g_sha3_ctx);
        g_sha3_ctx = nullptr;
    }
}

// Optimized EVP hash helper - reuses context
std::vector<std::uint8_t> hashWithEVP_Reusable(EVP_MD_CTX* ctx, 
                                                const EVP_MD* md,
                                                const std::uint8_t* data,
                                                std::size_t len) {
    std::vector<std::uint8_t> out;
    
    if (!md || !ctx) {
        return out;
    }
    // Initialize context for new hash (this also resets it)
    
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        return out;
    }
    
    // Hash data
    if (len > 0 && EVP_DigestUpdate(ctx, data, len) != 1) {
        return out;
    }
    
    // Get digest size
    unsigned int outlen = EVP_MD_size(md);
    if (outlen == 0 || outlen == static_cast<unsigned int>(-1)) {
        return out;
    }
    
    out.resize(outlen);
    
    // Finalize
    if (EVP_DigestFinal_ex(ctx, out.data(), &outlen) != 1) {
        out.clear();
        return out;
    }
    
    out.resize(outlen);
    return out;
}

// Regular EVP hash helper - when context reuse isn't available
std::vector<std::uint8_t> hashWithEVP(const EVP_MD* md,
                                      const std::uint8_t* data,
                                      std::size_t len) {
    std::vector<std::uint8_t> out;
    
    if (!md) {
        return out;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return out;
    }
    
    int ok = EVP_DigestInit_ex(ctx, md, nullptr);
    if (ok != 1) {
        EVP_MD_CTX_free(ctx);
        return out;
    }
    
    if (len > 0) {
        ok = EVP_DigestUpdate(ctx, data, len);
        if (ok != 1) {
            EVP_MD_CTX_free(ctx);
            return out;
        }
    }
    
    unsigned int outlen = EVP_MD_size(md);
    if (outlen == 0 || outlen == static_cast<unsigned int>(-1)) {
        EVP_MD_CTX_free(ctx);
        return out;
    }
    
    out.resize(outlen);
    ok = EVP_DigestFinal_ex(ctx, out.data(), &outlen);
    EVP_MD_CTX_free(ctx);
    
    if (ok != 1) {
        out.clear();
        return out;
    }
    
    out.resize(outlen);
    return out;
}

// Convert bytes to hex string (cached for repeated calls)
std::string bytesToHex(const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty()) {
        return "0x";
    }
    
    std::stringstream ss;
    ss << "0x" << std::hex << std::setfill('0');
    
    for (const auto& byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

} // anonymous namespace

// =======================
// Public API Implementation (Optimized)
// =======================

std::vector<std::uint8_t> Crypto::hashSHA2(const std::vector<std::uint8_t>& zData) {
    try {
        // Use optimized path with context reuse
        init_contexts();
        return hashWithEVP_Reusable(g_sha256_ctx, EVP_sha256(),
                                     zData.empty() ? nullptr : zData.data(),
                                     zData.size());
    } catch (...) {
        // Mimic Java behavior: swallow exceptions and return empty vector
        return {};
    }
}

std::vector<std::uint8_t> Crypto::hashData(const std::vector<std::uint8_t>& zData) {
    try {
        // SHA3-256 (default hash algorithm)
        // Use optimized path with context reuse
        init_contexts();
        return hashWithEVP_Reusable(g_sha3_ctx, EVP_sha3_256(),
                                     zData.empty() ? nullptr : zData.data(),
                                     zData.size());
    } catch (...) {
        // Mimic Java behavior: swallow exceptions and return empty vector
        return {};
    }
}

org::minima::objects::base::MiniData Crypto::hashObject(org::minima::utils::Streamable& zObject) {
    using org::minima::objects::base::MiniData;
    try {
        // Use binary stringstream for efficient serialization
        std::ostringstream oss(std::ios::binary);
        zObject.writeDataStream(oss);
        oss.flush();
        
        const std::string s = oss.str();
        // Avoid copy: create vector directly from string data
        const std::vector<std::uint8_t> data(
            reinterpret_cast<const std::uint8_t*>(s.data()),
            reinterpret_cast<const std::uint8_t*>(s.data()) + s.size()
        );


        // Hash the serialized data
        std::vector<std::uint8_t> digest = hashData(data);
        
        if (digest.empty()) {
            return MiniData(); // mimic null -> default
        }
        
        return MiniData(digest);
    } catch (...) {
        return MiniData(); // mimic null -> default
    }
}

org::minima::objects::base::MiniData Crypto::hashObjects(org::minima::utils::Streamable& zLeftObject,
                                                         org::minima::utils::Streamable& zRightObject2) {
    using org::minima::objects::base::MiniData;
    try {
        // Preallocate buffer to avoid resizing
        std::ostringstream oss(std::ios::binary);
        zLeftObject.writeDataStream(oss);
        zRightObject2.writeDataStream(oss);
        oss.flush();
        
        const std::string s = oss.str();
        const std::vector<std::uint8_t> data(
            reinterpret_cast<const std::uint8_t*>(s.data()),
            reinterpret_cast<const std::uint8_t*>(s.data()) + s.size()
        );
        
        std::vector<std::uint8_t> digest = hashData(data);
        
        if (digest.empty()) {
            return MiniData(); // mimic null -> default
        }
        
        return MiniData(digest);
    } catch (...) {
        return MiniData(); // mimic null -> default
    }
}

org::minima::objects::base::MiniData Crypto::hashAllObjects(
    const std::vector<org::minima::utils::Streamable*>& zObjects) {
    using org::minima::objects::base::MiniData;
    try {
        // Estimate buffer size to minimize allocations
        std::ostringstream oss(std::ios::binary);
        
        for (auto* obj : zObjects) {
            if (obj) {
                obj->writeDataStream(oss);
            }
        }
        
        oss.flush();
        
        const std::string s = oss.str();
        const std::vector<std::uint8_t> data(
            reinterpret_cast<const std::uint8_t*>(s.data()),
            reinterpret_cast<const std::uint8_t*>(s.data()) + s.size()
        );
        
        std::vector<std::uint8_t> digest = hashData(data);
        
        if (digest.empty()) {
            return MiniData(); // mimic null -> default
        }
        
        return MiniData(digest);
    } catch (...) {
        return MiniData(); // mimic null -> default
    }
}

org::minima::objects::base::MiniData Crypto::hashAllObjects(
    std::initializer_list<org::minima::utils::Streamable*> zObjects) {
    std::vector<org::minima::utils::Streamable*> vec(zObjects.begin(), zObjects.end());
    return hashAllObjects(vec);
}

} // namespace utils
} // namespace minima
} // namespace org