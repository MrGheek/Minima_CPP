#include "org/minima/utils/encrypt/password_crypto.hpp"

#include <stdexcept>
#include <vector>
#include <sstream>
#include <iostream>
#include <iterator>
#include <cstring>

#include "org/minima/objects/base/mini_data.hpp"

// OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

// zlib
#include <zlib.h>

namespace org {
namespace minima {
namespace utils {
namespace encrypt {

namespace {

// Configuration defaults (assumed in absence of GenerateKey.java)
constexpr int KDF_ITERATIONS = 100000;          // PBKDF2 iterations (tunable)
constexpr std::size_t AES_KEY_LEN = 32;         // AES-256
constexpr std::size_t AES_BLOCK_LEN = 16;       // AES block size / IV length
constexpr std::size_t SALT_LEN = 16;            // Salt length (NIST recommends >= 16 bytes); length is serialized so legacy 8-byte salts still decrypt

// PBKDF2 settings for at-rest password hashing (RPC users)
constexpr int PW_HASH_ITERATIONS = 100000;
constexpr std::size_t PW_HASH_KEY_LEN = 32;
constexpr std::size_t PW_HASH_SALT_LEN = 16;
constexpr const char* PW_HASH_PREFIX = "pbkdf2$";

std::string to_hex_lower(const std::vector<std::uint8_t>& bytes) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        out.push_back(digits[(b >> 4) & 0x0F]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool from_hex(const std::string& hex, std::vector<std::uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

std::string openssl_last_error() {
    unsigned long err = ERR_get_error();
    if (err == 0) return std::string();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

std::vector<std::uint8_t> pbkdf2_hmac_sha256(const std::string& password,
                                             const std::vector<std::uint8_t>& salt,
                                             int iterations,
                                             std::size_t key_len) {
    std::vector<std::uint8_t> key(key_len);
    int ok = PKCS5_PBKDF2_HMAC(
        password.c_str(), static_cast<int>(password.size()),
        salt.empty() ? nullptr : salt.data(), static_cast<int>(salt.size()),
        iterations, EVP_sha256(),
        static_cast<int>(key_len), key.data()
    );
    if (ok != 1) {
        throw std::runtime_error("PBKDF2_HMAC_SHA256 failed: " + openssl_last_error());
    }
    return key;
}

std::vector<std::uint8_t> aes_encrypt_cbc(const std::vector<std::uint8_t>& plaintext,
                                          const std::vector<std::uint8_t>& key,
                                          const std::vector<std::uint8_t>& iv) {
    const EVP_CIPHER* cipher = nullptr;
    switch (key.size()) {
        case 16: cipher = EVP_aes_128_cbc(); break;
        case 24: cipher = EVP_aes_192_cbc(); break;
        case 32: cipher = EVP_aes_256_cbc(); break;
        default: throw std::runtime_error("Unsupported AES key length");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<std::uint8_t> ciphertext(plaintext.size() + AES_BLOCK_LEN);
    int len = 0;
    int total = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) != 1) {
        std::string err = openssl_last_error();
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed: " + err);
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        std::string err = openssl_last_error();
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed: " + err);
    }
    total = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len) != 1) {
        std::string err = openssl_last_error();
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed: " + err);
    }
    total += len;
    ciphertext.resize(static_cast<std::size_t>(total));
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<std::uint8_t> aes_decrypt_cbc(const std::vector<std::uint8_t>& ciphertext,
                                          const std::vector<std::uint8_t>& key,
                                          const std::vector<std::uint8_t>& iv) {
    const EVP_CIPHER* cipher = nullptr;
    switch (key.size()) {
        case 16: cipher = EVP_aes_128_cbc(); break;
        case 24: cipher = EVP_aes_192_cbc(); break;
        case 32: cipher = EVP_aes_256_cbc(); break;
        default: throw std::runtime_error("Unsupported AES key length");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<std::uint8_t> plaintext(ciphertext.size() + AES_BLOCK_LEN);
    int len = 0;
    int total = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) != 1) {
        std::string err = openssl_last_error();
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed: " + err);
    }

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1) {
        std::string err = openssl_last_error();
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed: " + err);
    }
    total = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len) != 1) {
        std::string err = openssl_last_error();
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed: " + err);
    }
    total += len;
    plaintext.resize(static_cast<std::size_t>(total));
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// GZIP compress using zlib (deflate with gzip header)
std::vector<std::uint8_t> gzip_compress(const std::vector<std::uint8_t>& input) {
    z_stream strm{};
    int ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) throw std::runtime_error("deflateInit2 failed");

    std::vector<std::uint8_t> out;
    out.reserve(input.size() / 2 + 64);

    constexpr std::size_t CHUNK = 16384;
    std::vector<std::uint8_t> outbuf(CHUNK);

    strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input.data()));
    strm.avail_in = static_cast<uInt>(input.size());

    do {
        strm.next_out = outbuf.data();
        strm.avail_out = static_cast<uInt>(outbuf.size());

        int flush = (strm.avail_in == 0) ? Z_FINISH : Z_NO_FLUSH;
        ret = deflate(&strm, flush);
        if (ret == Z_STREAM_ERROR) {
            deflateEnd(&strm);
            throw std::runtime_error("deflate Z_STREAM_ERROR");
        }

        std::size_t have = outbuf.size() - strm.avail_out;
        out.insert(out.end(), outbuf.data(), outbuf.data() + have);
    } while (ret != Z_STREAM_END);

    deflateEnd(&strm);
    return out;
}

// GZIP decompress using zlib (inflate with gzip header)
std::vector<std::uint8_t> gzip_decompress(const std::vector<std::uint8_t>& input) {
    z_stream strm{};
    int ret = inflateInit2(&strm, 15 + 16);
    if (ret != Z_OK) throw std::runtime_error("inflateInit2 failed");

    std::vector<std::uint8_t> out;
    out.reserve(input.size() * 2 + 64);

    constexpr std::size_t CHUNK = 16384;
    std::vector<std::uint8_t> outbuf(CHUNK);

    strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input.data()));
    strm.avail_in = static_cast<uInt>(input.size());

    do {
        strm.next_out = outbuf.data();
        strm.avail_out = static_cast<uInt>(outbuf.size());

        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&strm);
            throw std::runtime_error("inflate error");
        }
        std::size_t have = outbuf.size() - strm.avail_out;
        out.insert(out.end(), outbuf.data(), outbuf.data() + have);
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    return out;
}

std::vector<std::uint8_t> random_bytes(std::size_t len) {
    std::vector<std::uint8_t> buf(len);
    if (len > 0) {
        if (RAND_bytes(buf.data(), static_cast<int>(len)) != 1) {
            throw std::runtime_error("RAND_bytes failed: " + openssl_last_error());
        }
    }
    return buf;
}

} // anonymous namespace

org::minima::objects::base::MiniData PasswordCrypto::encryptPassword(
    const std::string& zPassword,
    const org::minima::objects::base::MiniData& zData) {

    using org::minima::objects::base::MiniData;

    // 1) Generate Salt (8 bytes) and IV (16 bytes)
    MiniData salt = MiniData::getRandomData(static_cast<int>(SALT_LEN));
    std::vector<std::uint8_t> iv = random_bytes(AES_BLOCK_LEN);

    // 2) Derive key from password and salt
    std::vector<std::uint8_t> secret = pbkdf2_hmac_sha256(zPassword, salt.getBytes(), KDF_ITERATIONS, AES_KEY_LEN);

    // 3) Serialize payload (MiniData.writeDataStream) - writeDataStream is non-const, so copy first
    MiniData dataCopy = zData;
    std::ostringstream payload_stream(std::ios::binary);
    dataCopy.writeDataStream(payload_stream);
    const std::string payload_str = payload_stream.str();
    std::vector<std::uint8_t> payload(payload_str.begin(), payload_str.end());

    // 4) GZIP compress the payload
    std::vector<std::uint8_t> compressed = gzip_compress(payload);

    // 5) AES encrypt compressed data
    std::vector<std::uint8_t> ciphertext = aes_encrypt_cbc(compressed, secret, iv);

    // 6) Construct final output: salt.writeDataStream, iv.writeDataStream, then ciphertext raw bytes
    MiniData ivmd(iv);
    std::ostringstream out(std::ios::binary);
    salt.writeDataStream(out);
    ivmd.writeDataStream(out);
    out.write(reinterpret_cast<const char*>(ciphertext.data()), static_cast<std::streamsize>(ciphertext.size()));

    const std::string outstr = out.str();
    std::vector<std::uint8_t> finalbytes(outstr.begin(), outstr.end());
    return MiniData(finalbytes);
}

org::minima::objects::base::MiniData PasswordCrypto::decryptPassword(
    const std::string& zPassword,
    const org::minima::objects::base::MiniData& zEncryptedData) {

    using org::minima::objects::base::MiniData;

    // Prepare input stream
    const std::vector<std::uint8_t>& inbytes = zEncryptedData.getBytes();
    std::istringstream in(std::string(reinterpret_cast<const char*>(inbytes.data()), inbytes.size()),
                          std::ios::binary);

    // 1) Read salt and IV MiniData frames
    MiniData salt = MiniData::ReadFromStream(in);
    MiniData ivmd = MiniData::ReadFromStream(in);
    const std::vector<std::uint8_t>& iv = ivmd.getBytes();

    if (iv.size() != AES_BLOCK_LEN) {
        throw std::runtime_error("Unexpected IV length in encrypted data");
    }

    // 2) Read remaining bytes as ciphertext
    std::vector<std::uint8_t> ciphertext;
    {
        std::string rest((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        ciphertext.assign(rest.begin(), rest.end());
    }

    // 3) Derive key
    std::vector<std::uint8_t> secret = pbkdf2_hmac_sha256(zPassword, salt.getBytes(), KDF_ITERATIONS, AES_KEY_LEN);

    // 4) Decrypt
    std::vector<std::uint8_t> decompressed_input = aes_decrypt_cbc(ciphertext, secret, iv);

    // 5) GZIP decompress
    std::vector<std::uint8_t> plain = gzip_decompress(decompressed_input);

    // 6) Read MiniData from plaintext stream
    std::istringstream pstream(std::string(reinterpret_cast<const char*>(plain.data()), plain.size()),
                               std::ios::binary);
    MiniData decrypted = MiniData::ReadFromStream(pstream);

    return decrypted;
}

std::string PasswordCrypto::hashPassword(const std::string& zPassword) {
    // Generate a random salt
    std::vector<std::uint8_t> salt(PW_HASH_SALT_LEN);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed: " + openssl_last_error());
    }

    std::vector<std::uint8_t> hash =
        pbkdf2_hmac_sha256(zPassword, salt, PW_HASH_ITERATIONS, PW_HASH_KEY_LEN);

    std::string out;
    out.reserve(64 + 64);
    out.append(PW_HASH_PREFIX);
    out.append(std::to_string(PW_HASH_ITERATIONS));
    out.push_back('$');
    out.append(to_hex_lower(salt));
    out.push_back('$');
    out.append(to_hex_lower(hash));
    return out;
}

bool PasswordCrypto::verifyPassword(const std::string& zPassword, const std::string& zStored) {
    try {
        const std::string prefix = PW_HASH_PREFIX;
        if (zStored.compare(0, prefix.size(), prefix) != 0) {
            // Legacy plaintext value: compare in constant time. Digest both
            // values first so neither the length nor the content is leaked
            // through the comparison timing.
            unsigned char ha[SHA256_DIGEST_LENGTH];
            unsigned char hb[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(zPassword.data()), zPassword.size(), ha);
            SHA256(reinterpret_cast<const unsigned char*>(zStored.data()), zStored.size(), hb);
            return CRYPTO_memcmp(ha, hb, SHA256_DIGEST_LENGTH) == 0;
        }

        std::string rest = zStored.substr(prefix.size());
        std::size_t iter_end = rest.find('$');
        if (iter_end == std::string::npos) return false;
        int iterations = std::stoi(rest.substr(0, iter_end));
        if (iterations <= 0) return false;

        std::string rest2 = rest.substr(iter_end + 1);
        std::size_t salt_end = rest2.find('$');
        if (salt_end == std::string::npos) return false;

        std::vector<std::uint8_t> salt;
        if (!from_hex(rest2.substr(0, salt_end), salt)) return false;

        std::vector<std::uint8_t> expected;
        if (!from_hex(rest2.substr(salt_end + 1), expected)) return false;

        std::vector<std::uint8_t> actual =
            pbkdf2_hmac_sha256(zPassword, salt, iterations, expected.size());

        if (actual.size() != expected.size()) return false;
        return CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) == 0;
    } catch (...) {
        return false;
    }
}

} // namespace encrypt
} // namespace utils
} // namespace minima
} // namespace org
