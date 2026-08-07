#include "org/minima/objects/base/mini_string.hpp"

#include <stdexcept>
#include <limits>
#include <cstring>

#include "org/minima/objects/base/mini_data.hpp"

namespace {

// This is the UTF-8 byte sequence for the Unicode Replacement Character (U+FFFD)
const char* UTF8_REPLACEMENT_CHAR = "\xEF\xBF\xBD";
const size_t UTF8_REPLACEMENT_CHAR_LEN = 3;

/**
 * @brief Sanitizes a byte stream, replacing invalid UTF-8 sequences with the
 * Unicode replacement character (U+FFFD), mimicking Java's
 * new String(bytes, "UTF-8") behavior.
 *
 * @param data A pointer to the raw byte data.
 * @param len The length of the raw byte data.
 * @return A std::string containing valid UTF-8.
 */
std::string sanitize_utf8(const char* data, size_t len) {
    if (data == nullptr || len == 0) {
        return "";
    }

    std::string sanitized;
    sanitized.reserve(len); // Reserve at least this much

    for (size_t i = 0; i < len;) {
        unsigned char c = static_cast<unsigned char>(data[i]);

        if (c < 0x80) {
            // 1-byte sequence (ASCII)
            sanitized.push_back(c);
            i += 1;
        } else if (c >= 0xC2 && c <= 0xDF) {
            // 2-byte sequence
            if (i + 1 < len && (static_cast<unsigned char>(data[i + 1]) & 0xC0) == 0x80) {
                sanitized.push_back(c);
                sanitized.push_back(data[i + 1]);
                i += 2;
            } else {
                sanitized.append(UTF8_REPLACEMENT_CHAR, UTF8_REPLACEMENT_CHAR_LEN);
                i += 1;
            }
        } else if (c >= 0xE0 && c <= 0xEF) {
            // 3-byte sequence
            if (i + 2 < len &&
                (static_cast<unsigned char>(data[i + 1]) & 0xC0) == 0x80 &&
                (static_cast<unsigned char>(data[i + 2]) & 0xC0) == 0x80) {
                
                // Check for overlong encodings (e.g., U+0000)
                if (c == 0xE0 && static_cast<unsigned char>(data[i + 1]) < 0xA0) {
                    sanitized.append(UTF8_REPLACEMENT_CHAR, UTF8_REPLACEMENT_CHAR_LEN);
                    i += 1;
                // Check for UTF-16 surrogates (U+D800 to U+DFFF)
                } else if (c == 0xED && static_cast<unsigned char>(data[i + 1]) >= 0xA0) {
                    sanitized.append(UTF8_REPLACEMENT_CHAR, UTF8_REPLACEMENT_CHAR_LEN);
                    i += 1;
                } else {
                    sanitized.push_back(c);
                    sanitized.push_back(data[i + 1]);
                    sanitized.push_back(data[i + 2]);
                    i += 3;
                }
            } else {
                sanitized.append(UTF8_REPLACEMENT_CHAR, UTF8_REPLACEMENT_CHAR_LEN);
                i += 1;
            }
        } else if (c >= 0xF0 && c <= 0xF4) {
            // 4-byte sequence
            if (i + 3 < len &&
                (static_cast<unsigned char>(data[i + 1]) & 0xC0) == 0x80 &&
                (static_cast<unsigned char>(data[i + 2]) & 0xC0) == 0x80 &&
                (static_cast<unsigned char>(data[i + 3]) & 0xC0) == 0x80) {
                
                // Check for overlong encodings
                if (c == 0xF0 && static_cast<unsigned char>(data[i + 1]) < 0x90) {
                     sanitized.append(UTF8_REPLACEMENT_CHAR, UTF8_REPLACEMENT_CHAR_LEN);
                     i += 1;
                // Check for code points > U+10FFFF
                } else if (c == 0xF4 && static_cast<unsigned char>(data[i + 1]) >= 0x90) {
                     sanitized.append(UTF8_REPLACEMENT_CHAR, UTF8_REPLACEMENT_CHAR_LEN);
                     i += 1;
                } else {
                    sanitized.push_back(c);
                    sanitized.push_back(data[i + 1]);
                    sanitized.push_back(data[i + 2]);
                    sanitized.push_back(data[i + 3]);
                    i += 4;
                }
            } else {
                sanitized.append(UTF8_REPLACEMENT_CHAR, UTF8_REPLACEMENT_CHAR_LEN);
                i += 1;
            }
        } else {
            // Invalid starting byte (e.g., 0x80-0xC1, 0xF5-0xFF)
            sanitized.append(UTF8_REPLACEMENT_CHAR, UTF8_REPLACEMENT_CHAR_LEN);
            i += 1;
        }
    }
    return sanitized;
}


// --- Helper functions for serialization (unchanged) ---

inline void writeUint32BE(std::ostream& out, uint32_t value) {
    unsigned char buf[4];
    buf[0] = static_cast<unsigned char>((value >> 24) & 0xFF);
    buf[1] = static_cast<unsigned char>((value >> 16) & 0xFF);
    buf[2] = static_cast<unsigned char>((value >> 8) & 0xFF);
    buf[3] = static_cast<unsigned char>(value & 0xFF);
    out.write(reinterpret_cast<const char*>(buf), 4);
    if (!out) {
        throw std::ios_base::failure("MiniString::writeDataStream failed writing length");
    }
}

inline uint32_t readUint32BE(std::istream& in) {
    unsigned char buf[4];
    in.read(reinterpret_cast<char*>(buf), 4);
    if (!in) {
        throw std::ios_base::failure("MiniString::readDataStream failed reading length");
    }
    uint32_t value = (static_cast<uint32_t>(buf[0]) << 24) |
                     (static_cast<uint32_t>(buf[1]) << 16) |
                     (static_cast<uint32_t>(buf[2]) << 8)  |
                     (static_cast<uint32_t>(buf[3])      );
    return value;
}

} // anonymous namespace

namespace org {
namespace minima {
namespace objects {
namespace base {

MiniString::MiniString() : mString() {}

MiniString::MiniString(const std::string& zString)
    : mString(zString) {}  // Direct assignment, no sanitization

MiniString::MiniString(const std::vector<uint8_t>& zBytesData)
    : mString(std::string(
        reinterpret_cast<const char*>(zBytesData.data()),
        zBytesData.size())) {}  // Direct conversion

MiniString::MiniString(const MiniString& zString)
    : mString(zString.toString()) {}

MiniString::~MiniString() = default;

bool MiniString::isEqual(const std::string& zString) const {
    return mString == zString;
}

std::string MiniString::toString() const {
    return mString;
}

std::vector<uint8_t> MiniString::getData() const {
    const auto* dataPtr = reinterpret_cast<const unsigned char*>(mString.data());
    return std::vector<uint8_t>(dataPtr, dataPtr + mString.size());
}

void MiniString::writeDataStream(std::ostream& out) {
    // Create MiniData wrapper exactly like Java does
    MiniData strdata(getData());
    // Delegate serialization to MiniData
    strdata.writeDataStream(out);
}

void MiniString::readDataStream(std::istream& in) {
    MiniData strdata = MiniData::ReadFromStream(in);
    const std::vector<uint8_t>& bytes = strdata.getBytes();
    if (!bytes.empty()) {
        mString = std::string(
            reinterpret_cast<const char*>(bytes.data()),
            bytes.size()
        );  // Direct conversion without sanitization
    } else {
        mString.clear();
    }
}

MiniString MiniString::ReadFromStream(std::istream& in) {
    MiniString data;
    data.readDataStream(in);
    return data;
}

void MiniString::WriteToStream(std::ostream& out, const std::string& zString) {
    MiniString tmp(zString);
    tmp.writeDataStream(out);
}

} // namespace base
} // namespace objects
} // namespace minima
} // namespace org
