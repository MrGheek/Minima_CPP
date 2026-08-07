#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace org { namespace minima { namespace objects { namespace base { class MiniData; } } } }
namespace org { namespace minima { namespace utils { class Streamable; } } }

namespace org {
namespace minima {
namespace utils {

class Crypto {
public:
    // Public static constants analogous to Java fields
    static const std::string& MAX_VAL_HEX();
    static const std::string& MAX_VALDEC();
    static const org::minima::objects::base::MiniData& MAX_HASH();

    // Singleton access
    static Crypto& getInstance();

    Crypto() = default;
    Crypto(const Crypto&) = delete;
    Crypto& operator=(const Crypto&) = delete;

    // Hash functions
    std::vector<std::uint8_t> hashSHA2(const std::vector<std::uint8_t>& zData);
    std::vector<std::uint8_t> hashData(const std::vector<std::uint8_t>& zData); // SHA3-256 default

    // Object hashing (non-const due to Streamable::writeDataStream non-const)
    org::minima::objects::base::MiniData hashObject(org::minima::utils::Streamable& zObject);
    org::minima::objects::base::MiniData hashObjects(org::minima::utils::Streamable& zLeftObject,
                                                     org::minima::utils::Streamable& zRightObject2);

    // Varargs analogs (non-const pointers due to non-const writeDataStream)
    org::minima::objects::base::MiniData hashAllObjects(const std::vector<org::minima::utils::Streamable*>& zObjects);
    org::minima::objects::base::MiniData hashAllObjects(std::initializer_list<org::minima::utils::Streamable*> zObjects);
};

} // namespace utils
} // namespace minima
} // namespace org