/**
 * stubs.cpp - Minimal stub implementations for symbols needed by test_serialization
 * but not actually called during the test.
 */
#include <string>
#include <exception>

namespace org { namespace minima { namespace utils {
class MiniFormat {
public:
    static std::string formatSize(long long v);
};

class MinimaLogger {
public:
    static void log(const std::string& msg);
    static void log(const std::exception& e);
};

// Out-of-line definitions
std::string MiniFormat::formatSize(long long v) {
    return std::to_string(v) + " bytes";
}
void MinimaLogger::log(const std::string&) {}
void MinimaLogger::log(const std::exception&) {}

// Force these symbols to exist by referencing them
}}}  // namespace org::minima::utils

// Force instantiation
void __force_stubs() {
    org::minima::utils::MiniFormat::formatSize(0);
    org::minima::utils::MinimaLogger::log(std::string());
    org::minima::utils::MinimaLogger::log(std::exception());
}
