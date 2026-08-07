#ifndef ORG_MINIMA_OBJECTS_KEYS_WINTERNITZ_HPP
#define ORG_MINIMA_OBJECTS_KEYS_WINTERNITZ_HPP

#include <vector>
#include <array>
#include <cstdint>
#include "org/minima/objects/base/mini_data.hpp"

namespace org {
namespace minima {
namespace objects {
namespace keys {

class Winternitz {
private:
    using Hash256 = std::array<std::uint8_t, 32>;
    
    org::minima::objects::base::MiniData mPrivateSeed;
    org::minima::objects::base::MiniData mPublicKey;
    
    // Store private chains (optional, for performance)
    std::vector<Hash256> mPrivateChains;

public:
    /**
     * Default constructor
     */
    Winternitz();
    
    /**
     * Create Winternitz signature scheme from private seed
     * @param zPrivateSeed The private seed (32 bytes)
     */
    Winternitz(const org::minima::objects::base::MiniData& zPrivateSeed);
    
    /**
     * Get the public key
     * @return The public key (32 bytes)
     */
    org::minima::objects::base::MiniData getPublicKey() const;
    
    /**
     * Sign data
     * @param zData The data to sign
     * @return The signature
     */
    org::minima::objects::base::MiniData sign(const org::minima::objects::base::MiniData& zData) const;
    
    /**
     * Verify a signature (static method)
     * @param zPublicKey The public key
     * @param zData The data that was signed
     * @param zSignature The signature
     * @return true if signature is valid, false otherwise
     */
    static bool verify(const org::minima::objects::base::MiniData& zPublicKey,
                      const org::minima::objects::base::MiniData& zData,
                      const org::minima::objects::base::MiniData& zSignature);
};

} // namespace keys
} // namespace objects
} // namespace minima
} // namespace org

#endif // ORG_MINIMA_OBJECTS_KEYS_WINTERNITZ_HPP