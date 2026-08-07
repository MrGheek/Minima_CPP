#pragma once

#include <memory>
#include <string>
#include <filesystem>
#include <ostream>
#include <istream>
#include <vector>

#include "org/minima/utils/streamable.hpp"
#include "org/minima/objects/base/mini_number.hpp"
#include "org/minima/objects/base/mini_data.hpp"

// Forward declarations
namespace org { namespace minima { namespace objects { class TxPoW; } } }
namespace org { namespace minima { namespace database { namespace cascade { class CascadeNode; } } } }

namespace org {
namespace minima {
namespace database {
namespace cascade {

class Cascade : public org::minima::utils::Streamable {
public:
    Cascade();
    virtual ~Cascade(); // must be defined in .cpp due to unique_ptr<CascadeNode> member

    // Non-copyable, movable (explicitly declared per Pitfall 1)
    Cascade(const Cascade&) = delete;
    Cascade& operator=(const Cascade&) = delete;
    Cascade(Cascade&&) noexcept;
    Cascade& operator=(Cascade&&) noexcept;

    // Mutators
    void addToTip(const org::minima::objects::TxPoW& zTxPoW);
    void cascadeChain();

    // Accessors
    CascadeNode* getTip() const;
    org::minima::objects::base::MiniNumber getTotalWeight() const;
    int getLength() const;

    // Utilities
    std::unique_ptr<Cascade> deepCopy() const;
    std::string printCascade() const;

    // Persistence
    void loadDB(const std::filesystem::path& zFile);
    void saveDB(const std::filesystem::path& zFile);

    // Streamable
    void writeDataStream(std::ostream& out) override;
    void readDataStream(std::istream& in) override;

    // Static helpers
    static std::unique_ptr<Cascade> convertMiniDataVersion(const org::minima::objects::base::MiniData& zCascData);
    static Cascade ReadFromStream(std::istream& in);

    static bool checkCascadeCorrect(const Cascade& zCascade);
    static bool checkPastNodeExists(CascadeNode* zCascadeNode, const std::string& zTxPoWID);

private:
    // Own all nodes; parent links inside CascadeNode are raw pointers to nodes in this pool
    std::vector<std::unique_ptr<CascadeNode>> mNodes;
    CascadeNode* mTip {nullptr}; // non-owning raw pointer to the tip
    org::minima::objects::base::MiniNumber mTotalWeight; // exact BigDecimal-style total weight
    bool hasBlock(const std::string& zTxPoWID) const;
};

} // namespace cascade
} // namespace database
} // namespace minima
} // namespace org