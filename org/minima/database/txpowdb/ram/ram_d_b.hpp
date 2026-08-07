#pragma once

#include <unordered_map>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <shared_mutex>

// Namespaced Forward declarations for project classes (Rule 2 & 4)
namespace org { namespace minima { namespace objects { class TxPoW; } } }
namespace org { namespace minima { namespace objects { namespace base { class MiniData; } } } }
namespace org { namespace minima { namespace objects { class CoinProof; } } }

//
// ### FIX 1 ###
// Removed the include for ram_data.hpp.
//

// Java Package to C++ Namespace Mapping for RamDB: org.minima.database.txpowdb.ram
namespace org { namespace minima { namespace database { namespace txpowdb { namespace ram {

//
// ### FIX 2 ###
// Added a forward declaration for RamData instead.
//
class RamData;

/**
 * RamDB - in-memory pool of TxPoW with aging and mempool utilities.
 * Mirrors org.minima.database.txpowdb.ram.RamDB
 */
class RamDB {
public:
    // How long does data remain in RAM DB in milliseconds
    std::int64_t MAX_TIME;

    RamDB();
    ~RamDB() = default;

    bool addTxPoW(const std::shared_ptr<org::minima::objects::TxPoW>& zTxPoW);

    // This now correctly uses the forward-declared RamData
    std::unordered_map<std::string, std::shared_ptr<RamData>> getCompleteMemPool() const;

    bool exists(const std::string& zTxPoWID) const;

    std::shared_ptr<org::minima::objects::TxPoW> getTxPoW(const std::string& zTxPoWID);

    void remove(const std::string& zTxPoWID);

    void cleanDB();

    int getSize() const;

    void wipeRamDB();

    // MEMPOOL specific functions
    void clearMainChainTxns();
    void setOnMainChain(const std::string& zTxPoWID);
    
    std::vector<std::shared_ptr<org::minima::objects::TxPoW>> getAllUnusedTxns() const;
    void setInCascade(const std::string& zTxPoWID);

    bool checkForCoinID(const org::minima::objects::base::MiniData& zCoinID) const;

private:
    static std::int64_t currentTimeMillis();

private:
    mutable std::shared_mutex mMutex;
    
    // This now correctly uses the forward-declared RamData
    std::unordered_map<std::string, std::shared_ptr<RamData>> mTxPoWDB;
};

} } } } } // end namespace org::minima::database::txpowdb::ram