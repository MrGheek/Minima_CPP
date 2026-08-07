#include "org/minima/database/txpowdb/ram/ram_d_b.hpp"
#include "org/minima/database/txpowdb/ram/ram_data.hpp"

#include <chrono>
#include <type_traits>
#include <mutex>

// Full project headers for used types
#include "org/minima/objects/tx_po_w.hpp"
#include "org/minima/objects/coin_proof.hpp"
#include "org/minima/objects/base/mini_data.hpp"
#include "org/minima/system/params/general_params.hpp"
#include "org/minima/objects/coin.hpp" // For Coin definition
#include "org/minima/objects/witness.hpp" // For Witness definition


static inline std::int64_t now_ms_internal() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

namespace org { namespace minima { namespace database { namespace txpowdb { namespace ram {

//
// FULL implementation of RamData
//
// class RamData {
// public:
//     RamData(std::shared_ptr<org::minima::objects::TxPoW> zTxPoW)
//         : mTxPoW(std::move(zTxPoW)),
//           mLastAccess(now_ms_internal()),
//           mIsOnMainChain(false),
//           mIsInCascade(false) {}

//     std::shared_ptr<org::minima::objects::TxPoW> getTxPoW() const {
//         return mTxPoW;
//     }

//     void updateLastAccess() {
//         mLastAccess = now_ms_internal();
//     }

//     std::int64_t getLastAccess() const {
//         return mLastAccess;
//     }

//     void setOnMainChain(bool zOnChain) {
//         mIsOnMainChain = zOnChain;
//     }

//     bool isOnMainChain() const {
//         return mIsOnMainChain;
//     }

//     void setInCascade(bool zCascader) {
//         mIsInCascade = zCascader;
//     }

//     bool isInCascade() const {
//         return mIsInCascade;
//     }

// private:
//     std::shared_ptr<org::minima::objects::TxPoW> mTxPoW;
//     std::int64_t mLastAccess;
//     bool mIsOnMainChain;
//     bool mIsInCascade;
// };


/*
 * RamDB implementation
 */
std::int64_t RamDB::currentTimeMillis() {
    return now_ms_internal();
}

RamDB::RamDB()
    : MAX_TIME(1000LL * 60 * 60 * org::minima::system::params::GeneralParams::NUMBER_HOURS_RAMTXPOWDB) {
}

bool RamDB::addTxPoW(const std::shared_ptr<org::minima::objects::TxPoW>& zTxPoW) {
    if (!zTxPoW) {
        return false;
    }

    const std::string txpid = zTxPoW->getTxPoWID();

    std::unique_lock<std::shared_mutex> lock(mMutex);
    auto it = mTxPoWDB.find(txpid);
    if (it != mTxPoWDB.end()) {
        if (it->second) {
            it->second->updateLastAccess(); 
        }
        return false;
    } else {
        mTxPoWDB.emplace(txpid, std::make_shared<RamData>(zTxPoW)); 
    }

    return true;
}

std::unordered_map<std::string, std::shared_ptr<RamData>> RamDB::getCompleteMemPool() const {
    std::shared_lock<std::shared_mutex> lock(mMutex);
    return mTxPoWDB; 
}

bool RamDB::exists(const std::string& zTxPoWID) const {
    std::shared_lock<std::shared_mutex> lock(mMutex);
    return mTxPoWDB.find(zTxPoWID) != mTxPoWDB.end();
}

std::shared_ptr<org::minima::objects::TxPoW> RamDB::getTxPoW(const std::string& zTxPoWID) {
    std::unique_lock<std::shared_mutex> lock(mMutex);
    auto it = mTxPoWDB.find(zTxPoWID);
    if (it != mTxPoWDB.end() && it->second) {
        it->second->updateLastAccess(); 
        return it->second->getTxPoW();  
    }
    return nullptr;
}

void RamDB::remove(const std::string& zTxPoWID) {
    std::unique_lock<std::shared_mutex> lock(mMutex);
    mTxPoWDB.erase(zTxPoWID);
}

void RamDB::cleanDB() {
    const std::int64_t timecut = currentTimeMillis() - MAX_TIME;

    std::unordered_map<std::string, std::shared_ptr<RamData>> newmap;
    {
        std::unique_lock<std::shared_mutex> lock(mMutex);
        newmap.reserve(mTxPoWDB.size());

        for (auto& kv : mTxPoWDB) {
            const auto& ram = kv.second;
            if (!ram) {
                continue;
            }

            if (ram->getLastAccess() > timecut) { 
                auto txp = ram->getTxPoW(); 
                if (txp) {
                    newmap.emplace(txp->getTxPoWID(), ram);
                }
            }
        }
        mTxPoWDB.swap(newmap);
    }
}

int RamDB::getSize() const {
    std::shared_lock<std::shared_mutex> lock(mMutex);
    return static_cast<int>(mTxPoWDB.size());
}

void RamDB::wipeRamDB() {
    std::unique_lock<std::shared_mutex> lock(mMutex);
    mTxPoWDB.clear();
}

void RamDB::clearMainChainTxns() {
    std::unique_lock<std::shared_mutex> lock(mMutex);
    for (auto& kv : mTxPoWDB) {
        if (kv.second) {
            kv.second->setOnMainChain(false); 
        }
    }
}

void RamDB::setOnMainChain(const std::string& zTxPoWID) {
    std::unique_lock<std::shared_mutex> lock(mMutex);
    auto it = mTxPoWDB.find(zTxPoWID);
    if (it != mTxPoWDB.end() && it->second) {
        it->second->setOnMainChain(true); 
    }
}

std::vector<std::shared_ptr<org::minima::objects::TxPoW>> RamDB::getAllUnusedTxns() const {
    std::vector<std::shared_ptr<org::minima::objects::TxPoW>> ret;
    std::shared_lock<std::shared_mutex> lock(mMutex);
    ret.reserve(mTxPoWDB.size());

    for (const auto& kv : mTxPoWDB) {
        const auto& ram = kv.second;
        if (!ram) {
            continue;
        }
        const bool onMain = ram->isOnMainChain(); 
        const bool inCascade = ram->isInCascade(); 
        auto txp = ram->getTxPoW(); 
        if (txp && !onMain && txp->isTransaction() && !inCascade) {
            ret.push_back(txp);
        }
    }

    return ret;
}

void RamDB::setInCascade(const std::string& zTxPoWID) {
    std::unique_lock<std::shared_mutex> lock(mMutex);
    auto it = mTxPoWDB.find(zTxPoWID);
    if (it != mTxPoWDB.end() && it->second) {
        it->second->setInCascade(true); 
    }
}

// Helper to normalize container element to CoinProof reference
static const org::minima::objects::CoinProof& GetCoinProofRef(const org::minima::objects::CoinProof& cp) {
    return cp;
}
static const org::minima::objects::CoinProof& GetCoinProofRef(const std::shared_ptr<org::minima::objects::CoinProof>& cp) {
    return *cp;
}
static const org::minima::objects::CoinProof& GetCoinProofRef(const std::unique_ptr<org::minima::objects::CoinProof>& cp) {
    return *cp;
}
static const org::minima::objects::CoinProof& GetCoinProofRef(const org::minima::objects::CoinProof* cp) {
    return *cp;
}

bool RamDB::checkForCoinID(const org::minima::objects::base::MiniData& zCoinID) const {
    std::shared_lock<std::shared_mutex> lock(mMutex);

    for (const auto& kv : mTxPoWDB) {
        const auto& ram = kv.second;
        if (!ram) {
            continue;
        }

        auto txp = ram->getTxPoW(); 
        if (!txp) {
            continue;
        }

        if (txp->isTransaction() && !ram->isInCascade()) { 
            // Normal inputs
            {
                //
                // ### FIX 1 ###
                // Changed 'auto' to 'const auto&' to avoid copying the vector.
                //
                const auto& proofs = txp->getWitness().getAllCoinProofs(); 
                for (const auto& anycp : proofs) {
                    const org::minima::objects::CoinProof& cp = GetCoinProofRef(anycp);
                    const auto& coin = cp.getCoin(); 
                    if (coin.getCoinID().isEqual(zCoinID)) {
                        return true;
                    }
                }
            }

            // Burn inputs
            {
                //
                // ### FIX 2 ###
                // Changed 'auto' to 'const auto&' here as well.
                //
                const auto& proofs = txp->getBurnWitness().getAllCoinProofs();
                for (const auto& anycp : proofs) {
                    const org::minima::objects::CoinProof& cp = GetCoinProofRef(anycp);
                    const auto& coin = cp.getCoin();
                    if (coin.getCoinID().isEqual(zCoinID)) {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

} } } } } // end namespace org::minima::database::txpowdb::ram