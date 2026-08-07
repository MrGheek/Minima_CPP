#include "org/minima/database/cascade/cascade.hpp"

#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <set>

#include "org/minima/database/cascade/cascade_node.hpp"
#include "org/minima/objects/tx_po_w.hpp"
#include "org/minima/system/params/global_params.hpp"
#include "org/minima/utils/mini_file.hpp"
#include "org/minima/utils/minima_logger.hpp"
#include "org/minima/objects/base/mini_number.hpp"
#include "org/minima/objects/base/mini_data.hpp"

namespace org {
namespace minima {
namespace database {
namespace cascade {

using org::minima::utils::MinimaLogger;

Cascade::Cascade() = default;
Cascade::~Cascade() = default;
Cascade::Cascade(Cascade&&) noexcept = default;
Cascade& Cascade::operator=(Cascade&&) noexcept = default;

void Cascade::addToTip(const org::minima::objects::TxPoW& zTxPoW) {
    // MinimaLogger::log("DEBUG Cascade::addToTip: Received TxPoW for block " + 
    //                   zTxPoW.getBlockNumber().toString() + 
    //                   " TxPoWID=" + zTxPoW.getTxPoWID() + 
    //                   " SuperLevel=" + std::to_string(zTxPoW.getSuperLevel()));
    
    // Log all super parents before creating node
    // MinimaLogger::log("DEBUG Cascade::addToTip: TxPoW super parents:");
    // for (int i = 0; i < org::minima::system::params::GlobalParams::MINIMA_CASCADE_LEVELS; i++) {
    //     MinimaLogger::log("  Level " + std::to_string(i) + ": " + zTxPoW.getSuperParent(i).to0xString());
    // }

    // New Node - CascadeNode deep copies TxPoW internals and clears body per Java
    auto node = std::make_unique<CascadeNode>(zTxPoW);
    

    if (mTip != nullptr) {
        // Set as child to the old tip (new tip's parent is old tip)
        node->setParent(mTip);
    }

    // Own and set the new tip
    mTip = node.get();
    mNodes.push_back(std::move(node));

}

CascadeNode* Cascade::getTip() const {
    return mTip;
}

org::minima::objects::base::MiniNumber Cascade::getTotalWeight() const {
    return mTotalWeight;
}

int Cascade::getLength() const {
    int length = 0;
    CascadeNode* current = mTip;
    while (current != nullptr) {
        ++length;
        current = current->getParent();
    }
    return length;
}

void Cascade::cascadeChain() {
    // check not empty
    if (!getTip()) {
        return;
    }

    // Start at the tip and work back..
    CascadeNode* newcascade = mTip;
    CascadeNode* current    = (mTip ? mTip->getParent() : nullptr);

    // Keep a score of the total weight using MiniNumber for precision [cite: 26]
    // Java uses BigDecimal here. std::stod was causing the fork.
    org::minima::objects::base::MiniNumber totalWeightCalc(newcascade->getCurrentWeight());

    int casclevel = 0;
    int totlevel  = 1;

    // Track which nodes are kept in the new chain to handle memory/vector cleanup later
    std::set<CascadeNode*> keptNodes;
    keptNodes.insert(newcascade);

    while (current != nullptr) {
        // What super level is this node
        int superlev = current->getSuperLevel();

        // Are we above the minimum power
        if (superlev >= casclevel) {
            // Set the current level
            current->setLevel(casclevel);

            // Add to the new..
            newcascade->setParent(current);

            // New root
            newcascade = current;
            keptNodes.insert(current);

            // Add to the total Weight using MiniNumber math
            totalWeightCalc = totalWeightCalc.add(org::minima::objects::base::MiniNumber(newcascade->getCurrentWeight()));

            // Increase node count at this level
            totlevel++;
            if (totlevel >= org::minima::system::params::GlobalParams::MINIMA_CASCADE_LEVEL_NODES) {
                if (casclevel < org::minima::system::params::GlobalParams::MINIMA_CASCADE_LEVELS - 1) {
                    casclevel++;
                    totlevel = 0;
                }
            }
        }

        // Get the parent
        current = current->getParent();
    }

    // New cascade has no parent - it's the root..
    if (newcascade) {
        newcascade->setParent(nullptr);
    }
    
    // Keep total weight as exact MiniNumber to match Java BigDecimal semantics.
    mTotalWeight = totalWeightCalc;

    // --- MANUAL GARBAGE COLLECTION (Critical for C++ Port) ---
    // Java GC handles this automatically. In C++, we must remove nodes from mNodes
    // that are no longer part of the linked list, otherwise the vector grows forever.
    std::vector<std::unique_ptr<CascadeNode>> validNodes;
    validNodes.reserve(keptNodes.size());

    for (auto& nodePtr : mNodes) {
        if (keptNodes.count(nodePtr.get()) > 0) {
            validNodes.push_back(std::move(nodePtr));
        }
    }
    mNodes = std::move(validNodes);
}

std::unique_ptr<Cascade> Cascade::deepCopy() const {
    // Serialize to memory
    std::ostringstream baos(std::ios::binary);
    const_cast<Cascade*>(this)->writeDataStream(baos);
    const std::string bytes = baos.str();

    // Read into a new object
    std::istringstream bais(bytes, std::ios::binary);
    auto deepcopy = std::make_unique<Cascade>();
    deepcopy->readDataStream(bais);
    return deepcopy;
}

std::string Cascade::printCascade() const {
    std::string casstr;

    // Flip it..
    std::vector<CascadeNode*> nodes;
    CascadeNode* current = mTip;
    while (current != nullptr) {
        nodes.insert(nodes.begin(), current);
        current = current->getParent();
    }

    // Print all nodes
    for (const auto* node : nodes) {
        casstr += node->toString();
        casstr += "\n";
    }

    return casstr;
}

void Cascade::loadDB(const std::filesystem::path& zFile) {
    org::minima::utils::MiniFile::loadObjectSlow(zFile, *this);
}

void Cascade::saveDB(const std::filesystem::path& zFile) {
    org::minima::utils::MiniFile::saveObjectDirect(zFile, *this);
}

void Cascade::writeDataStream(std::ostream& out) {
    // How many nodes in this Cascade
    int len = 0;
    CascadeNode* current = mTip;
    while (current != nullptr) {
        ++len;
        current = current->getParent();
    }

    // Now Write this out..
    org::minima::objects::base::MiniNumber::WriteToStream(out, len);

    // And write them all out..
    current = mTip;
    int written = 0;
    while (current != nullptr) {
        current->writeDataStream(out);
        written++;
        current = current->getParent();
    }
}

void Cascade::readDataStream(std::istream& in) {
    // How many nodes..
    int len = org::minima::objects::base::MiniNumber::ReadFromStream(in).getAsInt();
    
    org::minima::utils::MinimaLogger::log("Cascade: Loading " + std::to_string(len) + " nodes from database");
    
    // Load them all..
    mNodes.clear();
    mTip = nullptr;
    mTotalWeight = org::minima::objects::base::MiniNumber::ZERO();

    mNodes.reserve(len);
    
    CascadeNode* current = nullptr;
    int successful = 0;
    int failed = 0;
    
    for (int i = 0; i < len; i++) {
        try {
            auto node = CascadeNode::ReadFromStream(in);
            
            if (!node) {
                org::minima::utils::MinimaLogger::log(
                    "ERROR Cascade: Node " + std::to_string(i) + " returned null, skipping");
                failed++;
                continue;
            }
            
            // VALIDATION: Check TxPoWID
            auto& txpow = node->getTxPoW();
            if (txpow.getTxPoWID().empty()) {
                org::minima::utils::MinimaLogger::log(
                    "ERROR Cascade: Node " + std::to_string(i) + " has empty TxPoWID, skipping");
                failed++;
                continue;
            }
            
            // VALIDATION: Try to access block number
            try {
                auto blockNum = txpow.getBlockNumber();
            } catch (const std::exception& e) {
                org::minima::utils::MinimaLogger::log(
                    "ERROR Cascade: Node " + std::to_string(i) + 
                    " TxHeader access failed: " + std::string(e.what()) + ", skipping");
                failed++;
                continue;
            }
            
            // Move into vector FIRST, then get stable pointer
            mNodes.push_back(std::move(node));

            // Get pointer from vector (safe due to reserve())
            CascadeNode* nodePtr = mNodes.back().get();

            // Stitch the chain
            if (current != nullptr) {
                current->setParent(nodePtr);
            } else {
                mTip = nodePtr;  // First node becomes the tip
            }

            current = nodePtr;
            successful++;
            
        } catch (const std::exception& e) {
            failed++;
            org::minima::utils::MinimaLogger::log(
                "ERROR Cascade: Failed to load node " + std::to_string(i) + 
                ": " + std::string(e.what()));
            
            // Stop if too many failures
            if (failed > 5) {
                org::minima::utils::MinimaLogger::log(
                    "ERROR Cascade: Too many consecutive failures (" + 
                    std::to_string(failed) + "), stopping cascade load");
                break;
            }
            
            continue;
        }
    }
    
    org::minima::utils::MinimaLogger::log(
        "Cascade: Loaded " + std::to_string(successful) + " nodes successfully, " + 
        std::to_string(failed) + " failed");
    
    // And calculate weights..
    if (mTip) {
        cascadeChain();  // ← This will now clean up any stale nodes
    } else {
        org::minima::utils::MinimaLogger::log("WARNING Cascade: No valid tip node after loading");
    }
}


std::unique_ptr<Cascade> Cascade::convertMiniDataVersion(
    const org::minima::objects::base::MiniData& zCascData) {
    const std::vector<std::uint8_t>& bytes = zCascData.getBytes();
    std::string data(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    std::istringstream dis(data, std::ios::binary);

    std::unique_ptr<Cascade> cascade;

    try {
        cascade = std::make_unique<Cascade>();
        cascade->readDataStream(dis);
    } catch (const std::exception& e) {
        org::minima::utils::MinimaLogger::log(e);
    }

    return cascade;
}

Cascade Cascade::ReadFromStream(std::istream& in) {
    Cascade cascade;
    cascade.readDataStream(in);
    return cascade;
}

bool Cascade::checkCascadeCorrect(const Cascade& zCascade) {
    // Start at the top..
    CascadeNode* cnode = zCascade.getTip();

    // Make sure starts at 0
    if (cnode != nullptr) {
        if (cnode->getLevel() != 0) {
            org::minima::utils::MinimaLogger::log(
                std::string("Cascade does not start at level 0.. ") + std::to_string(cnode->getLevel()));
            return false;
        }
    }

    // Which node at the current level
    int counter  = 0;
    int oldlevel = 0;
    while (cnode != nullptr) {
        // Get the txpow..
        org::minima::objects::TxPoW& txp = cnode->getTxPoW();

        // What level is this..
        int clevel = cnode->getLevel();

        // Have we switched to a new Level
        if (clevel != oldlevel) {
            // The new level MUST be 1 more than the old level..
            if (clevel != oldlevel + 1) {
                org::minima::utils::MinimaLogger::log(
                    "NEXT level up is not a single increment @ clevel:" + std::to_string(clevel) +
                    " oldlevel:" + std::to_string(oldlevel));
                return false;
            }

            // reset counter for this level
            counter = 0;

            // Remember..
            oldlevel = clevel;
        }

        // Is this the last node at this super level..
        CascadeNode* pnode = cnode->getParent();
        bool lastnode = false;
        if (pnode == nullptr) {
            lastnode = true;
        } else {
            lastnode = (pnode->getLevel() != clevel);
        }

        // Now check that all the parents are in the cascade..
        bool foundzero = false;
        for (int i = clevel; i < org::minima::system::params::GlobalParams::MINIMA_CASCADE_LEVELS; ++i) {
            // Get the super parent..
            std::string sparent = txp.getSuperParent(i).to0xString();

            // Is it 0x00.. means there was not a node at this super level when the block was made
            if (sparent == "0x00") {
                foundzero = true;
            } else {
                if (foundzero) {
                    // Should ALL be zero..
                    org::minima::utils::MinimaLogger::log(
                        "NON zero node found in cascade after first zero node.." + sparent +
                        " @ slevel " + std::to_string(i) + "/" + std::to_string(clevel) +
                        " counter:" + std::to_string(counter));
                    return false;
                }

                // Check we have it..
                if (lastnode) {
                    if (i > clevel) {
                        if (!checkPastNodeExists(cnode, sparent)) {
                            org::minima::utils::MinimaLogger::log(
                                "Parent not found in cascade.. " + sparent + " @ slevel " +
                                std::to_string(i) + "/" + std::to_string(clevel) +
                                " counter:" + std::to_string(counter));
                            return false;
                        }
                    }
                } else {
                    if (!checkPastNodeExists(cnode, sparent)) {
                        org::minima::utils::MinimaLogger::log(
                            "Parent not found in cascade.. " + sparent + " @ slevel " +
                            std::to_string(i) + "/" + std::to_string(clevel) +
                            " counter:" + std::to_string(counter));
                        return false;
                    }
                }
            }
        }

        // And jump to the parent..
        cnode = cnode->getParent();
        counter++;
    }

    return true;
}

bool Cascade::checkPastNodeExists(CascadeNode* zCascadeNode, const std::string& zTxPoWID) {
    CascadeNode* cnode = zCascadeNode;
    while (cnode != nullptr) {
        if (cnode->getTxPoW().getTxPoWID() == zTxPoWID) {
            return true;
        }
        cnode = cnode->getParent();
    }
    return false;
}

bool Cascade::hasBlock(const std::string& zTxPoWID) const {
    CascadeNode* current = mTip;
    while (current != nullptr) {
        if (current->getTxPoW().getTxPoWID() == zTxPoWID) {
            return true;
        }
        current = current->getParent();
    }
    return false;
}

} // namespace cascade
} // namespace database
} // namespace minima
} // namespace org