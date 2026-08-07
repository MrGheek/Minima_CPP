#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <cstdint>

#include "org/minima/utils/sql_d_b.hpp"

//
// ### FIX 1 ###
// Added include for the full MiniNumber definition
//
#include "org/minima/objects/base/mini_number.hpp"

// Forward declarations
struct sqlite3;
struct sqlite3_stmt;

namespace org { namespace minima { namespace objects {
class TxPoW;
} } }

// Forward declaration for MiniData is likely needed if MiniNumber wasn't included before
namespace org { namespace minima { namespace objects { namespace base {
// class MiniNumber; // No longer needed
class MiniData;
} } } }


namespace org {
namespace minima {
namespace database {
namespace txpowdb {
namespace sql {

class TxPoWSqlDB : public org::minima::utils::SqlDB {
public:
    // Static config
    static std::int64_t MAX_SQL_MILLI;
    // This declaration will now work
    static org::minima::objects::base::MiniNumber MAX_RELEVANT_TXPOW;

    static bool LOG_ADD_BLOCKS;
    static bool LOG_ADD_TRANSACTION;

public:
    TxPoWSqlDB();
    virtual ~TxPoWSqlDB();

    // Non-copyable
    TxPoWSqlDB(const TxPoWSqlDB&) = delete;
    TxPoWSqlDB& operator=(const TxPoWSqlDB&) = delete;

    // SQL schema creation (called by base)
protected:
    void createSQL() override;

public:
    // Wipe and recreate DB schema
    void wipeDB();

    // Custom size query with sanitized WHERE clause
    int customSizeQuery(const std::string& zWhereCondition);

    // Add / Get / Exists
    bool addTxPoW(const org::minima::objects::TxPoW& zTxPoW, bool zIsRelevant);
    std::unique_ptr<org::minima::objects::TxPoW> getTxPoW(const std::string& zTxPoWID);
    bool exists(const std::string& zTxPoWID);

    // Children of a parent block
    std::vector<std::string> getChildBlocks(const std::string& zParentTxPoWID);

    // Sizes and retrieval
    int getRelevantSize();
    std::vector<std::unique_ptr<org::minima::objects::TxPoW>> getAllRelevant(int zLimit);
    std::vector<std::unique_ptr<org::minima::objects::TxPoW>> getAllRelevant(int zLimit, int zOffset);

    std::vector<std::unique_ptr<org::minima::objects::TxPoW>> getLatestTxPoW(int zLimit, int zOffset);
    int getLatestTxPoWSize(std::int64_t zMinMilliTime);

    int getSize();

    // Cleanup old entries, returns number deleted
    int cleanDB();
    int cleanDB(bool zHard);

    // Close and reopen DB to clean connection
    void closeAndReopen();

private:
    // SQLite connection for this class (separate from base)
    sqlite3* mConn;

    // Prepared statements
    sqlite3_stmt* mStmtInsert;
    sqlite3_stmt* mStmtSelectByID;
    sqlite3_stmt* mStmtSelectChildren;
    sqlite3_stmt* mStmtTotalTxpow;
    sqlite3_stmt* mStmtDeleteOldNotRelevant;
    sqlite3_stmt* mStmtExists;

    sqlite3_stmt* mStmtSelectRelevant;
    sqlite3_stmt* mStmtSelectRelevantSize;
    sqlite3_stmt* mStmtSelectTopTxpow;
    sqlite3_stmt* mStmtSelectTopTxpowSize;

    // Synchronization
    std::mutex mLocalMutex;

private:
    // Helpers
    void openConnectionIfNeeded();
    void prepareStatements();
    void finalizeStatements();
    void closeConnection();
    void execSQL(const std::string& sql);

    static std::int64_t currentTimeMillis();

    static std::string sanitizeWhere(const std::string& where);
};

} // namespace sql
} // namespace txpowdb
} // namespace database
} // namespace minima
} // namespace org