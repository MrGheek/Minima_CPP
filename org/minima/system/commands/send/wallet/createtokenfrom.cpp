#include "org/minima/system/commands/send/wallet/createtokenfrom.hpp"

#include <stdexcept>
#include <sstream>

#include "org/minima/database/minima_d_b.hpp"
#include "org/minima/database/userprefs/txndb/txn_d_b.hpp"
#include "org/minima/database/userprefs/txndb/txn_row.hpp"
#include "org/minima/objects/coin.hpp"
#include "org/minima/objects/token.hpp"
#include "org/minima/objects/transaction.hpp"
#include "org/minima/objects/base/mini_data.hpp"
#include "org/minima/objects/base/mini_number.hpp"
#include "org/minima/objects/base/mini_string.hpp"
#include "org/minima/system/commands/command_exception.hpp"
#include "org/minima/system/commands/command_runner.hpp"
#include "org/minima/utils/json/j_s_o_n_object.hpp"
#include "org/minima/utils/json/j_s_o_n_array.hpp"

namespace org {
namespace minima {
namespace system {
namespace commands {
namespace send {
namespace wallet {

using org::minima::database::MinimaDB;
using org::minima::database::userprefs::txndb::TxnDB;
using org::minima::database::userprefs::txndb::TxnRow;
using org::minima::objects::Coin;
using org::minima::objects::Token;
using org::minima::objects::Transaction;
using org::minima::objects::base::MiniData;
using org::minima::objects::base::MiniNumber;
using org::minima::objects::base::MiniString;
using org::minima::utils::json::JSONObject;

createtokenfrom::createtokenfrom()
    : org::minima::system::commands::Command(
          "createtokenfrom",
          "[fromaddress:] [script:] [privatekey:] [keyuses:] [name:] [amount:] (decimals:) (mine:) - Create Tokens from a certain address") {
}

std::vector<std::string> createtokenfrom::getValidParams() const {
    return {"fromaddress","script","privatekey","keyuses","name","amount","decimals","mine"};
}

std::string createtokenfrom::getFullHelp() const {
    return std::string("\ncreatetokenfrom\n")
        + "\n"
        + "Create (mint) custom tokens or NFTs using a specific address in your wallet.\n"
        + "\n"
        + "fromaddress:\n"
        + "    The address that will send the Minima needed to colour the new token.\n"
        + "\n"
        + "script:\n"
        + "    Add a custom script that must return 'TRUE' when spending any coin of this token.\n"
        + "    Both the token script and coin script must return 'TRUE' for a coin to be sendable.\n"
        + "\n"
        + "privatekey:\n"
        + "    The private key of the fromaddress used to sign the transaction.\n"
        + "\n"
        + "keyuses:\n"
        + "    The number of uses for the private key.\n"
        + "\n"
        + "name:\n"
        + "    The name of the token. Can be a string or JSON Object.\n"
        + "\n"
        + "amount:\n"
        + "    The amount of total supply to create for the token. Between 1 and 1 Trillion.\n"
        + "\n"
        + "decimals: (optional)\n"
        + "    The number of decimal places for the token. Default is 8, maximum 16.\n"
        + "    To create NFTs, use 0.\n"
        + "\n"
        + "mine: (optional)\n"
        + "    Mine the TxPoW synchronously. Default is true.\n"
        + "\n"
        + "Examples:\n"
        + "\n"
        + "createtokenfrom fromaddress:0x6A3A060CE9D8E876E9B12DBE5D8F6A6864183BA1A63EA8CBCC14D668B5BECACF script:RETURN TRUE privatekey:0xF5C44E0F9FE6ECCC0DE48B8C9BA052A5CCD95380D6F5B49C1032BF17AE430644 keyuses:10000 name:newtoken amount:1000000\n"
        + "\n"
        + "createtokenfrom fromaddress:0x6A3A060CE9D8E876E9B12DBE5D8F6A6864183BA1A63EA8CBCC14D668B5BECACF script:RETURN TRUE privatekey:0xF5C44E0F9FE6ECCC0DE48B8C9BA052A5CCD95380D6F5B49C1032BF17AE430644 keyuses:10000 amount:10 name:{\"name\":\"newcoin\",\"link\":\"http:mysite.com\",\"description\":\"A very cool token\"}\n";
}

std::unique_ptr<JSONObject> createtokenfrom::runCommand() {
    // Prepare response
    std::unique_ptr<JSONObject> ret = getJSONReply();

    try {
        std::string fromaddress = getAddressParam("fromaddress");
        std::unique_ptr<MiniNumber> amount = getNumberParam("amount");
        std::string script = getParam("script");

        std::string privatekey = getAddressParam("privatekey");
        std::unique_ptr<MiniNumber> keyuses = getNumberParam("keyuses");

        bool mine = getBooleanParam("mine", true);

        // The name of the token
        std::unique_ptr<JSONObject> jsonname;
        if (isParamJSONObject("name")) {
            jsonname = getJSONObjectParam("name");

            // Make sure there is a name key
            if (!jsonname->containsKey("name")) {
                throw CommandException("MUST specify a 'name' for the token in the JSON");
            }
        } else {
            // It's a String.. create a JSON
            jsonname = std::make_unique<JSONObject>();
            jsonname->put("name", getParam("name"));
        }

        // Get the number of decimals - and check
        int decimals = 8;
        if (existsParam("decimals")) {
            try {
                decimals = std::stoi(getParam("decimals"));
            } catch (...) {
                throw CommandException("Invalid decimals value");
            }

            if (decimals > 16) {
                throw CommandException("Maximum number of decimals is 16");
            }
        }

        // Check some things
        MiniNumber totaltoks = amount->floor();
        if (totaltoks.isMore(MiniNumber::TRILLION())) {
            throw CommandException("Cannot create more than a trillion tokens");
        }
        if (totaltoks.isLessEqual(MiniNumber::ZERO())) {
            throw CommandException("Cannot create zero or less tokens");
        }

        // Now create the token
        MiniNumber totaldecs = MiniNumber::TEN().pow(decimals);
        MiniNumber minimamount = MiniNumber::MINI_UNIT().mult(totaldecs).mult(totaltoks);

        // Scale
        int scale = MiniNumber::MAX_DECIMAL_PLACES - decimals;

        // Random transaction id
        std::string randomid = MiniData::getRandomData(32).to0xString();

        // Create the transaction
        runCommandSingle(std::string("txncreate id:") + randomid);

        // Add the amount to the transaction
        std::ostringstream addcmd;
        addcmd << "txnaddamount id:" << randomid
               << " fromaddress:" << fromaddress
               << " address:" << fromaddress
               << " amount:" << minimamount.toString();
        std::shared_ptr<JSONObject> result = runCommandSingle(addcmd.str());

        // Check status
        if (!checkStatus(*result)) {
            // Delete the txn
            runCommandSingle(std::string("txndelete id:") + randomid);

            // Throw an error
            throw CommandException(result->getString("error"));
        }

        // Create a new Token
        auto createtoken = std::make_unique<Token>(
            Coin::COINID_OUTPUT,
            MiniNumber(scale),
            minimamount,
            MiniString(tokenNameValue(*jsonname)),
            MiniString("RETURN TRUE"));

        // Create a Coin
        auto tokenoutput = std::make_unique<Coin>(
            Coin::COINID_OUTPUT, MiniData(fromaddress), minimamount, Token::TOKENID_CREATE, true);
        tokenoutput->setToken(std::move(createtoken));

        // Get the Transaction and replace the output
        TxnDB& txndb = MinimaDB::getDB()->getCustomTxnDB();
        TxnRow* txnrow = txndb.getTransactionRow(randomid);
        if (!txnrow) {
            runCommandSingle(std::string("txndelete id:") + randomid);
            throw CommandException("Internal error: transaction row missing.");
        }
        Transaction& trans = txnrow->getTransaction();

        // Get all the outputs..
        auto& outputs = trans.getAllOutputs();
        if (outputs.empty()) {
            runCommandSingle(std::string("txndelete id:") + randomid);
            throw CommandException("No outputs found for the transaction");
        }
        outputs[0] = std::move(tokenoutput);

        // Now the Script
        std::ostringstream scr;
        scr << "txnscript id:" << randomid << " scripts:{\"" << script << "\":\"\"}";
        runCommandSingle(scr.str());

        // Calculate the MMR
        runCommandSingle(std::string("txnmmr id:") + randomid);

        // Now sign
        std::ostringstream signcmd;
        signcmd << "txnsign id:" << randomid
                << " publickey:custom"
                << " privatekey:" << privatekey
                << " keyuses:" << keyuses->toString();
        result = runCommandSingle(signcmd.str());

        // Check status
        if (!checkStatus(*result)) {
            // Delete the txn
            runCommandSingle(std::string("txndelete id:") + randomid);

            // Throw an error
            throw CommandException(result->getString("error"));
        }

        // Now Post it
        std::ostringstream postcmd;
        postcmd << "txnpost id:" << randomid << " mine:" << (mine ? "true" : "false");
        result = runCommandSingle(postcmd.str());

        // Check status
        if (!checkStatus(*result)) {
            // Delete the txn
            runCommandSingle(std::string("txndelete id:") + randomid);

            // Throw an error
            throw CommandException(result->getString("error"));
        }

        // Delete the txn
        runCommandSingle(std::string("txndelete id:") + randomid);

        // Return the result
        ret->put("response", result->get("response"));
        return ret;

    } catch (const CommandException& e) {
        ret->put("status", false);
        ret->put("pending", false);
        ret->put("error", std::string(e.what()));
        return ret;
    } catch (const std::exception& e) {
        ret->put("status", false);
        ret->put("pending", false);
        ret->put("error", std::string("Exception: ") + e.what());
        return ret;
    }
}

std::shared_ptr<JSONObject> createtokenfrom::runCommandSingle(const std::string& zCommand) {
    auto res = org::minima::system::commands::CommandRunner::getRunner()->runSingleCommand(zCommand);
    if (!res) {
        throw std::runtime_error("CommandRunner returned null JSONObject for command: " + zCommand);
    }
    return res;
}

bool createtokenfrom::checkStatus(const JSONObject& zResult) {
    if (!zResult.containsKey("status")) {
        return false;
    }
    try {
        return zResult.getBoolean("status");
    } catch (...) {
        return false;
    }
}

std::string createtokenfrom::tokenNameValue(const JSONObject& zName) {
    if (!zName.containsKey("name")) {
        return zName.toString();
    }

    const std::any& v = zName.get("name");

    // String
    if (v.type() == typeid(std::string)) {
        return std::any_cast<const std::string&>(v);
    }
    if (v.type() == typeid(const char*)) {
        return std::string(std::any_cast<const char*>(v));
    }

    // Nested JSONObject
    if (v.type() == typeid(std::shared_ptr<JSONObject>)) {
        const auto& sp = std::any_cast<const std::shared_ptr<JSONObject>&>(v);
        return sp ? sp->toString() : std::string("");
    }
    if (v.type() == typeid(JSONObject*)) {
        JSONObject* op = std::any_cast<JSONObject*>(v);
        return op ? op->toString() : std::string("");
    }
    if (v.type() == typeid(JSONObject)) {
        return std::any_cast<const JSONObject&>(v).toString();
    }

    // Fall back to the JSON of the whole name object
    return zName.toString();
}

org::minima::system::commands::Command* createtokenfrom::getFunction() {
    return new createtokenfrom();
}

} // namespace wallet
} // namespace send
} // namespace commands
} // namespace system
} // namespace minima
} // namespace org
