#pragma once

#include <any>
#include <memory>
#include <string>
#include <vector>

#include "org/minima/system/commands/command.hpp"

namespace org {
namespace minima {
namespace system {
namespace commands {
namespace send {
namespace wallet {

class createtokenfrom : public org::minima::system::commands::Command {
public:
    createtokenfrom();

    // Parameter specification and help
    std::vector<std::string> getValidParams() const;
    std::string getFullHelp() const;

    // Execute command
    std::unique_ptr<org::minima::utils::json::JSONObject> runCommand() override;

    // Factory clone
    org::minima::system::commands::Command* getFunction() override;

private:
    // Helper to run a single command and get the resulting JSONObject
    std::shared_ptr<org::minima::utils::json::JSONObject> runCommandSingle(const std::string& zCommand);

    // Check the status of a nested command result
    static bool checkStatus(const org::minima::utils::json::JSONObject& zResult);

    // Get the token name string from the name JSON object (Java: name.get("name").toString())
    static std::string tokenNameValue(const org::minima::utils::json::JSONObject& zName);
};

} // namespace wallet
} // namespace send
} // namespace commands
} // namespace system
} // namespace minima
} // namespace org
