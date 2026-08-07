#include "org/minima/system/network/rpc/c_m_d_handler.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <ctime>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
#endif

#include "org/minima/database/minima_d_b.hpp"
#include "org/minima/database/userprefs/user_d_b.hpp"
#include "org/minima/system/network/rpc/h_t_t_p_s_server.hpp"
#include "org/minima/system/network/rpc/authorizer.hpp"
#include "org/minima/objects/base/mini_string.hpp"
#include "org/minima/system/params/general_params.hpp"
#include "org/minima/system/commands/command_runner.hpp"
#include "org/minima/system/main.hpp"
#include "org/minima/utils/minima_logger.hpp"
#include "org/minima/utils/json/j_s_o_n_array.hpp"
#include "org/minima/utils/json/j_s_o_n_object.hpp"

namespace org {
namespace minima {
namespace system {
namespace network {
namespace rpc {

// Helpers (internal linkage)
namespace {

#ifdef _WIN32
static SOCKET to_os_socket(std::intptr_t s) { return static_cast<SOCKET>(s); }
#else
static int to_os_socket(std::intptr_t s) { return static_cast<int>(s); }
#endif

static void socket_close(std::intptr_t s) {
#ifdef _WIN32
    SOCKET sock = to_os_socket(s);
    if (sock != INVALID_SOCKET) {
        ::shutdown(sock, SD_BOTH);
        ::closesocket(sock);
    }
#else
    int sock = to_os_socket(s);
    if (sock >= 0) {
        ::shutdown(sock, SHUT_RDWR);
        ::close(sock);
    }
#endif
}

// Abstract I/O interface used by readLine / recv_all / send_all so the same
// HTTP parsing code works for both plain TCP and TLS sockets.
class ByteStream {
public:
    virtual ~ByteStream() = default;
    virtual int read(void* buf, std::size_t len) = 0;
    virtual int write(const void* buf, std::size_t len) = 0;
};

class PlainByteStream : public ByteStream {
    std::intptr_t mSock;
public:
    explicit PlainByteStream(std::intptr_t sock) : mSock(sock) {}
    int read(void* buf, std::size_t len) override {
#ifdef _WIN32
        SOCKET s = to_os_socket(mSock);
#else
        int s = to_os_socket(mSock);
#endif
        int r = ::recv(s, static_cast<char*>(buf), static_cast<int>(len), 0);
        return r;
    }
    int write(const void* buf, std::size_t len) override {
#ifdef _WIN32
        SOCKET s = to_os_socket(mSock);
#else
        int s = to_os_socket(mSock);
#endif
        int r = ::send(s, static_cast<const char*>(buf), static_cast<int>(len), 0);
        return r;
    }
};

class SSLByteStream : public ByteStream {
    std::shared_ptr<HTTPSServer::SSLClient> mClient;
public:
    explicit SSLByteStream(std::shared_ptr<HTTPSServer::SSLClient> client) : mClient(std::move(client)) {}
    int read(void* buf, std::size_t len) override {
        if (!mClient || !mClient->isValid()) return -1;
        long r = mClient->read(buf, len);
        return static_cast<int>(r);
    }
    int write(const void* buf, std::size_t len) override {
        if (!mClient || !mClient->isValid()) return -1;
        long r = mClient->write(buf, len);
        return static_cast<int>(r);
    }
};

static bool recv_byte(ByteStream& stream, char& out) {
    unsigned char c;
    int r = stream.read(&c, 1);
    if (r == 1) {
        out = static_cast<char>(c);
        return true;
    }
    return false;
}

static constexpr std::size_t MAX_HEADER_LINE_LENGTH = 8192;
static constexpr int MAX_POST_BODY_SIZE = 10 * 1024 * 1024; // 10 MB

// SECURITY: Per-IP rate limiting for authentication attempts (brute-force protection)
static constexpr std::size_t MAX_AUTH_FAILURES = 5;       // max failures before throttle
static constexpr std::chrono::minutes AUTH_WINDOW(15);    // sliding window
static constexpr std::size_t MAX_AUTH_TRACKED = 1024;     // max IPs tracked before pruning
static std::mutex s_authMutex;
static std::unordered_map<std::string, std::pair<std::size_t, std::chrono::steady_clock::time_point>> s_authFailures;

static std::string peerIp(std::intptr_t sock) {
#ifdef _WIN32
    SOCKET s = to_os_socket(sock);
#else
    int s = to_os_socket(sock);
#endif
    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    std::memset(&addr, 0, sizeof(addr));
    if (getpeername(s, reinterpret_cast<sockaddr*>(&addr), &addrlen) == 0) {
        char host[
#ifdef NI_MAXHOST
            NI_MAXHOST
#else
            1025
#endif
        ] = {0};
        if (getnameinfo(reinterpret_cast<sockaddr*>(&addr), addrlen, host, sizeof(host), nullptr, 0,
                        NI_NUMERICHOST) == 0) {
            return std::string(host);
        }
    }
    return "unknown";
}

// Returns true if the peer has exceeded the allowed number of failed attempts.
static bool authRateLimited(const std::string& ip) {
    std::lock_guard<std::mutex> lock(s_authMutex);
    auto now = std::chrono::steady_clock::now();
    auto it = s_authFailures.find(ip);
    if (it == s_authFailures.end()) {
        return false;
    }
    auto& [count, first] = it->second;
    if (now - first > AUTH_WINDOW) {
        s_authFailures.erase(it);
        return false;
    }
    return count >= MAX_AUTH_FAILURES;
}

// Record a failed authentication attempt for the peer.
static void recordAuthFailure(const std::string& ip) {
    std::lock_guard<std::mutex> lock(s_authMutex);
    auto now = std::chrono::steady_clock::now();
    auto& entry = s_authFailures[ip];
    if (now - entry.second > AUTH_WINDOW) {
        entry = {1, now};
    } else {
        entry.first++;
        entry.second = now;
    }
    // SECURITY: Bound the size of the tracking map. Expired entries are swept
    // once the map grows large, preventing unbounded memory growth.
    if (s_authFailures.size() > MAX_AUTH_TRACKED) {
        for (auto it = s_authFailures.begin(); it != s_authFailures.end();) {
            if (now - it->second.second > AUTH_WINDOW) {
                it = s_authFailures.erase(it);
            } else {
                ++it;
            }
        }
    }
}

static std::string readLine(ByteStream& stream) {
    // Reads until '\n' (handles CRLF or LF). Returns empty string on EOF with no data.
    std::string line;
    char ch = 0;
    bool got_any = false;
    while (true) {
        if (!recv_byte(stream, ch)) {
            break; // EOF or error
        }
        got_any = true;
        if (ch == '\n') {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            break;
        }
        line.push_back(ch);
        if (line.size() > MAX_HEADER_LINE_LENGTH) {
            throw std::runtime_error("HTTP header line exceeds maximum length");
        }
        // In case the client sent only '\r' terminated lines (unlikely)
        if (ch == '\r') {
            // Peek next; if it's '\n', the next loop iteration will consume it
            continue;
        }
    }
    if (!got_any && line.empty()) {
        return std::string(); // empty => caller treats as ""
    }
    // Trim trailing '\r' if present (already handled above when seeing '\n')
    return line;
}

static bool recv_all(ByteStream& stream, char* buf, std::size_t len) {
    std::size_t total = 0;
    while (total < len) {
        int r = stream.read(buf + total, len - total);
        if (r <= 0) {
            return false;
        }
        total += static_cast<std::size_t>(r);
    }
    return true;
}

static bool send_all(ByteStream& stream, const char* data, std::size_t len) {
    std::size_t total = 0;
    while (total < len) {
        int r = stream.write(data + total, len - total);
        if (r <= 0) {
            return false;
        }
        total += static_cast<std::size_t>(r);
    }
    return true;
}

static std::string trim(const std::string& s) {
    std::size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) ++start;
    if (start == s.size()) return std::string();
    std::size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) --end;
    return s.substr(start, end - start);
}

static std::string url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '+') {
            out.push_back(' ');
        } else if (c == '%' && i + 2 < s.size()) {
            char hi = s[i + 1];
            char lo = s[i + 2];
            auto hex = [](char ch) -> int {
                if (ch >= '0' && ch <= '9') return ch - '0';
                if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
                if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
                return -1;
            };
            int h = hex(hi), l = hex(lo);
            if (h >= 0 && l >= 0) {
                out.push_back(static_cast<char>((h << 4) | l));
                i += 2;
            } else {
                out.push_back(c);
            }
        } else {
            out.push_back(c);
        }
    }
    return out;
}

static std::string current_date_string() {
    std::time_t now = std::time(nullptr);
    char buf[128]{0};
#if defined(_WIN32)
    ctime_s(buf, sizeof(buf), &now);
#else
    std::string tmp = std::ctime(&now);
    std::snprintf(buf, sizeof(buf), "%s", tmp.c_str());
#endif
    std::string ds(buf);
    // remove trailing newline if present
    if (!ds.empty() && ds.back() == '\n') {
        ds.pop_back();
    }
    return ds;
}

static std::string any_to_json_string(const std::any& a) {
    using org::minima::utils::json::JSONObject;
    using org::minima::utils::json::JSONArray;

    // Try common forms
    try { return std::any_cast<std::string>(a); } catch (...) {}
    try { return std::string(std::any_cast<const char*>(a)); } catch (...) {}

    try {
        const JSONObject& obj = std::any_cast<const JSONObject&>(a);
        return obj.toString();
    } catch (...) {}

    try {
        const JSONArray& arr = std::any_cast<const JSONArray&>(a);
        return arr.toString();
    } catch (...) {}

    try {
        const std::shared_ptr<JSONObject>& pobj = std::any_cast<const std::shared_ptr<JSONObject>&>(a);
        if (pobj) return pobj->toString();
    } catch (...) {}

    try {
        const std::shared_ptr<JSONArray>& parr = std::any_cast<const std::shared_ptr<JSONArray>&>(a);
        if (parr) return parr->toString();
    } catch (...) {}

    // Fallback: unknown type; attempt to stringify via typeid
    return std::string("{}");
}

} // anonymous namespace

CMDHandler::CMDHandler(std::intptr_t zSocket)
    : mSocket(zSocket), mSocketOpen(true), mSSLClient(nullptr) {}

CMDHandler::CMDHandler(std::shared_ptr<HTTPSServer::SSLClient> zSSLClient)
    : mSocket(0), mSocketOpen(false), mSSLClient(std::move(zSSLClient)) {}

CMDHandler::~CMDHandler() {
    closeSocket();
}

CMDHandler::CMDHandler(CMDHandler&& other) noexcept
    : mSocket(other.mSocket), mSocketOpen(other.mSocketOpen), mSSLClient(std::move(other.mSSLClient)) {
    other.mSocket = 0;
    other.mSocketOpen = false;
}

CMDHandler& CMDHandler::operator=(CMDHandler&& other) noexcept {
    if (this != &other) {
        closeSocket();
        mSocket = other.mSocket;
        mSocketOpen = other.mSocketOpen;
        mSSLClient = std::move(other.mSSLClient);
        other.mSocket = 0;
        other.mSocketOpen = false;
    }
    return *this;
}

void CMDHandler::closeSocket() noexcept {
    if (mSocketOpen) {
        socket_close(mSocket);
        mSocketOpen = false;
    }
    if (mSSLClient) {
        mSSLClient->close();
        mSSLClient.reset();
    }
}

void CMDHandler::run() {
    std::string firstline = "no first line..";
    bool quit = false;

    // Choose the transport stream
    std::unique_ptr<ByteStream> stream;
    if (mSSLClient) {
        stream = std::make_unique<SSLByteStream>(mSSLClient);
    } else {
        stream = std::make_unique<PlainByteStream>(mSocket);
    }

    try {
        // Read request line
        std::string input = readLine(*stream);
        if (input.empty()) {
            input = "";
        }

        // Get the first line..
        firstline = std::string(input);

        // Parse method and request-target
        std::istringstream iss(input);
        std::string method, fileRequested;
        if (!(iss >> method)) {
            throw std::runtime_error("Invalid HTTP request line (no method)");
        }
        std::transform(method.begin(), method.end(), method.begin(),
                       [](unsigned char c){ return static_cast<char>(std::toupper(c)); });

        if (!(iss >> fileRequested)) {
            throw std::runtime_error("Invalid HTTP request line (no target)");
        }

        // Remove slashes..
        if (!fileRequested.empty() && fileRequested.front() == '/') {
            fileRequested.erase(fileRequested.begin());
        }
        if (!fileRequested.empty() && fileRequested.back() == '/') {
            fileRequested.pop_back();
        }

        // URL decode (UTF-8 semantics)
        fileRequested = trim(url_decode(fileRequested));

        // SECURITY: Default to UNAUTHENTICATED. Only grant access if valid credentials provided.
        org::minima::utils::json::JSONObject authuser;
        authuser.put("valid", false);
        authuser.put("mode", std::string("read"));

        // Get the Headers..
        int contentlength = 0;
        while (true) {
            input = readLine(*stream);
            if (input.empty()) {
                break;
            }
            std::string t = trim(input);
            if (t.empty()) {
                break; // blank line between headers and content
            }

            // Check if Authorised (case-insensitive per RFC 7230)
            std::string lowerInput = input;
            std::transform(lowerInput.begin(), lowerInput.end(), lowerInput.begin(),
                [](unsigned char c) { return std::tolower(c); });
            std::size_t authref = lowerInput.find("authorization:");
            if (authref != std::string::npos) {
                // Check it..
                try {
                    authuser = Authorizer::checkAuchCredentials(input);
                } catch (...) {
                    // If Authorizer throws, leave authuser as-is; subsequent valid check will fail if required.
                }
            }

            std::size_t ref = input.find("Content-Length:");
            if (ref != std::string::npos) {
                std::size_t colon = input.find(':', ref);
                if (colon != std::string::npos) {
                    std::string lenstr = trim(input.substr(colon + 1));
                    try {
                        contentlength = std::stoi(lenstr);
                    } catch (...) {
                        contentlength = 0;
                    }
                }
            }
        }

        // Are we Authorised
        if (!authuser.getBoolean("valid")) {
            const std::string ip = mSSLClient ? "ssl" : peerIp(mSocket);

            // SECURITY: Throttle repeated authentication failures
            if (authRateLimited(ip)) {
                std::string resp;
                const std::string nl = "\n";
                resp += "HTTP/1.1 429 Too Many Requests" + nl;
                resp += "Server: HTTP RPC Server from Minima 1.3" + nl;
                resp += nl;
                resp += "{\"error\":\"Too many failed authentication attempts..\"}" + nl;
                send_all(*stream, resp.c_str(), resp.size());
                throw std::invalid_argument("Rate-limited authentication at RPC");
            }
            recordAuthFailure(ip);

            std::string resp;
            const std::string nl = "\n";
            resp += "HTTP/1.1 401 Unauthorized" + nl;
            resp += "Server: HTTP RPC Server from Minima 1.3" + nl;
            resp += nl;
            resp += "{\"error\":\"Authentication failure..\"}" + nl;
            send_all(*stream, resp.c_str(), resp.size());

            throw std::invalid_argument("Invalid Authentication at RPC");
        }

        // SECURITY: Enforce read/write mode. Sensitive commands require write access.
        std::string authMode = authuser.getString("mode");
        bool isWriteMode = (authMode == "write");
        static const std::vector<std::string> writeRequiredCommands = {
            "send", "tokencreate", "vault", "backup", "restore", "reset",
            "newaddress", "newscript", "removescript", "magic", "slavenode",
            "quit", "rpc", "txnpost", "txncreate", "txndelete", "txninput",
            "txnoutput", "txnscript", "txnsign", "txnmine", "txnclear",
            "txnimport", "txncoinlock", "txnlock", "txnstate", "txnaddamount",
            "sign", "multisig", "consolidate", "burn", "coinexport", "coinimport",
            "archive", "mysql", "mysqlcoins", "decryptbackup", "restoresync",
            "megammrsync", "megammr", "sendfrom", "createfrom", "signfrom",
            "postfrom", "rawfrom", "constructfrom", "consolidatefrom",
            "sendnosign", "sendsign", "sendpost", "sendpoll", "sendview",
            "automine", "incentivecash", "seedrandom", "wipekeys", "restorekeys",
            "passwordlock", "passwordunlock", "resetkeys", "testphrase"
        };
        if (!isWriteMode) {
            std::string cmdLower = fileRequested;
            std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(),
                           [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            for (const auto& wcmd : writeRequiredCommands) {
                if (cmdLower == wcmd || cmdLower.rfind(wcmd + " ", 0) == 0) {
                    std::string resp;
                    const std::string nl = "\n";
                    resp += "HTTP/1.1 403 Forbidden" + nl;
                    resp += "Server: HTTP RPC Server from Minima 1.3" + nl;
                    resp += nl;
                    resp += "{\"error\":\"Write access required for command: " + fileRequested + "\"}" + nl;
                    send_all(*stream, resp.c_str(), resp.size());
                    throw std::invalid_argument("Write access required for command: " + fileRequested);
                }
            }
        }

        // Is it a POST request
        if (method == "POST") {
            // SECURITY: Enforce maximum POST body size
            if (contentlength < 0 || contentlength > MAX_POST_BODY_SIZE) {
                std::string resp;
                const std::string nl = "\n";
                resp += "HTTP/1.1 413 Payload Too Large" + nl;
                resp += "Server: HTTP RPC Server from Minima 1.3" + nl;
                resp += nl;
                resp += "{\"error\":\"POST body exceeds maximum size of " + std::to_string(MAX_POST_BODY_SIZE) + " bytes\"}" + nl;
                send_all(*stream, resp.c_str(), resp.size());
                throw std::invalid_argument("POST body too large: " + std::to_string(contentlength));
            }

            // Get the POST data..
            std::string body;
            body.resize(static_cast<std::size_t>(std::max(0, contentlength)));

            // Read it ALL in
            if (!body.empty()) {
                bool ok = recv_all(*stream, &body[0], body.size());
                if (!ok) {
                    org::minima::utils::MinimaLogger::log("CMDHANDLER : Read wrong amount 0/" + std::to_string(contentlength));
                }
            }

            // Set this..
            fileRequested = body;
        }

        org::minima::utils::json::JSONObject statfalse;
        statfalse.put("status", false);
        std::string result = statfalse.toJSONString();

        try {
            if (fileRequested == "quit") {
                quit = true;
            }

            // Now run this command
            auto runner = org::minima::system::commands::CommandRunner::getRunner();
            auto res = runner ? runner->runMultiCommand(fileRequested) : nullptr;

            // Get the result.. is it a multi command or single..
            if (res && res->size() == 1) {
                const auto& elems = res->elements();
                if (!elems.empty()) {
                    result = any_to_json_string(elems[0]);
                } else {
                    result = res->toString();
                }
            } else if (res) {
                result = res->toString();
            }
            // else keep default result

        } catch (const std::exception& exc) {
            org::minima::utils::MinimaLogger::log(std::string("ERROR CMDHANDLER : ") + fileRequested + " " + exc.what());
        } catch (...) {
            org::minima::utils::MinimaLogger::log(std::string("ERROR CMDHANDLER : ") + fileRequested + " <unknown exception>");
        }

        // Calculate the size of the response (UTF-8 bytes)
        int finallength = static_cast<int>(result.size());

        // Are we using CRLF
        const bool use_crlf = org::minima::system::params::GeneralParams::RPC_CRLF;
        const std::string nl = use_crlf ? "\r\n" : "\n";

        // Build HTTP response
        std::ostringstream oss;
        oss << "HTTP/1.1 200 OK" << nl;
        oss << "Server: HTTP RPC Server from Minima 1.3" << nl;
        oss << "Date: " << current_date_string() << nl;
        oss << "Content-type: text/plain" << nl;
        oss << "Content-length: " << finallength << nl;
        oss << "Access-Control-Allow-Origin: http://localhost" << nl;
        oss << "Access-Control-Allow-Origin: https://localhost" << nl;
        oss << nl; // blank line
        oss << result << nl;

        std::string response = oss.str();
        send_all(*stream, response.c_str(), response.size());

    } catch (const std::exception& ioe) {
        org::minima::utils::MinimaLogger::log(std::string("CMDHANDLER : ") + ioe.what() + " " + firstline);
    } catch (...) {
        org::minima::utils::MinimaLogger::log(std::string("CMDHANDLER : unknown error ") + firstline);
    }

    // Finally close socket
    try {
        closeSocket();
    } catch (...) {
        // ignore
    }

    // Are we shutting down
    if (quit) {
        // SECURITY: Graceful shutdown via Main instead of hard std::_Exit(0)
        auto* mainInst = org::minima::system::Main::getInstance();
        if (mainInst) {
            mainInst->setHasShutDown();
        }
    }
}

} // namespace rpc
} // namespace network
} // namespace system
} // namespace minima
} // namespace org