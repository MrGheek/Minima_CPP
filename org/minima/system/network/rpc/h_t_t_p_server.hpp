#pragma once

#include <functional>
#include <atomic>
#include <cstdint>
#include <mutex>

#include "org/minima/system/network/rpc/server.hpp"

namespace org {
namespace minima {
namespace system {
namespace network {
namespace rpc {

class HTTPServer : public Server {
public:
    using NativeSocket = intptr_t; // OS-agnostic socket handle passed to handlers

    // Construct on port. Does NOT auto-start; call start() explicitly after
    // the derived object is fully constructed (matches safe C++ two-phase init).
    explicit HTTPServer(int port);

    // Construct on port with explicit auto-start. Prefer the single-arg
    // constructor plus an explicit start() call to avoid detached threads
    // running on partially-constructed derived objects.
    HTTPServer(int port, bool autoStart);

    // Non-copyable
    HTTPServer(const HTTPServer&) = delete;
    HTTPServer& operator=(const HTTPServer&) = delete;

    // Movable is implicitly deleted on most platforms because std::atomic
    // and std::thread are non-movable; keep declarations to match prior API.
    HTTPServer(HTTPServer&&) noexcept = default;
    HTTPServer& operator=(HTTPServer&&) noexcept = default;

    virtual ~HTTPServer();

    // Start the server loop in a background thread.
    // Safe to call once the most-derived object is fully constructed.
    void start();

    // Implement Server
    void shutdown() override;

    // The accept loop entry point
    virtual void run();

    // Subclasses must provide a handler factory for each accepted client socket.
    // The returned callable will be executed on a detached thread.
    virtual std::function<void()> getSocketHandler(NativeSocket clientSocket) = 0;

protected:
    std::atomic<bool> mRunning { true };
    // SECURITY: Track active connections to enforce limits
    std::atomic<int> mActiveConnections {0};
    static constexpr int MAX_RPC_CONNECTIONS = 100;

private:
    // Stored as an OS-agnostic handle; invalid when 0 or negative depending on platform.
    NativeSocket mServerSocket = static_cast<NativeSocket>(-1);
};

} // namespace rpc
} // namespace network
} // namespace system
} // namespace minima
} // namespace org