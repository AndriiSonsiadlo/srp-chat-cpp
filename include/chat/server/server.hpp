#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include "chat/auth/srp_server.hpp"
#include "chat/server/room.hpp"

namespace chat::server
{
    struct ServerConfig
    {
        uint16_t port                          = 8888;
        std::string users_db                   = "users.db";
        size_t max_connections                 = 256;
        std::chrono::seconds handshake_timeout = std::chrono::seconds(30);
        std::chrono::seconds idle_timeout      = std::chrono::seconds(120);
    };

    class Server
    {
    public:
        explicit Server(ServerConfig config);
        ~Server();

        void run();
        void stop();

        // Used by Session.
        Room& room() { return room_; }
        auth::SRPServer& srp() { return *srp_server_; }
        [[nodiscard]] std::chrono::seconds handshake_timeout() const { return config_.handshake_timeout; }
        [[nodiscard]] std::chrono::seconds idle_timeout() const { return config_.idle_timeout; }
        void on_session_closed() { --open_connections_; }

    private:
        boost::asio::awaitable<void> accept_loop();
        boost::asio::awaitable<void> session_sweeper();

        ServerConfig config_;
        boost::asio::io_context io_context_;
        boost::asio::ip::tcp::acceptor acceptor_;
        std::unique_ptr<auth::SRPServer> srp_server_;
        Room room_;
        std::atomic<size_t> open_connections_{0};
    };
} // namespace chat::server
