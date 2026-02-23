#pragma once

#include <memory>
#include <atomic>
#include <vector>
#include <boost/asio.hpp>

#include "chat/auth/srp_server.hpp"
#include "chat/common/types.hpp"
#include "chat/server/connection_manager.hpp"

namespace chat::server
{
    class Server
    {
    public:
        explicit Server(int port);
        ~Server();

        void run();
        void stop();

    private:
        boost::asio::io_context io_context_;
        boost::asio::ip::tcp::acceptor acceptor_;

        std::unique_ptr<auth::SRPServer> srp_server_;
        std::unique_ptr<ConnectionManager> connection_manager_;

        std::vector<Message> message_history_;
        std::mutex message_mutex_;

        std::atomic<int> next_user_id_;
        std::atomic<bool> running_;

        int port_;

        void start_accept();

        std::optional<std::string> handle_srp_authentication(const std::shared_ptr<Connection>& conn);
        void handle_srp_register(const std::shared_ptr<Connection>& conn, const std::vector<uint8_t>& payload);

        void handle_disconnect(const std::string& user_id) const;
        void handle_client(const std::shared_ptr<Connection>& conn, const std::string& user_id);
        void handle_message(const std::string& username, const std::string& text);
    };
} // namespace chat::server
