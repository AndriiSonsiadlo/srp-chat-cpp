#pragma once

#include <memory>
#include <atomic>
#include <vector>
#include <boost/asio.hpp>

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

        std::unique_ptr<ConnectionManager> connection_manager_;

        std::vector<Message> message_history_;
        std::mutex message_mutex_;

        std::atomic<int> next_user_id_;
        std::atomic<bool> running_;

        int port_;

        void start_accept();

        std::optional<std::string> handle_connect(const std::shared_ptr<Connection>& conn);
        void handle_disconnect(const std::string& user_id) const;
        void handle_client(const std::shared_ptr<Connection>& conn, const std::string& user_id);
        void handle_message(const std::shared_ptr<Connection>& conn,
                            const std::string& username,
                            const std::string& message);

        std::string generate_user_id();
        std::string get_timestamp();
    };
} // namespace chat::server
