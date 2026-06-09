#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <optional>
#include <thread>
#include <vector>
#include <mutex>
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/executor_work_guard.hpp>

#include "chat/auth/srp_client.hpp"
#include "chat/common/types.hpp"

namespace chat::client
{
    struct ClientConfig
    {
        std::string host     = "localhost";
        uint16_t port        = 8888;
        std::string username;
        bool register_first  = false;
    };

    class Client
    {
    public:
        explicit Client(ClientConfig config);
        ~Client();

        void run();
        void stop();

    private:
        boost::asio::io_context io_context_;
        boost::asio::ip::tcp::socket socket_;

        std::unique_ptr<auth::SRPClient> srp_client_;
        std::vector<uint8_t> room_key_;

        ClientConfig config_;
        std::string password_;
        std::string user_id_;

        std::atomic<bool> running_;
        std::atomic<bool> connected_;

        // Runs io_context_; replaces the old blocking receive thread.
        std::thread io_thread_;
        std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work_guard_;

        std::vector<Message> messages_;
        std::vector<User> users_;

        std::mutex messages_mutex_;
        std::mutex users_mutex_;
        std::mutex ui_mutex_;

        void connect();
        void disconnect();

        boost::asio::awaitable<void> srp_authenticate();
        boost::asio::awaitable<void> srp_register();

        boost::asio::awaitable<void> send_message(std::string text);
        boost::asio::awaitable<void> receive_loop();

        void input_loop(); // blocking stdin loop, runs on the main thread

        void handle_packet(MessageType type, const std::vector<uint8_t>& payload);
        void handle_broadcast(const std::vector<uint8_t>& payload);

        void render_ui();
        void print_banner();
    };
} // namespace chat::client
