#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>
#include <boost/asio.hpp>

#include "chat/auth/srp_client.hpp"
#include "chat/common/types.hpp"

namespace chat::client
{
    class Client
    {
    public:
        Client(std::string host, int port, std::string username);
        ~Client();

        void run();
        void stop();

    private:
        boost::asio::io_context io_context_;
        boost::asio::ip::tcp::socket socket_;

        std::unique_ptr<auth::SRPClient> srp_client_;
        std::vector<uint8_t> room_key_;

        std::string host_;
        int port_;
        std::string username_;
        std::string password_;
        std::string user_id_;

        std::atomic<bool> running_;
        std::atomic<bool> connected_;

        std::thread receive_thread_;

        std::vector<Message> messages_;
        std::vector<User> users_;

        std::mutex messages_mutex_;
        std::mutex users_mutex_;
        std::mutex ui_mutex_;

        void disconnect();

        void srp_authenticate();
        void srp_register();

        void send_message(const std::string& text);
        void receive_loop();

        void send_packet(const std::vector<uint8_t>& packet);
        std::pair<MessageType, std::vector<uint8_t>> receive_packet();
        void handle_packet(MessageType type, const std::vector<uint8_t>& payload);
        void handle_broadcast(const std::vector<uint8_t>& payload);

        void render_ui();
        void clear_screen();
        void print_banner();
    };
} // namespace chat::client
