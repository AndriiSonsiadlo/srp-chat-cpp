#pragma once

#include <memory>
#include <unordered_map>
#include <mutex>
#include <boost/asio.hpp>

#include "chat/common/types.hpp"

namespace chat::server
{
    class Connection
    {
    private:
        using socket_type = boost::asio::ip::tcp::socket;

        socket_type socket_;
        boost::asio::streambuf buffer_;

    public:
        explicit Connection(boost::asio::io_context& io_context);

        socket_type& socket();

        void send_packet(const std::vector<uint8_t>& packet);
        std::pair<MessageType, std::vector<uint8_t>> receive_packet();

        void close();
        [[nodiscard]] bool is_open() const;
    };

    class ConnectionManager
    {
    private:
        std::unordered_map<std::string, std::shared_ptr<Connection>> connections_;
        std::unordered_map<std::string, std::string> user_id_to_username_;
        mutable std::mutex mutex_;

    public:
        ConnectionManager() = default;

        void add(const std::string& user_id, std::shared_ptr<Connection> conn);
        void set_username(const std::string& user_id, const std::string& username);
        void remove(const std::string& user_id);
        void broadcast(const std::vector<uint8_t>& packet, const std::string& exclude_user = "");
        bool send_to(const std::string& user_id, const std::vector<uint8_t>& packet);
        bool username_exists(const std::string& username) const;
        std::vector<User> get_active_users() const;
        std::string get_user_id_by_username(const std::string& username) const;
        std::string get_username_by_user_id(const std::string& user_id) const;
    };
} // namespace chat::server
