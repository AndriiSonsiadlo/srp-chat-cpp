#pragma once

#include <string>
#include <vector>
#include "chat/common/types.hpp"

namespace chat
{
    class Protocol
    {
    public:
        static std::string encode_connect(const std::string& username);
        static std::string encode_connect_ack(const std::string& user_id);
        static std::string encode_init(
            const std::vector<Message>& messages,
            const std::vector<User>& users);
        static std::string encode_message(const std::string& text);
        static std::string encode_broadcast(
            const std::string& username,
            const std::string& text,
            const std::string& timestamp);
        static std::string encode_user_joined(const std::string& username, const std::string& user_id);
        static std::string encode_user_left(const std::string& username);
        static std::string encode_disconnect();
        static std::string encode_error(const std::string& error_msg);
        static MessageType parse_type(const std::string& message);
        static std::string parse_field(const std::string& message, const std::string& field_name);
        static std::vector<Message> parse_messages(const std::string& messages_str);
        static std::vector<User> parse_users(const std::string& users_str);

    private:
        static std::string escape(const std::string& str);
        static std::string unescape(const std::string& str);
    };
} // namespace chat
