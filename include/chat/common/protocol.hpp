#pragma once

#include <string>
#include <vector>
#include "chat/common/types.hpp"

namespace chat
{
    class Protocol
    {
    public:
        static std::vector<uint8_t> encode_connect(const std::string& username);
        static std::vector<uint8_t> encode_connect_ack(const std::string& user_id);
        static std::vector<uint8_t> encode_init(
            const std::vector<Message>& messages,
            const std::vector<User>& users);
        static std::vector<uint8_t> encode_message(const std::string& text);
        static std::vector<uint8_t> encode_broadcast(
            const std::string& username,
            const std::string& text,
            int64_t timestamp_ms);
        static std::vector<uint8_t> encode_user_joined(const std::string& username, const std::string& user_id);
        static std::vector<uint8_t> encode_user_left(const std::string& username);
        static std::vector<uint8_t> encode_disconnect();
        static std::vector<uint8_t> encode_error(const std::string& error_msg);

        static std::string decode_connect(const std::vector<uint8_t>& payload);
        static std::string decode_connect_ack(const std::vector<uint8_t>& payload);
        static void decode_init(const std::vector<uint8_t>& payload,
                                std::vector<Message>& messages,
                                std::vector<User>& users);
        static std::string decode_message(const std::vector<uint8_t>& payload);
        static void decode_broadcast(const std::vector<uint8_t>& payload,
                                     std::string& username,
                                     std::string& text,
                                     int64_t& timestamp_ms);
        static void decode_user_joined(const std::vector<uint8_t>& payload,
                                       std::string& username,
                                       std::string& user_id);
        static std::string decode_user_left(const std::vector<uint8_t>& payload);
        static std::string decode_error(const std::vector<uint8_t>& payload);
    };
} // namespace chat
