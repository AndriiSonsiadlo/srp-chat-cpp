#pragma once

#include <string>
#include <vector>

#include "chat/common/types.hpp"

namespace chat
{
    struct ConnectMsg
    {
        std::string username;

        [[nodiscard]] auto as_tuple() const { return std::tie(username); }
        [[nodiscard]] auto as_tuple() { return std::tie(username); }
    };

    struct ConnectAckMsg
    {
        std::string user_id;

        [[nodiscard]] auto as_tuple() const { return std::tie(user_id); }
        [[nodiscard]] auto as_tuple() { return std::tie(user_id); }
    };

    struct InitMsg
    {
        std::vector<Message> messages;
        std::vector<User> users;

        [[nodiscard]] auto as_tuple() const { return std::tie(messages, users); }
        [[nodiscard]] auto as_tuple() { return std::tie(messages, users); }
    };

    struct TextMsg
    {
        std::string text;

        [[nodiscard]] auto as_tuple() const { return std::tie(text); }
        [[nodiscard]] auto as_tuple() { return std::tie(text); }
    };

    struct BroadcastMsg
    {
        std::string username;
        std::string text;
        int64_t timestamp_ms;

        [[nodiscard]] auto as_tuple() const { return std::tie(username, text, timestamp_ms); }
        [[nodiscard]] auto as_tuple() { return std::tie(username, text, timestamp_ms); }
    };

    struct UserJoinedMsg
    {
        std::string username;
        std::string user_id;

        [[nodiscard]] auto as_tuple() const { return std::tie(username, user_id); }
        [[nodiscard]] auto as_tuple() { return std::tie(username, user_id); }
    };

    struct UserLeftMsg
    {
        std::string username;

        [[nodiscard]] auto as_tuple() const { return std::tie(username); }
        [[nodiscard]] auto as_tuple() { return std::tie(username); }
    };

    struct ErrorMsg
    {
        std::string error_msg;

        [[nodiscard]] auto as_tuple() const { return std::tie(error_msg); }
        [[nodiscard]] auto as_tuple() { return std::tie(error_msg); }
    };
} // namespace chat
