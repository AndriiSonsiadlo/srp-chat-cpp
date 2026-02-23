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

    struct SrpRegisterMsg
    {
        std::string username;
        std::string salt_b64;
        std::string verifier_b64;

        [[nodiscard]] auto as_tuple() const { return std::tie(username, salt_b64, verifier_b64); }
        [[nodiscard]] auto as_tuple() { return std::tie(username, salt_b64, verifier_b64); }
    };

    struct SrpInitMsg
    {
        std::string username;
        std::string A_b64;

        [[nodiscard]] auto as_tuple() const { return std::tie(username, A_b64); }
        [[nodiscard]] auto as_tuple() { return std::tie(username, A_b64); }
    };

    struct SrpChallengeMsg
    {
        std::string user_id;
        std::string B_b64;
        std::string salt_b64;
        std::string room_salt_b64;

        [[nodiscard]] auto as_tuple() const { return std::tie(user_id, B_b64, salt_b64, room_salt_b64); }
        [[nodiscard]] auto as_tuple() { return std::tie(user_id, B_b64, salt_b64, room_salt_b64); }
    };

    struct SrpResponseMsg
    {
        std::string user_id;
        std::string M_b64;

        [[nodiscard]] auto as_tuple() const { return std::tie(user_id, M_b64); }
        [[nodiscard]] auto as_tuple() { return std::tie(user_id, M_b64); }
    };

    struct SrpSuccessMsg
    {
        std::string H_AMK_b64;
        std::string session_key_b64;

        [[nodiscard]] auto as_tuple() const { return std::tie(H_AMK_b64, session_key_b64); }
        [[nodiscard]] auto as_tuple() { return std::tie(H_AMK_b64, session_key_b64); }
    };
} // namespace chat
