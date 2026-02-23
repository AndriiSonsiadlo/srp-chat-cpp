#pragma once

#include <string>
#include <chrono>
#include <cstdint>
#include <tuple>

namespace chat
{
#pragma pack(push, 1)
    struct MsgHeader
    {
        uint16_t type; // MessageType
        uint32_t size; // payload size in bytes
    };
#pragma pack(pop)

    enum class MessageType : uint16_t
    {
        // chat
        INIT,        // server sends initial data (messages, users)
        MESSAGE,     // client sends a message
        BROADCAST,   // server broadcasts a message
        USER_JOINED, // server notifies of new user
        USER_LEFT,   // server notifies of user leaving
        DISCONNECT,  // client disconnecting
        ERROR_MSG,   // error message

        // authentication (SRP-6a)
        SRP_REGISTER,       // client registers new account
        SRP_REGISTER_ACK,   // server acknowledges registration
        SRP_INIT,           // client initiates SRP auth
        SRP_CHALLENGE,      // server sends challenge
        SRP_RESPONSE,       // client sends proof M
        SRP_SUCCESS,        // server confirms authentication
        SRP_USER_NOT_FOUND, // server rejects authentication due to user not found
    };

    struct User
    {
        std::string username;
        std::string user_id;

        [[nodiscard]] auto as_tuple() const
        {
            return std::tie(username, user_id);
        }

        [[nodiscard]] auto as_tuple()
        {
            return std::tie(username, user_id);
        }
    };

    struct Message
    {
        std::string username;
        std::string text;
        std::chrono::system_clock::time_point timestamp;

        [[nodiscard]] auto as_tuple() const
        {
            return std::tie(username, text);
        }

        [[nodiscard]] auto as_tuple()
        {
            return std::tie(username, text);
        }
    };
} // namespace chat
