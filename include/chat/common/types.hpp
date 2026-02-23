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
        // connection (legacy - for backward compatibility)
        CONNECT     = 0, // client connecting with username
        CONNECT_ACK = 1, // server acknowledges connection

        // chat
        INIT        = 2, // server sends initial data (messages, users)
        MESSAGE     = 3, // client sends a message
        BROADCAST   = 4, // server broadcasts a message
        USER_JOINED = 5, // server notifies of new user
        USER_LEFT   = 6, // server notifies of user leaving
        DISCONNECT  = 7, // client disconnecting
        ERROR_MSG   = 8, // error message

        // authentication (SRP-6a)
        SRP_REGISTER       = 9,  // client registers new account
        SRP_INIT           = 10, // client initiates SRP auth
        SRP_CHALLENGE      = 11, // server sends challenge
        SRP_RESPONSE       = 12, // client sends proof M
        SRP_SUCCESS        = 13, // server confirms authentication
        SRP_FAILURE        = 14, // server rejects authentication
        SRP_USER_NOT_FOUND = 15, // server rejects authentication due to user not found
        SRP_REGISTER_ACK   = 16, // server acknowledges registration
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
