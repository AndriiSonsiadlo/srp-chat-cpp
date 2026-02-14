#pragma once

#include <string>
#include <chrono>

namespace chat
{
    struct User
    {
        std::string username;
        std::string user_id;
    };

    struct Message
    {
        std::string username;
        std::string text;
        std::chrono::system_clock::time_point timestamp;
    };

    enum class MessageType
    {
        CONNECT,     // client connecting with username
        CONNECT_ACK, // server acknowledges connection
        INIT,        // server sends initial data (messages, users)
        MESSAGE,     // client sends a message
        BROADCAST,   // server broadcasts a message
        USER_JOINED, // server notifies of new user
        USER_LEFT,   // server notifies of user leaving
        DISCONNECT,  // client disconnecting
        ERROR_MSG    // error message
    };

    std::string message_type_to_string(MessageType type);
    MessageType string_to_message_type(const std::string& str);
} // namespace chat
