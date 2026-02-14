#include <stdexcept>
#include "chat/common/types.hpp"

namespace chat
{
    std::string message_type_to_string(const MessageType type)
    {
        switch (type)
        {
            case MessageType::CONNECT: return "CONNECT";
            case MessageType::CONNECT_ACK: return "CONNECT_ACK";
            case MessageType::INIT: return "INIT";
            case MessageType::MESSAGE: return "MESSAGE";
            case MessageType::BROADCAST: return "BROADCAST";
            case MessageType::USER_JOINED: return "USER_JOINED";
            case MessageType::USER_LEFT: return "USER_LEFT";
            case MessageType::DISCONNECT: return "DISCONNECT";
            case MessageType::ERROR_MSG: return "ERROR";
            default: throw std::runtime_error("Unknown message type");
        }
    }

    MessageType string_to_message_type(const std::string& str)
    {
        if (str == "CONNECT") return MessageType::CONNECT;
        if (str == "CONNECT_ACK") return MessageType::CONNECT_ACK;
        if (str == "INIT") return MessageType::INIT;
        if (str == "MESSAGE") return MessageType::MESSAGE;
        if (str == "BROADCAST") return MessageType::BROADCAST;
        if (str == "USER_JOINED") return MessageType::USER_JOINED;
        if (str == "USER_LEFT") return MessageType::USER_LEFT;
        if (str == "DISCONNECT") return MessageType::DISCONNECT;
        if (str == "ERROR") return MessageType::ERROR_MSG;
        throw std::runtime_error("Unknown message type: " + str);
    }
} // namespace chat
