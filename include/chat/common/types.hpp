#pragma once

#include <string>
#include <chrono>
#include <cstdint>
#include <tuple>
#include <array>
#include <cstddef>

namespace chat
{
    inline constexpr uint16_t kProtocolVersion = 1;

    struct MsgHeader
    {
        uint16_t type; // MessageType
        uint32_t size; // payload size in bytes

        // Bytes on the wire: 2 for type, 4 for size. Deliberately not
        // sizeof(MsgHeader) — the struct is never memcpy'd into a packet.
        static constexpr size_t kWireSize = 6;
    };

    inline std::array<uint8_t, MsgHeader::kWireSize> encode_header(const MsgHeader& header)
    {
        return {
            static_cast<uint8_t>(header.type & 0xFFu),
            static_cast<uint8_t>((header.type >> 8) & 0xFFu),
            static_cast<uint8_t>(header.size & 0xFFu),
            static_cast<uint8_t>((header.size >> 8) & 0xFFu),
            static_cast<uint8_t>((header.size >> 16) & 0xFFu),
            static_cast<uint8_t>((header.size >> 24) & 0xFFu),
        };
    }

    inline MsgHeader decode_header(const std::array<uint8_t, MsgHeader::kWireSize>& raw)
    {
        return MsgHeader{
            .type = static_cast<uint16_t>(raw[0] | (raw[1] << 8)),
            .size = static_cast<uint32_t>(raw[2])
                  | (static_cast<uint32_t>(raw[3]) << 8)
                  | (static_cast<uint32_t>(raw[4]) << 16)
                  | (static_cast<uint32_t>(raw[5]) << 24),
        };
    }

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

        // NOTE: as_tuple() is retained here, despite the Task 2 brief calling for
        // its removal, because InitMsg::messages (std::vector<Message>) is still
        // serialized directly by Protocol in this task -- deleting it makes
        // Protocol::encode/decode<InitMsg> (and thus server.cpp's INIT send path,
        // plus the brief's own wire_tests.cpp OversizedVectorCountIsRejected test)
        // fail to compile, since read_field<vector<T>>'s body unconditionally
        // instantiates deserialize_object<T> regardless of the runtime early-throw
        // path. Task 7 (InitMsg::messages -> vector<HistoryEntry>) is the point
        // where Message can safely lose serialization support.
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
