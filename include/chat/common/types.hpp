#pragma once

#include <string>
#include <chrono>
#include <vector>
#include <cstring>
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

    struct User
    {
        std::string username;
        std::string user_id;

        auto as_tuple() const
        {
            return std::tie(username, user_id);
        }
    };

    struct Message
    {
        std::string username;
        std::string text;
        std::chrono::system_clock::time_point timestamp;

        auto as_tuple() const
        {
            return std::tie(username, text);
        }
    };

    enum class MessageType : uint16_t
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

    class BufferWriter
    {
    public:
        std::vector<uint8_t> data;

        template <typename T>
        void write(T v)
        {
            static_assert(std::is_trivially_copyable_v<T>);
            uint8_t* p = reinterpret_cast<uint8_t*>(&v);
            data.insert(data.end(), p, p + sizeof(T));
        }

        void write_string(const std::string& s)
        {
            uint32_t len = static_cast<uint32_t>(s.size());
            write(len);
            data.insert(data.end(), s.begin(), s.end());
        }
    };

    class BufferReader
    {
    public:
        const uint8_t* p;

        explicit BufferReader(const std::vector<uint8_t>& b) : p(b.data())
        {
        }

        template <typename T>
        T read()
        {
            T v;
            std::memcpy(&v, p, sizeof(T));
            p += sizeof(T);
            return v;
        }

        std::string read_string()
        {
            uint32_t len = read<uint32_t>();
            std::string s(reinterpret_cast<const char*>(p), len);
            p += len;
            return s;
        }
    };

    inline std::vector<uint8_t> make_packet(MessageType type, const std::vector<uint8_t>& payload)
    {
        MsgHeader h;
        h.type = static_cast<uint16_t>(type);
        h.size = static_cast<uint32_t>(payload.size());

        std::vector<uint8_t> out(sizeof(MsgHeader) + payload.size());
        std::memcpy(out.data(), &h, sizeof(h));
        std::memcpy(out.data() + sizeof(h), payload.data(), payload.size());

        return out;
    }

    std::string message_type_to_string(MessageType type);
    MessageType string_to_message_type(const std::string& str);
} // namespace chat
