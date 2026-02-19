#include "chat/common/protocol.hpp"

#include <chrono>

namespace chat
{
    template <typename T>
    std::vector<uint8_t> serialize(const T& obj)
    {
        BufferWriter w;
        std::apply([&](auto&&... fields)
        {
            (w.write_string(fields), ...);
        }, obj.as_tuple());
        return std::move(w.data);
    }

    template <typename T>
    T deserialize(const std::vector<uint8_t>& data)
    {
        BufferReader r(data);
        return r.read<T>();
    }

    // CONNECT: username
    std::vector<uint8_t> Protocol::encode_connect(const std::string& username)
    {
        BufferWriter w;
        w.write_string(username);
        return make_packet(MessageType::CONNECT, w.data);
    }

    std::string Protocol::decode_connect(const std::vector<uint8_t>& payload)
    {
        BufferReader r(payload);
        return r.read_string();
    }

    // CONNECT_ACK: user_id
    std::vector<uint8_t> Protocol::encode_connect_ack(const std::string& user_id)
    {
        BufferWriter w;
        w.write_string(user_id);
        return make_packet(MessageType::CONNECT_ACK, w.data);
    }

    std::string Protocol::decode_connect_ack(const std::vector<uint8_t>& payload)
    {
        BufferReader r(payload);
        return r.read_string();
    }

    // INIT: message_count, [username, text, timestamp_ms]*, user_count, [username, user_id]*
    std::vector<uint8_t> Protocol::encode_init(
        const std::vector<Message>& messages,
        const std::vector<User>& users)
    {
        BufferWriter w;

        // write messages
        w.write(static_cast<uint32_t>(messages.size()));
        for (const auto& msg : messages)
        {
            w.write_string(msg.username);
            w.write_string(msg.text);

            auto duration = msg.timestamp.time_since_epoch();
            auto millis   = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
            w.write(static_cast<int64_t>(millis));
        }

        // write users
        w.write(static_cast<uint32_t>(users.size()));
        for (const auto& user : users)
        {
            w.write_string(user.username);
            w.write_string(user.user_id);
        }

        return make_packet(MessageType::INIT, w.data);
    }

    void Protocol::decode_init(const std::vector<uint8_t>& payload,
                               std::vector<Message>& messages,
                               std::vector<User>& users)
    {
        BufferReader r(payload);

        // read messages
        uint32_t msg_count = r.read<uint32_t>();
        messages.reserve(msg_count);

        for (uint32_t i = 0; i < msg_count; ++i)
        {
            Message msg;
            msg.username = r.read_string();
            msg.text     = r.read_string();

            int64_t timestamp_ms = r.read<int64_t>();
            msg.timestamp        = std::chrono::system_clock::time_point(
                std::chrono::milliseconds(timestamp_ms));

            messages.push_back(std::move(msg));
        }

        // read users
        uint32_t user_count = r.read<uint32_t>();
        users.reserve(user_count);

        for (uint32_t i = 0; i < user_count; ++i)
        {
            User user;
            user.username = r.read_string();
            user.user_id  = r.read_string();
            users.push_back(std::move(user));
        }
    }

    // MESSAGE: text
    std::vector<uint8_t> Protocol::encode_message(const std::string& text)
    {
        BufferWriter w;
        w.write_string(text);
        return make_packet(MessageType::MESSAGE, w.data);
    }

    std::string Protocol::decode_message(const std::vector<uint8_t>& payload)
    {
        BufferReader r(payload);
        return r.read_string();
    }

    // BROADCAST: username, text, timestamp_ms
    std::vector<uint8_t> Protocol::encode_broadcast(
        const std::string& username,
        const std::string& text,
        int64_t timestamp_ms)
    {
        BufferWriter w;
        w.write_string(username);
        w.write_string(text);
        w.write(timestamp_ms);
        return make_packet(MessageType::BROADCAST, w.data);
    }

    void Protocol::decode_broadcast(const std::vector<uint8_t>& payload,
                                    std::string& username,
                                    std::string& text,
                                    int64_t& timestamp_ms)
    {
        BufferReader r(payload);
        username     = r.read_string();
        text         = r.read_string();
        timestamp_ms = r.read<int64_t>();
    }

    // USER_JOINED: username, user_id
    std::vector<uint8_t> Protocol::encode_user_joined(const std::string& username, const std::string& user_id)
    {
        BufferWriter w;
        w.write_string(username);
        w.write_string(user_id);
        return make_packet(MessageType::USER_JOINED, w.data);
    }

    void Protocol::decode_user_joined(const std::vector<uint8_t>& payload,
                                      std::string& username,
                                      std::string& user_id)
    {
        BufferReader r(payload);
        username = r.read_string();
        user_id  = r.read_string();
    }

    // USER_LEFT: username
    std::vector<uint8_t> Protocol::encode_user_left(const std::string& username)
    {
        BufferWriter w;
        w.write_string(username);
        return make_packet(MessageType::USER_LEFT, w.data);
    }

    std::string Protocol::decode_user_left(const std::vector<uint8_t>& payload)
    {
        BufferReader r(payload);
        return r.read_string();
    }

    // DISCONNECT: no payload
    std::vector<uint8_t> Protocol::encode_disconnect()
    {
        return make_packet(MessageType::DISCONNECT, {});
    }

    // ERROR: error_msg
    std::vector<uint8_t> Protocol::encode_error(const std::string& error_msg)
    {
        BufferWriter w;
        w.write_string(error_msg);
        return make_packet(MessageType::ERROR_MSG, w.data);
    }

    std::string Protocol::decode_error(const std::vector<uint8_t>& payload)
    {
        BufferReader r(payload);
        return r.read_string();
    }
} // namespace chat
