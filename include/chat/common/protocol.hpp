#pragma once

#include <string>
#include <vector>
#include <stdexcept>

#include <boost/asio.hpp>

#include "chat/common/types.hpp"
#include "chat/common/buffer.hpp"

namespace chat
{
    class Protocol
    {
    public:
        template <class T>
        static std::vector<uint8_t> encode(MessageType type, const T& msg)
        {
            auto payload = serialize_object(msg);
            return make_packet(type, payload);
        }

        static std::vector<uint8_t> encode(const MessageType type)
        {
            return make_packet(type, {});
        }

        template <class T>
        static T decode(const std::vector<uint8_t>& payload)
        {
            return deserialize_object<T>(payload);
        }

    private:
        template <class T>
        static void write_field(BufferWriter& w, const T& v)
        {
            w.write(v);
        }

        static void write_field(BufferWriter& w, const std::string& v)
        {
            w.write_string(v);
        }

        template <class T>
        static void write_field(BufferWriter& w, const std::vector<T>& v)
        {
            w.write(static_cast<uint32_t>(v.size()));
            for (const auto& item : v) {
                auto item_data = serialize_object(item);
                w.write(static_cast<uint32_t>(item_data.size()));
                w.write_bytes(item_data);
            }
        }

        template <class T>
        static T read_field(BufferReader& r, std::type_identity<T>)
        {
            return r.read<T>();
        }

        static std::string read_field(BufferReader& r, std::type_identity<std::string>)
        {
            return r.read_string();
        }

        template <class T>
        static std::vector<T> read_field(BufferReader& r, std::type_identity<std::vector<T>>)
        {
            const auto count = r.read<uint32_t>();
            std::vector<T> result;
            result.reserve(count);

            for (uint32_t i = 0; i < count; ++i) {
                const auto item_size = r.read<uint32_t>();
                std::vector<uint8_t> item_data(item_size);
                r.read_bytes(item_data.data(), item_size);
                result.push_back(deserialize_object<T>(item_data));
            }

            return result;
        }

        template <class T>
        static std::vector<uint8_t> serialize_object(const T& obj)
        {
            BufferWriter w;

            std::apply([&](auto const&... fields)
            {
                (write_field(w, fields), ...);
            }, obj.as_tuple());

            return std::move(w.data);
        }

        template <class T>
        static T deserialize_object(const std::vector<uint8_t>& data)
        {
            BufferReader r(data);
            T obj;

            std::apply([&](auto&... fields)
            {
                using swallow = int[];
                (void)swallow{
                    0, (fields = read_field(r, std::type_identity<std::remove_reference_t<decltype(fields)>>{}), 0)...
                };
            }, obj.as_tuple());

            return obj;
        }

        static std::vector<uint8_t> make_packet(MessageType type, const std::vector<uint8_t>& payload)
        {
            std::vector<uint8_t> packet(sizeof(MsgHeader) + payload.size());

            const MsgHeader header{
                .type = static_cast<uint16_t>(type),
                .size = static_cast<uint32_t>(payload.size())
            };

            std::memcpy(packet.data(), &header, sizeof(MsgHeader));
            if (!payload.empty())
                std::memcpy(packet.data() + sizeof(MsgHeader), payload.data(), payload.size());

            return packet;
        }
    };

    namespace ProtocolHelpers
    {
        inline constexpr uint32_t kMaxPayloadSize = 1024U * 1024U; // 1 MiB

        std::vector<uint8_t> make_empty_packet(MessageType type);

        inline void send_packet(boost::asio::ip::tcp::socket& socket, const std::vector<uint8_t>& packet)
        {
            boost::asio::write(socket, boost::asio::buffer(packet));
        }

        inline std::pair<MessageType, std::vector<uint8_t>> receive_packet(boost::asio::ip::tcp::socket& socket)
        {
            // read header first
            MsgHeader header{};
            boost::asio::read(socket, boost::asio::buffer(&header, sizeof(MsgHeader)));
            if (header.size > kMaxPayloadSize)
                throw std::runtime_error("Incoming payload exceeds maximum allowed size");

            // read payload
            std::vector<uint8_t> payload(header.size);
            if (header.size > 0)
                boost::asio::read(socket, boost::asio::buffer(payload));

            return {static_cast<MessageType>(header.type), std::move(payload)};
        }
    }
} // namespace chat
