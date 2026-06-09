#pragma once

#include <string>
#include <vector>
#include <array>
#include <stdexcept>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

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
            if (count > kMaxVectorCount)
                throw std::runtime_error("Vector field exceeds maximum element count");

            std::vector<T> result;
            result.reserve(count);

            for (uint32_t i = 0; i < count; ++i) {
                const auto item_size = r.read<uint32_t>();
                if (item_size > kMaxStringLength)
                    throw std::runtime_error("Vector element exceeds maximum size");

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
            const auto raw = encode_header(MsgHeader{
                .type = static_cast<uint16_t>(type),
                .size = static_cast<uint32_t>(payload.size())
            });

            std::vector<uint8_t> packet;
            packet.reserve(MsgHeader::kWireSize + payload.size());
            packet.insert(packet.end(), raw.begin(), raw.end());
            packet.insert(packet.end(), payload.begin(), payload.end());
            return packet;
        }
    };

    namespace ProtocolHelpers
    {
        inline constexpr uint32_t kMaxPayloadSize = 1024U * 1024U; // 1 MiB

        inline boost::asio::awaitable<void> async_send_packet(
            boost::asio::ip::tcp::socket& socket,
            const std::vector<uint8_t>& packet)
        {
            co_await boost::asio::async_write(
                socket, boost::asio::buffer(packet), boost::asio::use_awaitable);
        }

        inline boost::asio::awaitable<std::pair<MessageType, std::vector<uint8_t>>>
        async_receive_packet(boost::asio::ip::tcp::socket& socket)
        {
            std::array<uint8_t, MsgHeader::kWireSize> raw{};
            co_await boost::asio::async_read(
                socket, boost::asio::buffer(raw), boost::asio::use_awaitable);

            const auto header = decode_header(raw);
            if (header.size > kMaxPayloadSize)
                throw std::runtime_error("Incoming payload exceeds maximum allowed size");

            std::vector<uint8_t> payload(header.size);
            if (header.size > 0)
                co_await boost::asio::async_read(
                    socket, boost::asio::buffer(payload), boost::asio::use_awaitable);

            co_return std::pair{static_cast<MessageType>(header.type), std::move(payload)};
        }
    }
} // namespace chat
