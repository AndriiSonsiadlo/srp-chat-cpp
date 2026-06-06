#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <stdexcept>

namespace chat
{
    // Hard limits applied while decoding untrusted input, before any allocation.
    inline constexpr uint32_t kMaxStringLength = 65536u;
    inline constexpr uint32_t kMaxVectorCount  = 1024u;

    class BufferWriter
    {
    public:
        std::vector<uint8_t> data;

        // Integers are written little-endian, byte by byte, so the wire format
        // depends on neither host byte order nor struct layout.
        template <typename T>
        void write(const T& value)
        {
            static_assert(std::is_integral_v<T>, "BufferWriter::write supports integral types only");

            auto bits = static_cast<std::make_unsigned_t<T>>(value);
            for (size_t i = 0; i < sizeof(T); ++i) {
                data.push_back(static_cast<uint8_t>(bits & 0xFFu));
                bits = static_cast<std::make_unsigned_t<T>>(bits >> 8);
            }
        }

        void write_string(const std::string& str);
        void write_bytes(const std::vector<uint8_t>& bytes);
    };

    class BufferReader
    {
    public:
        const std::vector<uint8_t>& data;
        size_t pos = 0;

        explicit BufferReader(const std::vector<uint8_t>& d);

        template <typename T>
        T read()
        {
            static_assert(std::is_integral_v<T>, "BufferReader::read supports integral types only");

            if (sizeof(T) > data.size() - pos)
                throw std::runtime_error("Buffer underflow");

            std::make_unsigned_t<T> bits = 0;
            for (size_t i = 0; i < sizeof(T); ++i)
                bits = static_cast<std::make_unsigned_t<T>>(
                    bits | (static_cast<std::make_unsigned_t<T>>(data[pos + i]) << (8 * i)));

            pos += sizeof(T);
            return static_cast<T>(bits);
        }

        std::string read_string();
        void read_bytes(uint8_t* dest, size_t count);
    };
}
