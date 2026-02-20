#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <stdexcept>

namespace chat
{
    class BufferWriter
    {
    public:
        std::vector<uint8_t> data;

        template <typename T>
        void write(const T& value)
        {
            const size_t old_size = data.size();
            data.resize(old_size + sizeof(T));
            std::memcpy(data.data() + old_size, &value, sizeof(T));
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
            if (pos + sizeof(T) > data.size())
                throw std::runtime_error("Buffer underflow");

            T value;
            std::memcpy(&value, data.data() + pos, sizeof(T));
            pos += sizeof(T);
            return value;
        }

        std::string read_string();
        void read_bytes(uint8_t* dest, size_t count);
    };
}
