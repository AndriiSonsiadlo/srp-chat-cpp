#include "chat/common/buffer.hpp"

namespace chat
{
    void BufferWriter::write_string(const std::string& str)
    {
        if (str.size() > kMaxStringLength)
            throw std::runtime_error("String field exceeds maximum length");

        write(static_cast<uint32_t>(str.size()));

        const size_t old_size = data.size();
        data.resize(old_size + str.size());
        std::memcpy(data.data() + old_size, str.data(), str.size());
    }

    void BufferWriter::write_bytes(const std::vector<uint8_t>& bytes)
    {
        const size_t old_size = data.size();
        data.resize(old_size + bytes.size());
        std::memcpy(data.data() + old_size, bytes.data(), bytes.size());
    }

    BufferReader::BufferReader(const std::vector<uint8_t>& d)
        : data(d)
    {
    }

    std::string BufferReader::read_string()
    {
        const auto length = read<uint32_t>();

        if (length > kMaxStringLength)
            throw std::runtime_error("String field exceeds maximum length");

        if (length > data.size() - pos)
            throw std::runtime_error("Buffer underflow");

        std::string str(reinterpret_cast<const char*>(data.data() + pos), length);
        pos += length;
        return str;
    }

    void BufferReader::read_bytes(uint8_t* dest, const size_t count)
    {
        if (count > data.size() - pos)
            throw std::runtime_error("Buffer underflow");

        std::memcpy(dest, data.data() + pos, count);
        pos += count;
    }
} // namespace chat
