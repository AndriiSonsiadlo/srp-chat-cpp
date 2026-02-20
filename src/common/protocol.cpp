#include "chat/common/protocol.hpp"


namespace chat::ProtocolHelpers
{
    std::vector<uint8_t> make_empty_packet(MessageType type)
    {
        std::vector<uint8_t> packet(sizeof(MsgHeader));

        const MsgHeader header{
            .type = static_cast<uint16_t>(type),
            .size = 0
        };

        std::memcpy(packet.data(), &header, sizeof(MsgHeader));
        return packet;
    }
} // namespace chat::ProtocolHelpers
