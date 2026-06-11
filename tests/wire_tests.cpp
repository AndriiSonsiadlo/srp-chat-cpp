#include "chat/common/buffer.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"
#include "chat/common/types.hpp"

#include <gtest/gtest.h>

namespace chat
{
    TEST(WireTest, Uint32IsLittleEndian)
    {
        BufferWriter w;
        w.write(uint32_t{0x01020304});
        ASSERT_EQ(w.data.size(), 4u);
        EXPECT_EQ(w.data[0], 0x04);
        EXPECT_EQ(w.data[1], 0x03);
        EXPECT_EQ(w.data[2], 0x02);
        EXPECT_EQ(w.data[3], 0x01);
    }

    TEST(WireTest, SignedRoundTripPreservesNegativeValues)
    {
        BufferWriter w;
        w.write(int64_t{-1234567890123LL});

        BufferReader r(w.data);
        EXPECT_EQ(r.read<int64_t>(), -1234567890123LL);
    }

    TEST(WireTest, HeaderRoundTrip)
    {
        const MsgHeader in{.type = static_cast<uint16_t>(MessageType::BROADCAST), .size = 300u};
        const MsgHeader out = decode_header(encode_header(in));

        EXPECT_EQ(out.type, in.type);
        EXPECT_EQ(out.size, in.size);
        EXPECT_EQ(MsgHeader::kWireSize, 6u);
    }

    TEST(WireTest, TruncatedIntegerThrows)
    {
        const std::vector<uint8_t> truncated{0x01, 0x02};
        BufferReader r(truncated);
        EXPECT_THROW((void)r.read<uint32_t>(), std::runtime_error);
    }

    TEST(WireTest, TruncatedStringBodyThrows)
    {
        BufferWriter w;
        w.write(uint32_t{16}); // claims 16 bytes
        w.write_bytes({'a', 'b', 'c'});

        BufferReader r(w.data);
        EXPECT_THROW((void)r.read_string(), std::runtime_error);
    }

    TEST(WireTest, OversizedStringLengthIsRejected)
    {
        BufferWriter w;
        w.write(static_cast<uint32_t>(kMaxStringLength + 1));

        BufferReader r(w.data);
        EXPECT_THROW((void)r.read_string(), std::runtime_error);
    }

    TEST(WireTest, OversizedVectorCountIsRejectedWithoutAllocating)
    {
        // A four-byte count claiming ~4 billion elements must be refused before
        // reserve() is reached, not after.
        BufferWriter w;
        w.write(uint32_t{0xFFFFFFFFu});

        EXPECT_THROW((void)Protocol::decode<InitMsg>(w.data), std::runtime_error);
    }

    TEST(WireTest, WritingAnOversizedStringIsRejected)
    {
        const std::string huge(kMaxStringLength + 1, 'x');
        BufferWriter w;
        EXPECT_THROW(w.write_string(huge), std::runtime_error);
    }

    TEST(WireTest, SrpInitCarriesProtocolVersionFirst)
    {
        const auto packet = Protocol::encode(
            MessageType::SRP_INIT,
            SrpInitMsg{kProtocolVersion, "alice", "QUJD"});

        const std::vector<uint8_t> payload(packet.begin() + MsgHeader::kWireSize, packet.end());
        const auto decoded = Protocol::decode<SrpInitMsg>(payload);

        EXPECT_EQ(decoded.protocol_version, kProtocolVersion);
        EXPECT_EQ(decoded.username, "alice");
        EXPECT_EQ(decoded.A_b64, "QUJD");
    }

    TEST(WireTest, RoomListRoundTrip)
    {
        const RoomListMsg original{{
            RoomInfo{"lobby", 3, 0},
            RoomInfo{"Dev-Team", 1, 1},
        }};

        const auto packet  = Protocol::encode(MessageType::ROOM_LIST, original);
        const auto payload = std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        const auto decoded = Protocol::decode<RoomListMsg>(payload);

        ASSERT_EQ(decoded.rooms.size(), 2u);
        EXPECT_EQ(decoded.rooms[0].name, "lobby");
        EXPECT_EQ(decoded.rooms[0].user_count, 3u);
        EXPECT_EQ(decoded.rooms[0].has_password, 0);
        EXPECT_EQ(decoded.rooms[1].name, "Dev-Team");
        EXPECT_EQ(decoded.rooms[1].user_count, 1u);
        EXPECT_EQ(decoded.rooms[1].has_password, 1);
    }

    TEST(WireTest, EmptyRoomListRoundTrip)
    {
        const RoomListMsg original{};
        const auto packet  = Protocol::encode(MessageType::ROOM_LIST, original);
        const auto payload = std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        EXPECT_TRUE(Protocol::decode<RoomListMsg>(payload).rooms.empty());
    }

    TEST(WireTest, RoomJoinAndCreateRoundTrip)
    {
        const RoomJoinMsg join{"dev", "c2VhbGVk"};
        auto packet  = Protocol::encode(MessageType::ROOM_JOIN, join);
        auto payload = std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        const auto decoded_join = Protocol::decode<RoomJoinMsg>(payload);
        EXPECT_EQ(decoded_join.name, "dev");
        EXPECT_EQ(decoded_join.password_ct_b64, "c2VhbGVk");

        const RoomCreateMsg create{"public-room", ""};
        packet  = Protocol::encode(MessageType::ROOM_CREATE, create);
        payload = std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        const auto decoded_create = Protocol::decode<RoomCreateMsg>(payload);
        EXPECT_EQ(decoded_create.name, "public-room");
        EXPECT_TRUE(decoded_create.password_ct_b64.empty());
    }

    TEST(WireTest, InitCarriesRoomName)
    {
        InitMsg original;
        original.room = "dev";
        original.messages.push_back(HistoryEntry{"alice", "c2VhbGVk", 1234});
        original.users.push_back(User{"alice", "id-a"});

        const auto packet  = Protocol::encode(MessageType::INIT, original);
        const auto payload = std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        const auto decoded = Protocol::decode<InitMsg>(payload);

        EXPECT_EQ(decoded.room, "dev");
        ASSERT_EQ(decoded.messages.size(), 1u);
        EXPECT_EQ(decoded.messages[0].username, "alice");
        ASSERT_EQ(decoded.users.size(), 1u);
        EXPECT_EQ(decoded.users[0].username, "alice");
    }
} // namespace chat
