#include "chat/common/protocol.hpp"
#include "chat/common/messages.hpp"

#include <gtest/gtest.h>
#include <chrono>

namespace chat
{
    class ProtocolTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
        }

        void TearDown() override
        {
        }

        MsgHeader extract_header(const std::vector<uint8_t>& packet)
        {
            EXPECT_GE(packet.size(), sizeof(MsgHeader));
            MsgHeader header;
            std::memcpy(&header, packet.data(), sizeof(MsgHeader));
            return header;
        }

        std::vector<uint8_t> extract_payload(const std::vector<uint8_t>& packet)
        {
            EXPECT_GE(packet.size(), sizeof(MsgHeader));
            return std::vector<uint8_t>(packet.begin() + sizeof(MsgHeader), packet.end());
        }
    };

    TEST_F(ProtocolTest, EncodeDecodeConnect)
    {
        std::string username = "alice";

        auto packet = Protocol::encode(MessageType::CONNECT, ConnectMsg{username});

        auto header = extract_header(packet);
        EXPECT_EQ(header.type, static_cast<uint16_t>(MessageType::CONNECT));
        EXPECT_GT(header.size, 0);

        auto payload = extract_payload(packet);
        EXPECT_EQ(payload.size(), header.size);

        auto [decoded] = Protocol::decode<ConnectMsg>(payload);
        EXPECT_EQ(decoded, username);
    }

    TEST_F(ProtocolTest, EncodeDecodeConnectSpecialChars)
    {
        std::string username = "alice|bob:test";

        auto packet  = Protocol::encode(MessageType::CONNECT, ConnectMsg{username});
        auto payload = extract_payload(packet);

        auto [decoded] = Protocol::decode<ConnectMsg>(payload);
        EXPECT_EQ(decoded, username);
    }

    TEST_F(ProtocolTest, EncodeDecodeConnectAck)
    {
        std::string user_id = "user_123";

        auto packet = Protocol::encode(MessageType::CONNECT_ACK, ConnectAckMsg{user_id});

        auto header = extract_header(packet);
        EXPECT_EQ(header.type, static_cast<uint16_t>(MessageType::CONNECT_ACK));

        auto payload   = extract_payload(packet);
        auto [decoded] = Protocol::decode<ConnectAckMsg>(payload);
        EXPECT_EQ(decoded, user_id);
    }

    TEST_F(ProtocolTest, EncodeDecodeMessage)
    {
        std::string text = "Hello, world!";

        auto packet = Protocol::encode(MessageType::MESSAGE, TextMsg{text});

        auto header = extract_header(packet);
        EXPECT_EQ(header.type, static_cast<uint16_t>(MessageType::MESSAGE));

        auto payload   = extract_payload(packet);
        auto [decoded] = Protocol::decode<TextMsg>(payload);
        EXPECT_EQ(decoded, text);
    }

    TEST_F(ProtocolTest, EncodeDecodeMessageWithNewline)
    {
        std::string text = "Line 1\nLine 2\nLine 3";

        auto packet  = Protocol::encode(MessageType::MESSAGE, TextMsg{text});
        auto payload = extract_payload(packet);

        auto [decoded] = Protocol::decode<TextMsg>(payload);
        EXPECT_EQ(decoded, text);
    }

    TEST_F(ProtocolTest, EncodeDecodeBroadcast)
    {
        std::string username = "alice";
        std::string text     = "Hello!";
        int64_t timestamp_ms = 1234567890123LL;

        auto packet = Protocol::encode(MessageType::BROADCAST, BroadcastMsg{username, text, timestamp_ms});

        auto header = extract_header(packet);
        EXPECT_EQ(header.type, static_cast<uint16_t>(MessageType::BROADCAST));

        auto payload                                             = extract_payload(packet);
        auto [decoded_username, decoded_text, decoded_timestamp] = Protocol::decode<BroadcastMsg>(payload);

        EXPECT_EQ(decoded_username, username);
        EXPECT_EQ(decoded_text, text);
        EXPECT_EQ(decoded_timestamp, timestamp_ms);
    }

    TEST_F(ProtocolTest, EncodeDecodeUserJoined)
    {
        std::string username = "bob";
        std::string user_id  = "user_456";

        auto packet = Protocol::encode(MessageType::USER_JOINED, UserJoinedMsg{username, user_id});

        auto header = extract_header(packet);
        EXPECT_EQ(header.type, static_cast<uint16_t>(MessageType::USER_JOINED));

        auto payload = extract_payload(packet);

        auto [decoded_username, decoded_user_id] = Protocol::decode<UserJoinedMsg>(payload);

        EXPECT_EQ(decoded_username, username);
        EXPECT_EQ(decoded_user_id, user_id);
    }

    TEST_F(ProtocolTest, EncodeDecodeUserLeft)
    {
        std::string username = "charlie";

        auto packet = Protocol::encode(MessageType::USER_LEFT, UserLeftMsg{username});

        auto header = extract_header(packet);
        EXPECT_EQ(header.type, static_cast<uint16_t>(MessageType::USER_LEFT));

        auto payload   = extract_payload(packet);
        auto [decoded] = Protocol::decode<UserLeftMsg>(payload);
        EXPECT_EQ(decoded, username);
    }

    TEST_F(ProtocolTest, EncodeDisconnect)
    {
        auto packet = Protocol::encode(MessageType::DISCONNECT);

        auto header = extract_header(packet);
        EXPECT_EQ(header.type, static_cast<uint16_t>(MessageType::DISCONNECT));
        EXPECT_EQ(header.size, 0); // No payload
    }

    TEST_F(ProtocolTest, EncodeDecodeError)
    {
        std::string error_msg = "Connection failed";

        auto packet = Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{error_msg});

        auto header = extract_header(packet);
        EXPECT_EQ(header.type, static_cast<uint16_t>(MessageType::ERROR_MSG));

        auto payload   = extract_payload(packet);
        auto [decoded] = Protocol::decode<ErrorMsg>(payload);
        EXPECT_EQ(decoded, error_msg);
    }

    TEST_F(ProtocolTest, EncodeDecodeInitEmpty)
    {
        std::vector<Message> messages;
        std::vector<User> users;

        auto packet = Protocol::encode(MessageType::INIT, InitMsg{messages, users});

        auto header = extract_header(packet);
        EXPECT_EQ(header.type, static_cast<uint16_t>(MessageType::INIT));

        auto payload                           = extract_payload(packet);
        auto [decoded_messages, decoded_users] = Protocol::decode<InitMsg>(payload);

        EXPECT_TRUE(decoded_messages.empty());
        EXPECT_TRUE(decoded_users.empty());
    }

    TEST_F(ProtocolTest, EncodeDecodeInitWithData)
    {
        std::vector<Message> messages = {
            {"alice", "Hello", std::chrono::system_clock::now()},
            {"bob", "Hi there", std::chrono::system_clock::now()}
        };
        std::vector<User> users = {
            {"alice", "user_1"},
            {"bob", "user_2"},
            {"charlie", "user_3"}
        };

        auto packet  = Protocol::encode(MessageType::INIT, InitMsg{messages, users});
        auto payload = extract_payload(packet);

        auto [decoded_messages, decoded_users] = Protocol::decode<InitMsg>(payload);

        ASSERT_EQ(decoded_messages.size(), 2);
        EXPECT_EQ(decoded_messages[0].username, "alice");
        EXPECT_EQ(decoded_messages[0].text, "Hello");
        EXPECT_EQ(decoded_messages[1].username, "bob");
        EXPECT_EQ(decoded_messages[1].text, "Hi there");

        ASSERT_EQ(decoded_users.size(), 3);
        EXPECT_EQ(decoded_users[0].username, "alice");
        EXPECT_EQ(decoded_users[0].user_id, "user_1");
        EXPECT_EQ(decoded_users[1].username, "bob");
        EXPECT_EQ(decoded_users[1].user_id, "user_2");
        EXPECT_EQ(decoded_users[2].username, "charlie");
        EXPECT_EQ(decoded_users[2].user_id, "user_3");
    }

    TEST_F(ProtocolTest, PacketSizeCorrect)
    {
        std::string text = "Test message";
        auto packet      = Protocol::encode(MessageType::MESSAGE, TextMsg{text});

        auto header  = extract_header(packet);
        auto payload = extract_payload(packet);

        EXPECT_EQ(packet.size(), sizeof(MsgHeader) + header.size);
        EXPECT_EQ(payload.size(), header.size);
    }

    TEST_F(ProtocolTest, EmptyStringHandling)
    {
        std::string empty = "";

        auto packet  = Protocol::encode(MessageType::MESSAGE, TextMsg{empty});
        auto payload = extract_payload(packet);

        auto [decoded] = Protocol::decode<TextMsg>(payload);
        EXPECT_EQ(decoded, empty);
    }

    TEST_F(ProtocolTest, LongStringHandling)
    {
        std::string long_text(10000, 'a');

        auto packet  = Protocol::encode(MessageType::MESSAGE, TextMsg{long_text});
        auto payload = extract_payload(packet);

        auto [decoded] = Protocol::decode<TextMsg>(payload);
        EXPECT_EQ(decoded, long_text);
    }

    TEST_F(ProtocolTest, SpecialCharacters)
    {
        std::string special = "Test|with:special\nchars\\and\ttabs";

        auto packet  = Protocol::encode(MessageType::MESSAGE, TextMsg{special});
        auto payload = extract_payload(packet);

        auto [decoded] = Protocol::decode<TextMsg>(payload);
        EXPECT_EQ(decoded, special);
    }

    TEST_F(ProtocolTest, BufferWriterReader)
    {
        BufferWriter w;
        w.write_string("test");
        w.write(static_cast<int32_t>(42));
        w.write(static_cast<uint16_t>(123));

        BufferReader r(w.data);
        std::string str = r.read_string();
        int32_t i32     = r.read<int32_t>();
        uint16_t u16    = r.read<uint16_t>();

        EXPECT_EQ(str, "test");
        EXPECT_EQ(i32, 42);
        EXPECT_EQ(u16, 123);
    }
} // namespace chat
