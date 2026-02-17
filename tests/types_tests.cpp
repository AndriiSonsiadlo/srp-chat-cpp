#include <gtest/gtest.h>

#include "chat/common/types.hpp"

using namespace chat;

class TypesTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

TEST_F(TypesTest, MessageTypeToStringConnect)
{
    std::string result = message_type_to_string(MessageType::CONNECT);
    EXPECT_EQ(result, "CONNECT");
}

TEST_F(TypesTest, MessageTypeToStringConnectAck)
{
    std::string result = message_type_to_string(MessageType::CONNECT_ACK);
    EXPECT_EQ(result, "CONNECT_ACK");
}

TEST_F(TypesTest, MessageTypeToStringInit)
{
    std::string result = message_type_to_string(MessageType::INIT);
    EXPECT_EQ(result, "INIT");
}

TEST_F(TypesTest, MessageTypeToStringMessage)
{
    std::string result = message_type_to_string(MessageType::MESSAGE);
    EXPECT_EQ(result, "MESSAGE");
}

TEST_F(TypesTest, MessageTypeToStringBroadcast)
{
    std::string result = message_type_to_string(MessageType::BROADCAST);
    EXPECT_EQ(result, "BROADCAST");
}

TEST_F(TypesTest, MessageTypeToStringUserJoined)
{
    std::string result = message_type_to_string(MessageType::USER_JOINED);
    EXPECT_EQ(result, "USER_JOINED");
}

TEST_F(TypesTest, MessageTypeToStringUserLeft)
{
    std::string result = message_type_to_string(MessageType::USER_LEFT);
    EXPECT_EQ(result, "USER_LEFT");
}

TEST_F(TypesTest, MessageTypeToStringDisconnect)
{
    std::string result = message_type_to_string(MessageType::DISCONNECT);
    EXPECT_EQ(result, "DISCONNECT");
}

TEST_F(TypesTest, MessageTypeToStringError)
{
    std::string result = message_type_to_string(MessageType::ERROR_MSG);
    EXPECT_EQ(result, "ERROR");
}

TEST_F(TypesTest, StringToMessageTypeConnect)
{
    MessageType result = string_to_message_type("CONNECT");
    EXPECT_EQ(result, MessageType::CONNECT);
}

TEST_F(TypesTest, StringToMessageTypeConnectAck)
{
    MessageType result = string_to_message_type("CONNECT_ACK");
    EXPECT_EQ(result, MessageType::CONNECT_ACK);
}

TEST_F(TypesTest, StringToMessageTypeInit)
{
    MessageType result = string_to_message_type("INIT");
    EXPECT_EQ(result, MessageType::INIT);
}

TEST_F(TypesTest, StringToMessageTypeMessage)
{
    MessageType result = string_to_message_type("MESSAGE");
    EXPECT_EQ(result, MessageType::MESSAGE);
}

TEST_F(TypesTest, StringToMessageTypeBroadcast)
{
    MessageType result = string_to_message_type("BROADCAST");
    EXPECT_EQ(result, MessageType::BROADCAST);
}

TEST_F(TypesTest, StringToMessageTypeUserJoined)
{
    MessageType result = string_to_message_type("USER_JOINED");
    EXPECT_EQ(result, MessageType::USER_JOINED);
}

TEST_F(TypesTest, StringToMessageTypeUserLeft)
{
    MessageType result = string_to_message_type("USER_LEFT");
    EXPECT_EQ(result, MessageType::USER_LEFT);
}

TEST_F(TypesTest, StringToMessageTypeDisconnect)
{
    MessageType result = string_to_message_type("DISCONNECT");
    EXPECT_EQ(result, MessageType::DISCONNECT);
}

TEST_F(TypesTest, StringToMessageTypeError)
{
    MessageType result = string_to_message_type("ERROR");
    EXPECT_EQ(result, MessageType::ERROR_MSG);
}

TEST_F(TypesTest, StringToMessageTypeInvalid)
{
    EXPECT_THROW({
                 string_to_message_type("INVALID_TYPE");
                 }, std::runtime_error);
}

TEST_F(TypesTest, RoundtripConversion)
{
    std::vector<MessageType> types = {
        MessageType::CONNECT,
        MessageType::CONNECT_ACK,
        MessageType::INIT,
        MessageType::MESSAGE,
        MessageType::BROADCAST,
        MessageType::USER_JOINED,
        MessageType::USER_LEFT,
        MessageType::DISCONNECT,
        MessageType::ERROR_MSG
    };

    for (MessageType type : types)
    {
        std::string str            = message_type_to_string(type);
        MessageType converted_back = string_to_message_type(str);
        EXPECT_EQ(converted_back, type);
    }
}

TEST_F(TypesTest, UserStructCreation)
{
    User user{"alice", "user_123"};

    EXPECT_EQ(user.username, "alice");
    EXPECT_EQ(user.user_id, "user_123");
}

TEST_F(TypesTest, UserStructCopy)
{
    User user1{"alice", "user_123"};
    User user2 = user1;

    EXPECT_EQ(user2.username, "alice");
    EXPECT_EQ(user2.user_id, "user_123");

    user2.username = "bob";
    EXPECT_EQ(user1.username, "alice");
    EXPECT_EQ(user2.username, "bob");
}

TEST_F(TypesTest, MessageStructCreation)
{
    auto now = std::chrono::system_clock::now();
    Message msg{"alice", "Hello world", now};

    EXPECT_EQ(msg.username, "alice");
    EXPECT_EQ(msg.text, "Hello world");
    EXPECT_EQ(msg.timestamp, now);
}

TEST_F(TypesTest, MessageStructCopy)
{
    auto now = std::chrono::system_clock::now();
    Message msg1{"alice", "Hello", now};
    Message msg2 = msg1;

    EXPECT_EQ(msg2.username, "alice");
    EXPECT_EQ(msg2.text, "Hello");
    EXPECT_EQ(msg2.timestamp, now);
}

TEST_F(TypesTest, MessageStructWithEmptyText)
{
    auto now = std::chrono::system_clock::now();
    Message msg{"alice", "", now};

    EXPECT_EQ(msg.username, "alice");
    EXPECT_EQ(msg.text, "");
}

TEST_F(TypesTest, MessageStructWithLongText)
{
    auto now = std::chrono::system_clock::now();
    std::string long_text(1000, 'a');
    Message msg{"alice", long_text, now};

    EXPECT_EQ(msg.username, "alice");
    EXPECT_EQ(msg.text.length(), 1000);
    EXPECT_EQ(msg.text, long_text);
}
