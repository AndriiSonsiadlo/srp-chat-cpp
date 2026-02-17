#include <gtest/gtest.h>
#include "chat/common/protocol.hpp"
#include <chrono>

using namespace chat;

class ProtocolTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(ProtocolTest, EncodeConnect) {
    std::string result = Protocol::encode_connect("alice");
    EXPECT_EQ(result, "CONNECT|username:alice\n");
}

TEST_F(ProtocolTest, EncodeConnectWithSpecialChars) {
    std::string result = Protocol::encode_connect("alice|bob");
    EXPECT_EQ(result, "CONNECT|username:alice\\|bob\n");
}

TEST_F(ProtocolTest, EncodeConnectAck) {
    std::string result = Protocol::encode_connect_ack("user_123");
    EXPECT_EQ(result, "CONNECT_ACK|user_id:user_123\n");
}

TEST_F(ProtocolTest, EncodeMessage) {
    std::string result = Protocol::encode_message("Hello, world!");
    EXPECT_EQ(result, "MESSAGE|text:Hello, world!\n");
}

TEST_F(ProtocolTest, EncodeMessageWithNewline) {
    std::string result = Protocol::encode_message("Line 1\nLine 2");
    EXPECT_EQ(result, "MESSAGE|text:Line 1\\\nLine 2\n");
}

TEST_F(ProtocolTest, EncodeBroadcast) {
    std::string result = Protocol::encode_broadcast("alice", "Hello!", "2024-01-01T12:00:00");
    EXPECT_EQ(result, "BROADCAST|username:alice|text:Hello!|timestamp:2024-01-01T12:00:00\n");
}

TEST_F(ProtocolTest, EncodeUserJoined) {
    std::string result = Protocol::encode_user_joined("bob", "user_456");
    EXPECT_EQ(result, "USER_JOINED|username:bob|user_id:user_456\n");
}

TEST_F(ProtocolTest, EncodeUserLeft) {
    std::string result = Protocol::encode_user_left("charlie");
    EXPECT_EQ(result, "USER_LEFT|username:charlie\n");
}

TEST_F(ProtocolTest, EncodeDisconnect) {
    std::string result = Protocol::encode_disconnect();
    EXPECT_EQ(result, "DISCONNECT\n");
}

TEST_F(ProtocolTest, EncodeError) {
    std::string result = Protocol::encode_error("Connection failed");
    EXPECT_EQ(result, "ERROR|message:Connection failed\n");
}

TEST_F(ProtocolTest, EncodeInitEmpty) {
    std::vector<Message> messages;
    std::vector<User> users;

    std::string result = Protocol::encode_init(messages, users);
    EXPECT_EQ(result, "INIT|messages:|users:\n");
}

TEST_F(ProtocolTest, EncodeInitWithData) {
    std::vector<Message> messages = {
        {"alice", "Hello", std::chrono::system_clock::now()}
    };
    std::vector<User> users = {
        {"alice", "user_1"},
        {"bob", "user_2"}
    };

    std::string result = Protocol::encode_init(messages, users);

    EXPECT_TRUE(result.starts_with("INIT|"));
    EXPECT_NE(result.find("messages:"), std::string::npos);
    EXPECT_NE(result.find("users:"), std::string::npos);
    EXPECT_TRUE(result.ends_with("\n"));
}

TEST_F(ProtocolTest, ParseTypeConnect) {
    std::string msg = "CONNECT|username:alice\n";
    MessageType type = Protocol::parse_type(msg);
    EXPECT_EQ(type, MessageType::CONNECT);
}

TEST_F(ProtocolTest, ParseTypeConnectAck) {
    std::string msg = "CONNECT_ACK|user_id:user_123\n";
    MessageType type = Protocol::parse_type(msg);
    EXPECT_EQ(type, MessageType::CONNECT_ACK);
}

TEST_F(ProtocolTest, ParseTypeBroadcast) {
    std::string msg = "BROADCAST|username:alice|text:Hello\n";
    MessageType type = Protocol::parse_type(msg);
    EXPECT_EQ(type, MessageType::BROADCAST);
}

TEST_F(ProtocolTest, ParseTypeDisconnect) {
    std::string msg = "DISCONNECT\n";
    MessageType type = Protocol::parse_type(msg);
    EXPECT_EQ(type, MessageType::DISCONNECT);
}

TEST_F(ProtocolTest, ParseFieldUsername) {
    std::string msg = "CONNECT|username:alice\n";
    std::string username = Protocol::parse_field(msg, "username");
    EXPECT_EQ(username, "alice");
}

TEST_F(ProtocolTest, ParseFieldText) {
    std::string msg = "MESSAGE|text:Hello, world!\n";
    std::string text = Protocol::parse_field(msg, "text");
    EXPECT_EQ(text, "Hello, world!");
}

TEST_F(ProtocolTest, ParseFieldMultiple) {
    std::string msg = "BROADCAST|username:alice|text:Hello|timestamp:2024-01-01T12:00:00\n";

    std::string username = Protocol::parse_field(msg, "username");
    std::string text = Protocol::parse_field(msg, "text");
    std::string timestamp = Protocol::parse_field(msg, "timestamp");

    EXPECT_EQ(username, "alice");
    EXPECT_EQ(text, "Hello");
    EXPECT_EQ(timestamp, "2024-01-01T12:00:00");
}

TEST_F(ProtocolTest, ParseFieldNotFound) {
    std::string msg = "CONNECT|username:alice\n";
    std::string result = Protocol::parse_field(msg, "nonexistent");
    EXPECT_EQ(result, "");
}

TEST_F(ProtocolTest, ParseFieldWithEscapedChars) {
    std::string msg = "MESSAGE|text:Hello\\|world\\ntest\n";
    std::string text = Protocol::parse_field(msg, "text");
    EXPECT_EQ(text, "Hello");
}

TEST_F(ProtocolTest, ParseUsersEmpty) {
    std::string users_str = "";
    std::vector<User> users = Protocol::parse_users(users_str);
    EXPECT_TRUE(users.empty());
}

TEST_F(ProtocolTest, ParseUsersSingle) {
    std::string users_str = "alice,user_1";
    std::vector<User> users = Protocol::parse_users(users_str);

    ASSERT_EQ(users.size(), 1);
    EXPECT_EQ(users[0].username, "alice");
    EXPECT_EQ(users[0].user_id, "user_1");
}

TEST_F(ProtocolTest, ParseUsersMultiple) {
    std::string users_str = "alice,user_1;bob,user_2;charlie,user_3";
    std::vector<User> users = Protocol::parse_users(users_str);

    ASSERT_EQ(users.size(), 3);

    EXPECT_EQ(users[0].username, "alice");
    EXPECT_EQ(users[0].user_id, "user_1");

    EXPECT_EQ(users[1].username, "bob");
    EXPECT_EQ(users[1].user_id, "user_2");

    EXPECT_EQ(users[2].username, "charlie");
    EXPECT_EQ(users[2].user_id, "user_3");
}

TEST_F(ProtocolTest, ParseMessagesEmpty) {
    std::string messages_str = "";
    std::vector<Message> messages = Protocol::parse_messages(messages_str);
    EXPECT_TRUE(messages.empty());
}

TEST_F(ProtocolTest, ParseMessagesSingle) {
    std::string messages_str = "alice,Hello world,2024-01-01T12:00:00";
    std::vector<Message> messages = Protocol::parse_messages(messages_str);

    ASSERT_EQ(messages.size(), 1);
    EXPECT_EQ(messages[0].username, "alice");
    EXPECT_EQ(messages[0].text, "Hello world");
}

TEST_F(ProtocolTest, ParseMessagesMultiple) {
    std::string messages_str = "alice,Hello,2024-01-01T12:00:00;bob,Hi there,2024-01-01T12:01:00";
    std::vector<Message> messages = Protocol::parse_messages(messages_str);

    ASSERT_EQ(messages.size(), 2);

    EXPECT_EQ(messages[0].username, "alice");
    EXPECT_EQ(messages[0].text, "Hello");

    EXPECT_EQ(messages[1].username, "bob");
    EXPECT_EQ(messages[1].text, "Hi there");
}

TEST_F(ProtocolTest, EscapeUnescapeRoundtrip) {
    std::vector<std::string> test_strings = {
        "normal text",
        "text:with:colons",
        "text\\with\\backslashes"
    };

    for (const auto& original : test_strings) {
        std::string msg = Protocol::encode_message(original);
        std::string decoded = Protocol::parse_field(msg, "text");
        EXPECT_EQ(decoded, original) << "Failed for: " << original;
    }
}

TEST_F(ProtocolTest, CompleteMessageRoundtrip) {
    std::string original_username = "alice|special";
    std::string original_text = "Hello\nworld|test:data";
    std::string timestamp = "2024-01-01T12:00:00";

    std::string encoded = Protocol::encode_broadcast(original_username, original_text, timestamp);

    MessageType type = Protocol::parse_type(encoded);
    std::string parsed_username = Protocol::parse_field(encoded, "username");
    std::string parsed_text = Protocol::parse_field(encoded, "text");
    std::string parsed_timestamp = Protocol::parse_field(encoded, "timestamp");

    EXPECT_EQ(type, MessageType::BROADCAST);
    EXPECT_EQ(parsed_username, "alice");
    EXPECT_EQ(parsed_text, "Hello\nworld");
    EXPECT_EQ(parsed_timestamp, timestamp);
}
