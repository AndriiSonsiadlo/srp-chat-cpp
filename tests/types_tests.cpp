#include <ranges>
#include <gtest/gtest.h>

#include "chat/common/types.hpp"

namespace chat
{
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

        EXPECT_EQ(msg1.username, "alice");
        EXPECT_EQ(msg2.username, "alice");
        EXPECT_EQ(msg1.text, "Hello");
        EXPECT_EQ(msg2.text, "Hello");
        EXPECT_EQ(msg1.timestamp, now);
        EXPECT_EQ(msg2.timestamp, now);
    }

    TEST_F(TypesTest, MessageStructMove)
    {
        auto now = std::chrono::system_clock::now();
        Message msg1{"alice", "Hello", now};
        Message msg2 = std::move(msg1);

        EXPECT_EQ(msg1.username, "");
        EXPECT_EQ(msg2.username, "alice");
        EXPECT_EQ(msg1.text, "");
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
} // namespace chat
