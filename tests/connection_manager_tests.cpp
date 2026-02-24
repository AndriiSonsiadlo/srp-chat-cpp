#include "chat/server/connection_manager.hpp"

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <chrono>
#include <set>
#include <atomic>


namespace chat::server
{
    class ConnectionManagerTest : public ::testing::Test
    {
    protected:
        ConnectionManager manager_;

        void SetUp() override
        {
        }

        void TearDown() override
        {
        }

        std::shared_ptr<Connection> create_test_connection()
        {
            static boost::asio::io_context io_context;
            return std::make_shared<Connection>(io_context);
        }
    };


    TEST_F(ConnectionManagerTest, AddConnection)
    {
        auto conn = create_test_connection();

        EXPECT_NO_THROW({
            manager_.add("user_1", "alice", conn);
            });
    }

    TEST_F(ConnectionManagerTest, AddMultipleConnections)
    {
        auto conn1 = create_test_connection();
        auto conn2 = create_test_connection();
        auto conn3 = create_test_connection();

        manager_.add("user_1", "alice", conn1);
        manager_.add("user_2", "bob", conn2);
        manager_.add("user_3", "charlie", conn3);

        auto users = manager_.get_active_users();
        EXPECT_EQ(users.size(), 3);
    }

    TEST_F(ConnectionManagerTest, SetUsername)
    {
        auto conn = create_test_connection();
        manager_.add("user_1", "alice", conn);

        const std::string username = manager_.get_username_by_user_id("user_1");
        EXPECT_EQ(username, "alice");
    }

    TEST_F(ConnectionManagerTest, SetMultipleUsernames)
    {
        auto conn1 = create_test_connection();
        auto conn2 = create_test_connection();

        manager_.add("user_1", "alice", conn1);
        manager_.add("user_2", "bob", conn2);

        EXPECT_EQ(manager_.get_username_by_user_id("user_1"), "alice");
        EXPECT_EQ(manager_.get_username_by_user_id("user_2"), "bob");
    }

    TEST_F(ConnectionManagerTest, RemoveConnection)
    {
        auto conn = create_test_connection();
        manager_.add("user_1", "alice", conn);

        manager_.remove("user_1");

        std::string username = manager_.get_username_by_user_id("user_1");
        EXPECT_EQ(username, "");
    }

    TEST_F(ConnectionManagerTest, RemoveNonexistentConnection)
    {
        EXPECT_NO_THROW({
            manager_.remove("nonexistent_user");
            });
    }

    TEST_F(ConnectionManagerTest, RemoveOneOfMultiple)
    {
        auto conn1 = create_test_connection();
        auto conn2 = create_test_connection();
        auto conn3 = create_test_connection();

        manager_.add("user_1", "alice", conn1);
        manager_.add("user_2", "bob", conn2);
        manager_.add("user_3", "charlie", conn3);

        manager_.remove("user_2");

        auto users = manager_.get_active_users();
        EXPECT_EQ(users.size(), 2);

        EXPECT_EQ(manager_.get_username_by_user_id("user_1"), "alice");
        EXPECT_EQ(manager_.get_username_by_user_id("user_2"), "");
        EXPECT_EQ(manager_.get_username_by_user_id("user_3"), "charlie");
    }

    TEST_F(ConnectionManagerTest, UsernameExists)
    {
        auto conn = create_test_connection();
        manager_.add("user_1", "alice", conn);

        EXPECT_TRUE(manager_.username_exists("alice"));
        EXPECT_FALSE(manager_.username_exists("bob"));
    }

    TEST_F(ConnectionManagerTest, UsernameExistsMultiple)
    {
        auto conn1 = create_test_connection();
        auto conn2 = create_test_connection();

        manager_.add("user_1", "alice", conn1);
        manager_.add("user_2", "bob", conn2);

        EXPECT_TRUE(manager_.username_exists("alice"));
        EXPECT_TRUE(manager_.username_exists("bob"));
        EXPECT_FALSE(manager_.username_exists("charlie"));
    }

    TEST_F(ConnectionManagerTest, UsernameExistsAfterRemove)
    {
        auto conn = create_test_connection();
        manager_.add("user_1", "alice", conn);

        EXPECT_TRUE(manager_.username_exists("alice"));

        manager_.remove("user_1");

        EXPECT_FALSE(manager_.username_exists("alice"));
    }

    TEST_F(ConnectionManagerTest, GetActiveUsersEmpty)
    {
        auto users = manager_.get_active_users();
        EXPECT_TRUE(users.empty());
    }

    TEST_F(ConnectionManagerTest, GetActiveUsersSingle)
    {
        auto conn = create_test_connection();
        manager_.add("user_1", "alice", conn);

        auto users = manager_.get_active_users();
        ASSERT_EQ(users.size(), 1);
        EXPECT_EQ(users[0].username, "alice");
        EXPECT_EQ(users[0].user_id, "user_1");
    }

    TEST_F(ConnectionManagerTest, GetActiveUsersMultiple)
    {
        auto conn1 = create_test_connection();
        auto conn2 = create_test_connection();
        auto conn3 = create_test_connection();

        manager_.add("user_1", "alice", conn1);
        manager_.add("user_2", "bob", conn2);
        manager_.add("user_3", "charlie", conn3);

        auto users = manager_.get_active_users();
        EXPECT_EQ(users.size(), 3);

        std::set<std::string> usernames;
        for (const auto& user : users) {
            usernames.insert(user.username);
        }

        EXPECT_TRUE(usernames.count("alice") > 0);
        EXPECT_TRUE(usernames.count("bob") > 0);
        EXPECT_TRUE(usernames.count("charlie") > 0);
    }

    TEST_F(ConnectionManagerTest, GetUsernameByUserId)
    {
        auto conn = create_test_connection();
        manager_.add("user_1", "alice", conn);

        std::string username = manager_.get_username_by_user_id("user_1");
        EXPECT_EQ(username, "alice");
    }

    TEST_F(ConnectionManagerTest, GetUsernameByUserIdNotFound)
    {
        std::string username = manager_.get_username_by_user_id("nonexistent");
        EXPECT_EQ(username, "");
    }

    TEST_F(ConnectionManagerTest, GetUsernameByUserIdMultiple)
    {
        auto conn1 = create_test_connection();
        auto conn2 = create_test_connection();

        manager_.add("user_1", "alice", conn1);
        manager_.add("user_2", "bob", conn2);

        EXPECT_EQ(manager_.get_username_by_user_id("user_1"), "alice");
        EXPECT_EQ(manager_.get_username_by_user_id("user_2"), "bob");
    }

    TEST_F(ConnectionManagerTest, SendToNonexistentUser)
    {
        bool result = manager_.send_to("nonexistent", {});
        EXPECT_FALSE(result);
    }

    TEST_F(ConnectionManagerTest, ConcurrentAddRemove)
    {
        std::vector<std::thread> threads;

        for (int i = 0; i < 10; ++i) {
            threads.emplace_back([i, this]() {
                auto conn            = create_test_connection();
                std::string user_id  = "user_" + std::to_string(i);
                std::string username = "user" + std::to_string(i);

                manager_.add(user_id, username, conn);

                std::this_thread::sleep_for(std::chrono::milliseconds(10));

                manager_.remove(user_id);
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        auto users = manager_.get_active_users();
        EXPECT_TRUE(users.empty());
    }

    TEST_F(ConnectionManagerTest, ConcurrentUsernameCheck)
    {
        auto conn = create_test_connection();
        manager_.add("user_1", "alice", conn);

        std::vector<std::thread> threads;
        std::atomic<int> exists_count{0};

        for (int i = 0; i < 100; ++i) {
            threads.emplace_back([&exists_count, this]() {
                if (manager_.username_exists("alice"))
                    ++exists_count;
            });
        }

        for (auto& thread : threads)
            thread.join();

        EXPECT_EQ(exists_count, 100);
    }

    TEST_F(ConnectionManagerTest, AddSameUserIdTwice)
    {
        auto conn1 = create_test_connection();
        auto conn2 = create_test_connection();

        manager_.add("user_1", "alice", conn1);
        manager_.add("user_1", "bob", conn2);

        EXPECT_EQ(manager_.get_username_by_user_id("user_1"), "bob");
    }

    TEST_F(ConnectionManagerTest, EmptyUsername)
    {
        auto conn = create_test_connection();
        manager_.add("user_1", "", conn);

        std::string username = manager_.get_username_by_user_id("user_1");
        EXPECT_EQ(username, "");
    }

    TEST_F(ConnectionManagerTest, SpecialCharactersInUsername)
    {
        auto conn = create_test_connection();
        manager_.add("user_1", "alice@#$%", conn);

        EXPECT_TRUE(manager_.username_exists("alice@#$%"));
        EXPECT_EQ(manager_.get_username_by_user_id("user_1"), "alice@#$%");
    }

    TEST_F(ConnectionManagerTest, LongUsername)
    {
        auto conn = create_test_connection();
        std::string long_username(1000, 'a');

        manager_.add("user_1", long_username, conn);

        EXPECT_TRUE(manager_.username_exists(long_username));
        EXPECT_EQ(manager_.get_username_by_user_id("user_1"), long_username);
    }
} // namespace chat::server
