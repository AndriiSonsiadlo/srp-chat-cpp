#include "chat/server/connection_manager.hpp"

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <chrono>
#include <set>
#include <atomic>

using namespace chat::server;
using namespace chat;

class ConnectionManagerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

std::shared_ptr<Connection> create_test_connection()
{
    static boost::asio::io_context io_context;
    return std::make_shared<Connection>(io_context);
}

TEST_F(ConnectionManagerTest, AddConnection)
{
    ConnectionManager manager;
    auto conn = create_test_connection();

    EXPECT_NO_THROW({
        manager.add("user_1", conn);
        });
}

TEST_F(ConnectionManagerTest, AddMultipleConnections)
{
    ConnectionManager manager;
    auto conn1 = create_test_connection();
    auto conn2 = create_test_connection();
    auto conn3 = create_test_connection();

    manager.add("user_1", conn1);
    manager.add("user_2", conn2);
    manager.add("user_3", conn3);

    manager.set_username("user_1", "alice");
    manager.set_username("user_2", "bob");
    manager.set_username("user_3", "charlie");

    auto users = manager.get_active_users();
    EXPECT_EQ(users.size(), 3);
}

TEST_F(ConnectionManagerTest, SetUsername)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    manager.add("user_1", conn);

    manager.set_username("user_1", "alice");

    std::string username = manager.get_username_by_user_id("user_1");
    EXPECT_EQ(username, "alice");
}

TEST_F(ConnectionManagerTest, SetMultipleUsernames)
{
    ConnectionManager manager;
    auto conn1 = create_test_connection();
    auto conn2 = create_test_connection();

    manager.add("user_1", conn1);
    manager.add("user_2", conn2);

    manager.set_username("user_1", "alice");
    manager.set_username("user_2", "bob");

    EXPECT_EQ(manager.get_username_by_user_id("user_1"), "alice");
    EXPECT_EQ(manager.get_username_by_user_id("user_2"), "bob");
}

TEST_F(ConnectionManagerTest, RemoveConnection)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    manager.add("user_1", conn);
    manager.set_username("user_1", "alice");

    manager.remove("user_1");

    std::string username = manager.get_username_by_user_id("user_1");
    EXPECT_EQ(username, "");
}

TEST_F(ConnectionManagerTest, RemoveNonexistentConnection)
{
    ConnectionManager manager;
    EXPECT_NO_THROW({
        manager.remove("nonexistent_user");
        });
}

TEST_F(ConnectionManagerTest, RemoveOneOfMultiple)
{
    ConnectionManager manager;
    auto conn1 = create_test_connection();
    auto conn2 = create_test_connection();
    auto conn3 = create_test_connection();

    manager.add("user_1", conn1);
    manager.add("user_2", conn2);
    manager.add("user_3", conn3);

    manager.set_username("user_1", "alice");
    manager.set_username("user_2", "bob");
    manager.set_username("user_3", "charlie");

    manager.remove("user_2");

    auto users = manager.get_active_users();
    EXPECT_EQ(users.size(), 2);

    EXPECT_EQ(manager.get_username_by_user_id("user_1"), "alice");
    EXPECT_EQ(manager.get_username_by_user_id("user_2"), "");
    EXPECT_EQ(manager.get_username_by_user_id("user_3"), "charlie");
}

TEST_F(ConnectionManagerTest, UsernameExists)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    manager.add("user_1", conn);
    manager.set_username("user_1", "alice");

    EXPECT_TRUE(manager.username_exists("alice"));
    EXPECT_FALSE(manager.username_exists("bob"));
}

TEST_F(ConnectionManagerTest, UsernameExistsMultiple)
{
    ConnectionManager manager;
    auto conn1 = create_test_connection();
    auto conn2 = create_test_connection();

    manager.add("user_1", conn1);
    manager.add("user_2", conn2);

    manager.set_username("user_1", "alice");
    manager.set_username("user_2", "bob");

    EXPECT_TRUE(manager.username_exists("alice"));
    EXPECT_TRUE(manager.username_exists("bob"));
    EXPECT_FALSE(manager.username_exists("charlie"));
}

TEST_F(ConnectionManagerTest, UsernameExistsAfterRemove)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    manager.add("user_1", conn);
    manager.set_username("user_1", "alice");

    EXPECT_TRUE(manager.username_exists("alice"));

    manager.remove("user_1");

    EXPECT_FALSE(manager.username_exists("alice"));
}

TEST_F(ConnectionManagerTest, GetActiveUsersEmpty)
{
    ConnectionManager manager;
    auto users = manager.get_active_users();
    EXPECT_TRUE(users.empty());
}

TEST_F(ConnectionManagerTest, GetActiveUsersSingle)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    manager.add("user_1", conn);
    manager.set_username("user_1", "alice");

    auto users = manager.get_active_users();
    ASSERT_EQ(users.size(), 1);
    EXPECT_EQ(users[0].username, "alice");
    EXPECT_EQ(users[0].user_id, "user_1");
}

TEST_F(ConnectionManagerTest, GetActiveUsersMultiple)
{
    ConnectionManager manager;
    auto conn1 = create_test_connection();
    auto conn2 = create_test_connection();
    auto conn3 = create_test_connection();

    manager.add("user_1", conn1);
    manager.add("user_2", conn2);
    manager.add("user_3", conn3);

    manager.set_username("user_1", "alice");
    manager.set_username("user_2", "bob");
    manager.set_username("user_3", "charlie");

    auto users = manager.get_active_users();
    EXPECT_EQ(users.size(), 3);

    std::set<std::string> usernames;
    for (const auto& user : users)
    {
        usernames.insert(user.username);
    }

    EXPECT_TRUE(usernames.count("alice") > 0);
    EXPECT_TRUE(usernames.count("bob") > 0);
    EXPECT_TRUE(usernames.count("charlie") > 0);
}

TEST_F(ConnectionManagerTest, GetUserIdByUsername)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    manager.add("user_1", conn);
    manager.set_username("user_1", "alice");

    std::string user_id = manager.get_user_id_by_username("alice");
    EXPECT_EQ(user_id, "user_1");
}

TEST_F(ConnectionManagerTest, GetUserIdByUsernameNotFound)
{
    ConnectionManager manager;
    std::string user_id = manager.get_user_id_by_username("nonexistent");
    EXPECT_EQ(user_id, "");
}

TEST_F(ConnectionManagerTest, GetUserIdByUsernameMultiple)
{
    ConnectionManager manager;
    auto conn1 = create_test_connection();
    auto conn2 = create_test_connection();

    manager.add("user_1", conn1);
    manager.add("user_2", conn2);

    manager.set_username("user_1", "alice");
    manager.set_username("user_2", "bob");

    EXPECT_EQ(manager.get_user_id_by_username("alice"), "user_1");
    EXPECT_EQ(manager.get_user_id_by_username("bob"), "user_2");
}

TEST_F(ConnectionManagerTest, GetUsernameByUserId)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    manager.add("user_1", conn);
    manager.set_username("user_1", "alice");

    std::string username = manager.get_username_by_user_id("user_1");
    EXPECT_EQ(username, "alice");
}

TEST_F(ConnectionManagerTest, GetUsernameByUserIdNotFound)
{
    ConnectionManager manager;
    std::string username = manager.get_username_by_user_id("nonexistent");
    EXPECT_EQ(username, "");
}

TEST_F(ConnectionManagerTest, GetUsernameByUserIdMultiple)
{
    ConnectionManager manager;
    auto conn1 = create_test_connection();
    auto conn2 = create_test_connection();

    manager.add("user_1", conn1);
    manager.add("user_2", conn2);

    manager.set_username("user_1", "alice");
    manager.set_username("user_2", "bob");

    EXPECT_EQ(manager.get_username_by_user_id("user_1"), "alice");
    EXPECT_EQ(manager.get_username_by_user_id("user_2"), "bob");
}

TEST_F(ConnectionManagerTest, SendToNonexistentUser)
{
    ConnectionManager manager;
    bool result = manager.send_to("nonexistent", "test message");
    EXPECT_FALSE(result);
}

TEST_F(ConnectionManagerTest, ConcurrentAddRemove)
{
    ConnectionManager manager;
    std::vector<std::thread> threads;

    for (int i = 0; i < 10; ++i)
    {
        threads.emplace_back([&manager, i]()
        {
            auto conn            = create_test_connection();
            std::string user_id  = "user_" + std::to_string(i);
            std::string username = "user" + std::to_string(i);

            manager.add(user_id, conn);
            manager.set_username(user_id, username);

            std::this_thread::sleep_for(std::chrono::milliseconds(10));

            manager.remove(user_id);
        });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    auto users = manager.get_active_users();
    EXPECT_TRUE(users.empty());
}

TEST_F(ConnectionManagerTest, ConcurrentUsernameCheck)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    manager.add("user_1", conn);
    manager.set_username("user_1", "alice");

    std::vector<std::thread> threads;
    std::atomic<int> exists_count{0};

    for (int i = 0; i < 100; ++i)
    {
        threads.emplace_back([&manager, &exists_count]()
        {
            if (manager.username_exists("alice"))
            {
                exists_count++;
            }
        });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(exists_count, 100);
}

TEST_F(ConnectionManagerTest, AddSameUserIdTwice)
{
    ConnectionManager manager;
    auto conn1 = create_test_connection();
    auto conn2 = create_test_connection();

    manager.add("user_1", conn1);
    manager.set_username("user_1", "alice");

    manager.add("user_1", conn2);
    manager.set_username("user_1", "bob");

    EXPECT_EQ(manager.get_username_by_user_id("user_1"), "bob");
}

TEST_F(ConnectionManagerTest, EmptyUsername)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    manager.add("user_1", conn);
    manager.set_username("user_1", "");

    std::string username = manager.get_username_by_user_id("user_1");
    EXPECT_EQ(username, "");
}

TEST_F(ConnectionManagerTest, SpecialCharactersInUsername)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    manager.add("user_1", conn);
    manager.set_username("user_1", "alice@#$%");

    EXPECT_TRUE(manager.username_exists("alice@#$%"));
    EXPECT_EQ(manager.get_username_by_user_id("user_1"), "alice@#$%");
}

TEST_F(ConnectionManagerTest, LongUsername)
{
    ConnectionManager manager;
    auto conn = create_test_connection();
    std::string long_username(1000, 'a');

    manager.add("user_1", conn);
    manager.set_username("user_1", long_username);

    EXPECT_TRUE(manager.username_exists(long_username));
    EXPECT_EQ(manager.get_username_by_user_id("user_1"), long_username);
}
