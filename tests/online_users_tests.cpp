#include "chat/server/online_users.hpp"

#include <gtest/gtest.h>

namespace chat::server
{
    TEST(OnlineUsersTest, ClaimSucceedsOnceThenRefuses)
    {
        OnlineUsers online;

        EXPECT_TRUE(online.try_claim("alice"));
        EXPECT_TRUE(online.is_online("alice"));
        EXPECT_FALSE(online.try_claim("alice"));
    }

    TEST(OnlineUsersTest, DistinctNamesDoNotCollide)
    {
        OnlineUsers online;

        EXPECT_TRUE(online.try_claim("alice"));
        EXPECT_TRUE(online.try_claim("bob"));
        EXPECT_TRUE(online.is_online("bob"));
    }

    TEST(OnlineUsersTest, ReleaseAllowsReclaim)
    {
        OnlineUsers online;

        ASSERT_TRUE(online.try_claim("alice"));
        online.release("alice");

        EXPECT_FALSE(online.is_online("alice"));
        EXPECT_TRUE(online.try_claim("alice"));
    }

    TEST(OnlineUsersTest, ReleasingSomeoneAbsentIsHarmless)
    {
        OnlineUsers online;

        // The disconnect path releases unconditionally, including for a session
        // that failed before it ever claimed a name.
        online.release("nobody");
        online.release("");

        EXPECT_FALSE(online.is_online("nobody"));
    }
}
