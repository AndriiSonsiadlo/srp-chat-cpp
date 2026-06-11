#include "chat/server/room_name.hpp"

#include <gtest/gtest.h>
#include <string>

namespace chat::server
{
    TEST(RoomNameTest, AcceptsAlnumUnderscoreDash)
    {
        EXPECT_TRUE(is_valid_room_name("lobby"));
        EXPECT_TRUE(is_valid_room_name("dev-team_2"));
        EXPECT_TRUE(is_valid_room_name("A"));
    }

    TEST(RoomNameTest, RejectsEmptyAndOverlong)
    {
        EXPECT_FALSE(is_valid_room_name(""));
        EXPECT_TRUE(is_valid_room_name(std::string(kMaxRoomNameLength, 'a')));
        EXPECT_FALSE(is_valid_room_name(std::string(kMaxRoomNameLength + 1, 'a')));
    }

    TEST(RoomNameTest, RejectsSeparatorsAndControlCharacters)
    {
        EXPECT_FALSE(is_valid_room_name("has space"));
        EXPECT_FALSE(is_valid_room_name("has/slash"));
        EXPECT_FALSE(is_valid_room_name("has\ttab"));
        EXPECT_FALSE(is_valid_room_name("esc\033[0m"));
    }

    TEST(RoomNameTest, RejectsHighBytes)
    {
        // std::isalnum on a negative char is undefined; the helper must cast to
        // unsigned char before calling it, and must not accept UTF-8 bytes.
        EXPECT_FALSE(is_valid_room_name("caf\xC3\xA9"));
    }

    TEST(RoomNameTest, KeyIsLowercasedForCaseInsensitiveUniqueness)
    {
        EXPECT_EQ(room_key("Dev"), room_key("dev"));
        EXPECT_EQ(room_key("LOBBY"), "lobby");
        EXPECT_EQ(room_key("mixed-Case_1"), "mixed-case_1");
    }
} // namespace chat::server
