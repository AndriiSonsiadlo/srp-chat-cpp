#include "chat/common/cli.hpp"

#include <gtest/gtest.h>
#include <vector>

namespace chat
{
    namespace
    {
        Cli parse(std::vector<const char*> args)
        {
            args.insert(args.begin(), "prog");
            return Cli(static_cast<int>(args.size()), const_cast<char**>(args.data()));
        }
    }

    TEST(CliTest, ParsesSeparatedValues)
    {
        const auto cli = parse({"--host", "example.com", "--port", "9000"});
        EXPECT_EQ(cli.get("host", "localhost"), "example.com");
        EXPECT_EQ(cli.get_int("port", 8888), 9000);
    }

    TEST(CliTest, ParsesEqualsForm)
    {
        const auto cli = parse({"--host=example.com", "--port=9000"});
        EXPECT_EQ(cli.get("host", "localhost"), "example.com");
        EXPECT_EQ(cli.get_int("port", 8888), 9000);
    }

    TEST(CliTest, BareFlagIsBoolean)
    {
        const auto cli = parse({"--register"});
        EXPECT_TRUE(cli.has("register"));
        EXPECT_FALSE(cli.has("help"));
    }

    TEST(CliTest, FallsBackWhenAbsent)
    {
        const auto cli = parse({});
        EXPECT_EQ(cli.get("host", "localhost"), "localhost");
        EXPECT_EQ(cli.get_int("port", 8888), 8888);
    }

    TEST(CliTest, RejectsNonNumericInt)
    {
        const auto cli = parse({"--port", "eight"});
        EXPECT_THROW((void)cli.get_int("port", 8888), std::runtime_error);
    }

    TEST(CliTest, RejectsPositionalArguments)
    {
        EXPECT_THROW((void)parse({"stray"}), std::runtime_error);
    }

    TEST(CliTest, ExpectKnownNamesTheOffendingFlag)
    {
        const auto cli = parse({"--hsot", "example.com"});
        EXPECT_THROW(cli.expect_known({"host", "port"}), std::runtime_error);
        EXPECT_NO_THROW(parse({"--host", "x"}).expect_known({"host", "port"}));
    }

    TEST(CliTest, ParsesRoomCaps)
    {
        const auto cli = parse({"--max-rooms", "8", "--max-room-members", "12"});
        EXPECT_EQ(cli.get_int("max-rooms", 64), 8);
        EXPECT_EQ(cli.get_int("max-room-members", 64), 12);
    }

    TEST(CliTest, RoomCapsFallBackToDefaults)
    {
        const auto cli = parse({"--port", "9000"});
        EXPECT_EQ(cli.get_int("max-rooms", 64), 64);
        EXPECT_EQ(cli.get_int("max-room-members", 64), 64);
    }

    TEST(CliTest, RoomCapFlagsAreKnown)
    {
        const auto cli = parse({"--max-rooms", "8", "--max-room-members", "12"});
        EXPECT_NO_THROW(cli.expect_known({"max-rooms", "max-room-members"}));
    }
} // namespace chat
