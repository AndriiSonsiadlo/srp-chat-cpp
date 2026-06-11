#include "chat/server/room_manager.hpp"

#include "chat/crypto/aes_engine.hpp"

#include <algorithm>
#include <gtest/gtest.h>
#include <memory>

namespace chat::server
{
    namespace
    {
        class RecordingSink final : public Sink
        {
        public:
            std::vector<std::vector<uint8_t>> packets;
            bool closed = false;

            void send(std::vector<uint8_t> packet) override { packets.push_back(std::move(packet)); }
            void close() override { closed = true; }
        };

        std::vector<uint8_t> test_key(const uint8_t fill)
        {
            return std::vector<uint8_t>(crypto::AESEngine::KEY_SIZE, fill);
        }

        std::shared_ptr<RecordingSink> sink() { return std::make_shared<RecordingSink>(); }
    }

    TEST(RoomManagerTest, LobbyExistsAndIsPublic)
    {
        const RoomManager manager(64, 64);

        const auto lobby = manager.find(kDefaultRoom);
        ASSERT_NE(lobby, nullptr);
        EXPECT_FALSE(lobby->has_password());
        EXPECT_EQ(lobby->name(), std::string(kDefaultRoom));
    }

    TEST(RoomManagerTest, JoinsAnExistingRoom)
    {
        RoomManager manager(64, 64);

        const auto result = manager.join(kDefaultRoom, "", "id-a", "alice", sink(), test_key(0xAA));

        EXPECT_EQ(result.status, JoinStatus::Ok);
        ASSERT_NE(result.room, nullptr);
        EXPECT_EQ(result.room->size(), 1u);
    }

    TEST(RoomManagerTest, RefusesUnknownRoom)
    {
        RoomManager manager(64, 64);

        const auto result = manager.join("nowhere", "", "id-a", "alice", sink(), test_key(0xAA));

        EXPECT_EQ(result.status, JoinStatus::NoSuchRoom);
        EXPECT_EQ(result.room, nullptr);
    }

    TEST(RoomManagerTest, CreatesAndJoinsInOneStep)
    {
        RoomManager manager(64, 64);

        const auto result = manager.create_and_join("dev", "", "id-a", "alice", sink(), test_key(0xAA));

        ASSERT_EQ(result.status, JoinStatus::Ok);
        EXPECT_EQ(result.room->size(), 1u);
        EXPECT_NE(manager.find("dev"), nullptr);
    }

    TEST(RoomManagerTest, RefusesDuplicateNameCaseInsensitively)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("Dev", "", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        const auto result = manager.create_and_join("dev", "", "id-b", "bob", sink(), test_key(0xBB));

        EXPECT_EQ(result.status, JoinStatus::NameTaken);
    }

    TEST(RoomManagerTest, FindIsCaseInsensitiveButNameKeepsCasing)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("Dev-Team", "", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        const auto room = manager.find("dev-team");
        ASSERT_NE(room, nullptr);
        EXPECT_EQ(room->name(), "Dev-Team");
    }

    TEST(RoomManagerTest, LockedRoomRequiresTheRightPassword)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("dev", "hunter2", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        EXPECT_EQ(manager.join("dev", "", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::PasswordRequired);
        EXPECT_EQ(manager.join("dev", "wrong", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::WrongPassword);
        EXPECT_EQ(manager.join("dev", "hunter2", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::Ok);
    }

    TEST(RoomManagerTest, FailedJoinLeavesRoomUntouched)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("dev", "hunter2", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        ASSERT_EQ(manager.join("dev", "wrong", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::WrongPassword);

        EXPECT_EQ(manager.find("dev")->size(), 1u);
    }

    TEST(RoomManagerTest, EnforcesMemberCap)
    {
        RoomManager manager(64, 1);
        ASSERT_EQ(manager.create_and_join("dev", "", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        EXPECT_EQ(manager.join("dev", "", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::RoomFull);
    }

    TEST(RoomManagerTest, EnforcesRoomCap)
    {
        // The lobby occupies one slot from the start.
        RoomManager manager(2, 64);
        ASSERT_EQ(manager.create_and_join("one", "", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        EXPECT_EQ(manager.create_and_join("two", "", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::TooManyRooms);
    }

    TEST(RoomManagerTest, DropsEmptyRoom)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("dev", "", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        manager.drop_if_empty("dev");
        EXPECT_NE(manager.find("dev"), nullptr); // still occupied

        manager.find("dev")->leave("id-a");
        manager.drop_if_empty("dev");
        EXPECT_EQ(manager.find("dev"), nullptr);
    }

    TEST(RoomManagerTest, NeverDropsTheLobby)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.find(kDefaultRoom)->size(), 0u);

        manager.drop_if_empty(kDefaultRoom);

        EXPECT_NE(manager.find(kDefaultRoom), nullptr);
    }

    TEST(RoomManagerTest, ListsRoomsWithCountsAndLockFlag)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("dev", "hunter2", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        const auto rooms = manager.list();
        ASSERT_EQ(rooms.size(), 2u);

        const auto dev = std::ranges::find_if(rooms, [](const RoomInfo& r) { return r.name == "dev"; });
        ASSERT_NE(dev, rooms.end());
        EXPECT_EQ(dev->user_count, 1u);
        EXPECT_EQ(dev->has_password, 1);

        const auto lobby = std::ranges::find_if(
            rooms, [](const RoomInfo& r) { return r.name == std::string(kDefaultRoom); });
        ASSERT_NE(lobby, rooms.end());
        EXPECT_EQ(lobby->user_count, 0u);
        EXPECT_EQ(lobby->has_password, 0);
    }
}
