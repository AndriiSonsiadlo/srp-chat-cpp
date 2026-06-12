#include "chat/server/room.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"
#include "chat/crypto/aes_engine.hpp"
#include "chat/auth/srp_utils.hpp"

#include <gtest/gtest.h>
#include <memory>

namespace chat::server
{
    namespace
    {
        // Captures packets instead of writing them to a socket.
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

        MessageType type_of(const std::vector<uint8_t>& packet)
        {
            std::array<uint8_t, MsgHeader::kWireSize> raw{};
            std::copy_n(packet.begin(), MsgHeader::kWireSize, raw.begin());
            return static_cast<MessageType>(decode_header(raw).type);
        }

        std::vector<uint8_t> payload_of(const std::vector<uint8_t>& packet)
        {
            return std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        }

        std::vector<uint8_t> aad_of(const std::string& username)
        {
            return std::vector<uint8_t>(username.begin(), username.end());
        }
    }

    class RoomTest : public ::testing::Test
    {
    protected:
        Room room_;
        std::shared_ptr<RecordingSink> alice_ = std::make_shared<RecordingSink>();
        std::shared_ptr<RecordingSink> bob_   = std::make_shared<RecordingSink>();

        void join_both()
        {
            room_.join("user_a", "alice", alice_, test_key(0xAA));
            room_.join("user_b", "bob", bob_, test_key(0xBB));
        }
    };

    TEST_F(RoomTest, TracksMembership)
    {
        join_both();

        EXPECT_EQ(room_.size(), 2u);
        EXPECT_EQ(room_.username_of("user_a"), "alice");
        EXPECT_EQ(room_.username_of("user_b"), "bob");
        EXPECT_EQ(room_.username_of("nobody"), "");
        EXPECT_EQ(room_.active_users().size(), 2u);
    }

    TEST_F(RoomTest, LeaveRemovesAndDoesNotClose)
    {
        join_both();
        room_.leave("user_a");

        EXPECT_EQ(room_.size(), 1u);
        EXPECT_EQ(room_.username_of("user_a"), "");
        // Leaving a room must not close the connection — a room switch is a leave
        // followed by a join, and Session::run owns the socket teardown.
        EXPECT_FALSE(alice_->closed);
    }

    TEST_F(RoomTest, BroadcastPacketExcludesTheNamedUser)
    {
        join_both();
        room_.broadcast_packet(Protocol::encode(MessageType::USER_LEFT, UserLeftMsg{"carol"}), "user_a");

        EXPECT_TRUE(alice_->packets.empty());
        ASSERT_EQ(bob_->packets.size(), 1u);
        EXPECT_EQ(type_of(bob_->packets[0]), MessageType::USER_LEFT);
    }

    TEST_F(RoomTest, EachRecipientGetsTheMessageUnderTheirOwnKey)
    {
        join_both();
        room_.record_and_broadcast("alice", "hello everyone");

        ASSERT_EQ(alice_->packets.size(), 1u);
        ASSERT_EQ(bob_->packets.size(), 1u);

        const auto for_alice = Protocol::decode<BroadcastMsg>(payload_of(alice_->packets[0]));
        const auto for_bob   = Protocol::decode<BroadcastMsg>(payload_of(bob_->packets[0]));

        EXPECT_EQ(for_alice.username, "alice");
        EXPECT_GT(for_alice.timestamp_ms, 0);

        // Same plaintext, different keys, therefore different ciphertext.
        EXPECT_NE(for_alice.ciphertext_b64, for_bob.ciphertext_b64);

        const auto sender_aad = aad_of("alice");

        EXPECT_EQ(crypto::AESEngine::decrypt_string(
                      auth::SRPUtils::base64_to_bytes(for_alice.ciphertext_b64), test_key(0xAA), sender_aad),
                  "hello everyone");
        EXPECT_EQ(crypto::AESEngine::decrypt_string(
                      auth::SRPUtils::base64_to_bytes(for_bob.ciphertext_b64), test_key(0xBB), sender_aad),
                  "hello everyone");
    }

    TEST_F(RoomTest, BroadcastCiphertextIsBoundToSenderUsername)
    {
        join_both();
        room_.record_and_broadcast("alice", "hello everyone");

        const auto for_alice  = Protocol::decode<BroadcastMsg>(payload_of(alice_->packets[0]));
        const auto ciphertext = auth::SRPUtils::base64_to_bytes(for_alice.ciphertext_b64);

        // Re-attributing a valid ciphertext to a different username must fail
        // authentication, even with the correct key.
        const auto wrong_aad = aad_of("bob");
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(ciphertext, test_key(0xAA), wrong_aad),
                     std::runtime_error);

        const auto right_aad = aad_of("alice");
        EXPECT_EQ(crypto::AESEngine::decrypt_string(ciphertext, test_key(0xAA), right_aad),
                  "hello everyone");
    }

    TEST_F(RoomTest, HistoryIsEncryptedForTheJoiningUserAndKeepsTimestamps)
    {
        room_.join("user_a", "alice", alice_, test_key(0xAA));
        room_.record_and_broadcast("alice", "first");
        room_.record_and_broadcast("alice", "second");

        room_.join("user_b", "bob", bob_, test_key(0xBB));
        const auto init = Protocol::decode<InitMsg>(payload_of(room_.init_packet_for("user_b")));

        ASSERT_EQ(init.messages.size(), 2u);
        EXPECT_EQ(init.messages[0].username, "alice");
        EXPECT_GT(init.messages[0].timestamp_ms, 0);
        EXPECT_LE(init.messages[0].timestamp_ms, init.messages[1].timestamp_ms);

        const auto sender_aad = aad_of("alice");

        // Decryptable only with bob's key — the history is not plaintext.
        EXPECT_EQ(crypto::AESEngine::decrypt_string(
                      auth::SRPUtils::base64_to_bytes(init.messages[0].ciphertext_b64), test_key(0xBB), sender_aad),
                  "first");
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(
                         auth::SRPUtils::base64_to_bytes(init.messages[0].ciphertext_b64), test_key(0xAA), sender_aad),
                     std::runtime_error);
    }

    TEST_F(RoomTest, HistoryIsCappedAtOneHundredMessages)
    {
        room_.join("user_a", "alice", alice_, test_key(0xAA));
        for (int i = 0; i < 150; ++i)
            room_.record_and_broadcast("alice", "msg " + std::to_string(i));

        room_.join("user_b", "bob", bob_, test_key(0xBB));
        const auto init = Protocol::decode<InitMsg>(payload_of(room_.init_packet_for("user_b")));

        EXPECT_EQ(init.messages.size(), 100u);
        const auto sender_aad = aad_of("alice");
        EXPECT_EQ(crypto::AESEngine::decrypt_string(
                      auth::SRPUtils::base64_to_bytes(init.messages[0].ciphertext_b64), test_key(0xBB), sender_aad),
                  "msg 50"); // oldest 50 dropped
    }

    TEST_F(RoomTest, InitPacketForUnknownUserIsEmpty)
    {
        join_both();
        const auto init = Protocol::decode<InitMsg>(payload_of(room_.init_packet_for("nobody")));
        EXPECT_TRUE(init.messages.empty());
    }

    TEST(RoomPasswordTest, PublicRoomAcceptsAnything)
    {
        const Room room("lobby");

        EXPECT_EQ(room.name(), "lobby");
        EXPECT_FALSE(room.has_password());
        EXPECT_TRUE(room.verify_password(""));
        EXPECT_TRUE(room.verify_password("anything"));
    }

    TEST(RoomPasswordTest, LockedRoomAcceptsOnlyTheRightPassword)
    {
        const Room room("dev", "hunter2");

        EXPECT_TRUE(room.has_password());
        EXPECT_TRUE(room.verify_password("hunter2"));
        EXPECT_FALSE(room.verify_password("hunter3"));
        EXPECT_FALSE(room.verify_password(""));
        EXPECT_FALSE(room.verify_password("hunter2 "));
    }

    TEST(RoomPasswordTest, EqualPasswordsInDifferentRoomsBothVerify)
    {
        // Distinct random salts per room: two rooms sharing a password must not
        // share a hash, or one leaked hash would identify every room using it.
        const Room a("one", "same-password");
        const Room b("two", "same-password");

        EXPECT_TRUE(a.verify_password("same-password"));
        EXPECT_TRUE(b.verify_password("same-password"));
    }

    TEST(RoomPasswordTest, KeepsCreatorCasing)
    {
        const Room room("Dev-Team");
        EXPECT_EQ(room.name(), "Dev-Team");
    }
} // namespace chat::server
