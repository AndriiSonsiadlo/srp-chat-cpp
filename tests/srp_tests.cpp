#include "chat/auth/srp_client.hpp"
#include "chat/auth/srp_server.hpp"
#include "chat/auth/srp_types.hpp"
#include "chat/crypto/aes_engine.hpp"

#include <gtest/gtest.h>
#include <set>

namespace chat::auth
{
    namespace
    {
        // Registers `username` on `server` and returns a client ready to authenticate.
        SRPServer make_server_with_user(const std::string& username, const std::string& password)
        {
            SRPServer server;
            server.register_user(username, SRPClient::register_user(username, password));
            return server;
        }
    }

    TEST(SrpTest, BothSidesDeriveTheSameKeyWithoutExchangingIt)
    {
        const std::string username = "alice";
        const std::string password = "correct horse battery staple";

        auto server = make_server_with_user(username, password);
        SRPClient client(username, password);

        const auto A         = client.generate_A();
        const auto challenge = server.init_authentication(username, A);
        const auto M         = client.process_challenge(challenge.B, challenge.salt);
        const auto verify    = server.verify_authentication(challenge.user_id, M);

        ASSERT_TRUE(client.verify_server(verify.H_AMK));

        const auto client_key = client.derive_session_key(challenge.room_salt);
        const auto server_key = server.derive_session_key(challenge.user_id);

        EXPECT_EQ(client_key.size(), crypto::AESEngine::KEY_SIZE);
        EXPECT_EQ(client_key, server_key);
    }

    TEST(SrpTest, DerivedKeyActuallyDecryptsAMessage)
    {
        auto server = make_server_with_user("bob", "hunter2");
        SRPClient client("bob", "hunter2");

        const auto A         = client.generate_A();
        const auto challenge = server.init_authentication("bob", A);
        const auto M         = client.process_challenge(challenge.B, challenge.salt);
        const auto verify    = server.verify_authentication(challenge.user_id, M);
        ASSERT_TRUE(client.verify_server(verify.H_AMK));

        const auto client_key = client.derive_session_key(challenge.room_salt);
        const auto server_key = server.derive_session_key(challenge.user_id);

        const auto sealed = crypto::AESEngine::encrypt_string("ping", client_key);
        EXPECT_EQ(crypto::AESEngine::decrypt_string(sealed, server_key), "ping");
    }

    TEST(SrpTest, WrongPasswordFailsVerification)
    {
        auto server = make_server_with_user("carol", "right-password");
        SRPClient client("carol", "wrong-password");

        const auto A         = client.generate_A();
        const auto challenge = server.init_authentication("carol", A);
        const auto M         = client.process_challenge(challenge.B, challenge.salt);

        EXPECT_THROW((void)server.verify_authentication(challenge.user_id, M), std::runtime_error);
    }

    TEST(SrpTest, DeriveSessionKeyBeforeVerificationThrows)
    {
        auto server = make_server_with_user("dave", "pw");
        SRPClient client("dave", "pw");

        EXPECT_THROW((void)client.derive_session_key(std::vector<uint8_t>(16, 0x00)), std::runtime_error);
        EXPECT_THROW((void)server.derive_session_key("user_does_not_exist"), std::runtime_error);
    }

    TEST(SrpTest, DifferentUsersDeriveDifferentKeys)
    {
        SRPServer server;
        server.register_user("erin", SRPClient::register_user("erin", "pw-1"));
        server.register_user("frank", SRPClient::register_user("frank", "pw-2"));

        auto authenticate = [&server](const std::string& user, const std::string& pass) {
            SRPClient client(user, pass);
            const auto A         = client.generate_A();
            const auto challenge = server.init_authentication(user, A);
            const auto M         = client.process_challenge(challenge.B, challenge.salt);
            const auto verify    = server.verify_authentication(challenge.user_id, M);
            EXPECT_TRUE(client.verify_server(verify.H_AMK));
            return client.derive_session_key(challenge.room_salt);
        };

        EXPECT_NE(authenticate("erin", "pw-1"), authenticate("frank", "pw-2"));
    }

    TEST(SrpTest, ServerRejectsZeroA)
    {
        auto server = make_server_with_user("grace", "pw");

        // A ≡ 0 (mod N) forces S = 0 on the server side and must be refused
        // outright. Both a literal zero and a bare N are rejected.
        const std::vector<uint8_t> zero_A{0x00};
        EXPECT_THROW((void)server.init_authentication("grace", zero_A), std::runtime_error);

        const auto N_bytes = SRPUtils::BigNum(std::string(SRP_N_HEX_2048)).to_bytes();
        EXPECT_THROW((void)server.init_authentication("grace", N_bytes), std::runtime_error);
    }

    TEST(SrpTest, ClientRejectsZeroB)
    {
        SRPClient client("heidi", "pw");
        (void)client.generate_A();

        const std::vector<uint8_t> zero_B{0x00};
        const std::vector<uint8_t> salt(SRP_SALT_SIZE, 0x01);
        EXPECT_THROW((void)client.process_challenge(zero_B, salt), std::runtime_error);
    }

    TEST(SrpTest, ConstantTimeEqualsMatchesValueEquality)
    {
        const std::vector<uint8_t> a{1, 2, 3, 4};
        const std::vector<uint8_t> b{1, 2, 3, 4};
        const std::vector<uint8_t> c{1, 2, 3, 5};
        const std::vector<uint8_t> shorter{1, 2, 3};

        EXPECT_TRUE(SRPUtils::constant_time_equals(a, b));
        EXPECT_FALSE(SRPUtils::constant_time_equals(a, c));
        EXPECT_FALSE(SRPUtils::constant_time_equals(a, shorter));
    }

    TEST(SrpTest, UserIdsAreLongAndDistinct)
    {
        std::set<std::string> ids;
        for (int i = 0; i < 200; ++i) {
            auto id = SRPUtils::random_hex_id(16);
            EXPECT_EQ(id.size(), 32u); // 16 bytes, hex encoded
            ids.insert(id);
        }
        EXPECT_EQ(ids.size(), 200u);
    }

    TEST(SrpTest, ExpiredSessionsAreSweptAway)
    {
        auto server = make_server_with_user("ivan", "pw");
        SRPClient client("ivan", "pw");

        const auto A         = client.generate_A();
        const auto challenge = server.init_authentication("ivan", A);
        const auto M         = client.process_challenge(challenge.B, challenge.salt);
        (void)server.verify_authentication(challenge.user_id, M);

        EXPECT_TRUE(server.is_session_valid(challenge.user_id));

        server.clear_expired_sessions(0); // everything older than zero seconds
        EXPECT_FALSE(server.is_session_valid(challenge.user_id));
    }

    TEST(SrpTest, SessionRemembersItsUsername)
    {
        // Two users deliberately share a salt so that the old salt-scanning
        // lookup would resolve at most one identity correctly — the wrong
        // one for whichever user isn't hit first by map iteration order.
        // Authenticating BOTH users makes the test order-independent: the
        // old bug cannot satisfy both regardless of hash-map iteration order.
        SRPServer server;
        auto judy = SRPClient::register_user("judy", "pw-judy");
        auto karl = SRPClient::register_user("karl", "pw-karl");
        karl.salt = judy.salt;
        // Re-derive karl's verifier under the now-shared salt so the
        // collision is a legitimate one (internally-consistent salt/verifier
        // pair), rather than a corrupted credential that would fail SRP's
        // math regardless of the username-lookup bug this test targets.
        {
            SRPUtils::BigNum g(SRP_G_HEX);
            SRPUtils::BigNum N(SRP_N_HEX_2048);
            auto x    = SRPUtils::calculate_x(karl.salt, "karl", "pw-karl");
            karl.verifier = SRPUtils::calculate_verifier(g, x, N).to_bytes();
        }

        server.register_user("judy", judy);
        server.register_user("karl", karl);

        auto authenticate = [&server](const std::string& user, const std::string& pass) {
            SRPClient client(user, pass);
            const auto A         = client.generate_A();
            const auto challenge = server.init_authentication(user, A);
            const auto M         = client.process_challenge(challenge.B, challenge.salt);
            EXPECT_NO_THROW((void)server.verify_authentication(challenge.user_id, M));
        };

        authenticate("judy", "pw-judy");
        authenticate("karl", "pw-karl");
    }

    TEST(SrpTest, RejectZeroURejectsZero)
    {
        // Both SRPServer::verify_authentication and SRPClient::process_challenge
        // route their u == 0 check through this exact function, so this test
        // exercises the real guard, not a lookalike. Forcing a genuine u == 0
        // through the real protocol requires a SHA-256 preimage — infeasible
        // to construct in a test — hence testing the extracted guard directly.
        SRPUtils::BigNum zero_u;
        EXPECT_THROW(SRPUtils::reject_zero_u(zero_u), std::runtime_error);
    }

    TEST(SrpTest, RejectZeroUAcceptsOrdinaryU)
    {
        auto server = make_server_with_user("mallory", "pw");
        SRPClient client("mallory", "pw");

        const auto A         = client.generate_A();
        const auto challenge = server.init_authentication("mallory", A);

        SRPUtils::BigNum A_bn(A);
        SRPUtils::BigNum B_bn(challenge.B);
        auto u = SRPUtils::calculate_u(A_bn, B_bn);

        EXPECT_NO_THROW(SRPUtils::reject_zero_u(u));
    }
} // namespace chat::auth
