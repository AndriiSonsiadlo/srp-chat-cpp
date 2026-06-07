#include "chat/auth/srp_client.hpp"
#include "chat/auth/srp_server.hpp"
#include "chat/auth/srp_types.hpp"
#include "chat/crypto/aes_engine.hpp"

#include <gtest/gtest.h>

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
} // namespace chat::auth
