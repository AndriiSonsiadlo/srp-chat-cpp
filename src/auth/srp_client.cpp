#include "chat/auth/srp_client.hpp"

#include <stdexcept>

#include "chat/auth/srp_types.hpp"

namespace chat::auth
{
    SRPClient::SRPClient(std::string username, std::string* password)
        : username_(std::move(username))
          , password_(password)
    {
        // initialize SRP parameters
        N_ = std::make_unique<SRPUtils::BigNum>(SRP_N_HEX_2048);
        g_ = std::make_unique<SRPUtils::BigNum>(SRP_G_HEX);
        k_ = std::make_unique<SRPUtils::BigNum>(SRPUtils::calculate_k(*N_, *g_));
    }

    SRPClient::~SRPClient() = default;

    std::vector<uint8_t> SRPClient::generate_A()
    {
        // generate random private ephemeral 'a'
        auto a_bytes = SRPUtils::random_bytes(32); // 256-bit random
        a_           = std::make_unique<SRPUtils::BigNum>(a_bytes);

        // calculate A = g^a mod N
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create BN_CTX");

        A_ = std::make_unique<SRPUtils::BigNum>();
        if (!BN_mod_exp(A_->get(), g_->get(), a_->get(), N_->get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate A = g^a mod N");
        }

        BN_CTX_free(ctx);
        return A_->to_bytes();
    }

    std::vector<uint8_t> SRPClient::process_challenge(
        const std::vector<uint8_t>& B,
        const std::vector<uint8_t>& salt)
    {
        if (!A_) throw std::runtime_error("Must call generate_A() first");

        salt_ = salt;
        B_    = std::make_unique<SRPUtils::BigNum>(B);

        // calculate u = H(A, B)
        auto u = SRPUtils::calculate_u(*A_, *B_);

        // calculate x = H(salt, H(username, ":", password))
        auto x = SRPUtils::calculate_x(salt_, username_, *password_);

        // calculate S = (B - kg^x)^(a + ux) mod N
        auto S = SRPUtils::calculate_S_client(*N_, *B_, *k_, *g_, x, *a_, u);

        // calculate K = H(S)
        K_ = SRPUtils::calculate_K(S);

        // calculate M = H(H(N) XOR H(g), H(username), salt, A, B, K)
        M_ = SRPUtils::calculate_M(*N_, *g_, username_, salt_, *A_, *B_, K_);

        return M_;
    }

    bool SRPClient::verify_server(const std::vector<uint8_t>& H_AMK)
    {
        if (M_.empty() || K_.empty())
            throw std::runtime_error("Must call process_challenge() first");

        // calculate expected H_AMK = H(A, M, K)
        auto expected_H_AMK = SRPUtils::calculate_H_AMK(*A_, M_, K_);

        // constant-time comparison
        if (H_AMK.size() != expected_H_AMK.size())
            return false;

        uint8_t diff = 0;
        for (size_t i = 0; i < H_AMK.size(); ++i)
            diff |= H_AMK[i] ^ expected_H_AMK[i];

        authenticated_ = (diff == 0);
        return authenticated_;
    }

    UserCredentials SRPClient::register_user(const std::string& username, const std::string& password)
    {
        // generate random salt
        auto salt = SRPUtils::random_bytes(SRP_SALT_SIZE);

        // calculate x = H(salt, H(username, ":", password))
        auto x = SRPUtils::calculate_x(salt, username, password);

        // calculate verifier v = g^x mod N
        SRPUtils::BigNum N(SRP_N_HEX_2048);
        SRPUtils::BigNum g(SRP_G_HEX);
        auto v = SRPUtils::calculate_verifier(g, x, N);

        return UserCredentials{
            .username = username,
            .salt = salt,
            .verifier = v.to_bytes()
        };
    }
} // namespace chat::auth
