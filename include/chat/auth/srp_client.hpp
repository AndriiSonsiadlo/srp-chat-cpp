#pragma once

#include <string>
#include <vector>
#include <memory>

#include "chat/auth/srp_types.hpp"
#include "chat/auth/srp_utils.hpp"

namespace chat::auth
{
    /**
     * SRP-6a Client Implementation
     * Handles client-side authentication flow
     */
    class SRPClient
    {
    private:
        std::string username_;
        std::string* password_;

        // SRP parameters
        std::unique_ptr<SRPUtils::BigNum> N_; // safe prime
        std::unique_ptr<SRPUtils::BigNum> g_; // generator
        std::unique_ptr<SRPUtils::BigNum> k_; // multiplier k = H(N, g)

        // client ephemeral values
        std::unique_ptr<SRPUtils::BigNum> a_; // private ephemeral
        std::unique_ptr<SRPUtils::BigNum> A_; // public ephemeral A = g^a mod N

        // server values
        std::vector<uint8_t> salt_;
        std::unique_ptr<SRPUtils::BigNum> B_; // server's public ephemeral

        // session key
        std::vector<uint8_t> K_;

        // proof
        std::vector<uint8_t> M_;

        bool authenticated_{false};

    public:
        SRPClient(std::string username, std::string *password);
        ~SRPClient();

        // step 1: generate client's public ephemeral value A
        std::vector<uint8_t> generate_A();

        // step 2: process server's challenge (B, salt)
        // returns client proof M
        std::vector<uint8_t> process_challenge(const std::vector<uint8_t>& B, const std::vector<uint8_t>& salt);

        // step 3: verify server's proof H_AMK
        bool verify_server(const std::vector<uint8_t>& H_AMK);

        // get session key after successful authentication
        [[nodiscard]] std::vector<uint8_t> get_session_key() const { return K_; }

        [[nodiscard]] bool is_authenticated() const { return authenticated_; }

        // static helper: register new user (generate salt and verifier)
        static UserCredentials register_user(const std::string& username, const std::string& password);
    };
} // namespace chat::auth
