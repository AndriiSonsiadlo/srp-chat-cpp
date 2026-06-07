#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>

#include "chat/auth/srp_types.hpp"
#include "chat/auth/srp_utils.hpp"

namespace chat::auth
{
    /**
     * SRP-6a Server Implementation
     * Handles server-side authentication and session management
     */
    class SRPServer
    {
    private:
        // SRP parameters (shared)
        std::unique_ptr<SRPUtils::BigNum> N_; // safe prime
        std::unique_ptr<SRPUtils::BigNum> g_; // generator
        std::unique_ptr<SRPUtils::BigNum> k_; // multiplier k = H(N, g)

        // user credentials database
        std::unordered_map<std::string, UserCredentials> users_;
        std::mutex users_mutex_;

        // active SRP sessions
        std::unordered_map<std::string, SRPSession> sessions_;
        mutable std::mutex sessions_mutex_;

        // room salt for message encryption (shared by all users)
        std::vector<uint8_t> room_salt_;

    public:
        SRPServer();
        explicit SRPServer(const std::vector<uint8_t>& room_salt);
        ~SRPServer();

        // Movable (mutexes are not moved, they start fresh), not copyable.
        SRPServer(SRPServer&& other) noexcept;
        SRPServer& operator=(SRPServer&& other) noexcept;
        SRPServer(const SRPServer&)            = delete;
        SRPServer& operator=(const SRPServer&) = delete;

        // user management
        bool register_user(const std::string& username, const UserCredentials& creds);
        bool user_exists(const std::string& username);
        void remove_user(const std::string& username);

        // load/save user database
        void load_users(const std::string& filepath);
        void save_users(const std::string& filepath);

        // authentication flow
        // step 1: Initialize authentication for a user
        // returns: user_id, B (server's public ephemeral), salt
        struct ChallengeResponse
        {
            std::string user_id;
            std::vector<uint8_t> B;
            std::vector<uint8_t> salt;
            std::vector<uint8_t> room_salt;
        };

        ChallengeResponse init_authentication(
            const std::string& username,
            const std::vector<uint8_t>& A);

        // step 2: verify client's proof M
        // returns: H_AMK (server proof)
        struct VerifyResponse
        {
            std::vector<uint8_t> H_AMK;
        };

        VerifyResponse verify_authentication(
            const std::string& user_id,
            const std::vector<uint8_t>& M);

        // AES-256-GCM key for this session: HKDF(K, salt = room_salt, info = kSessionKeyInfo).
        // Never transmitted. Throws if the session is unknown or not yet authenticated.
        [[nodiscard]] std::vector<uint8_t> derive_session_key(const std::string& user_id) const;

        // session management
        bool is_session_valid(const std::string& user_id);
        void clear_session(const std::string& user_id);
        void clear_expired_sessions(int timeout_seconds = 3600);

        [[nodiscard]] std::vector<uint8_t> get_room_salt() const { return room_salt_; }

    private:
        [[nodiscard]] std::string generate_user_id() const;
    };
} // namespace chat::auth
