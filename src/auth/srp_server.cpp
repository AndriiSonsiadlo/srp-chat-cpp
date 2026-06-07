#include "chat/auth/srp_server.hpp"
#include "chat/auth/srp_types.hpp"
#include "chat/crypto/aes_engine.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <chrono>
#include <algorithm>

namespace chat::auth
{
    SRPServer::SRPServer()
        : SRPServer(SRPUtils::random_bytes(SRP_SALT_SIZE))
    {
    }

    SRPServer::SRPServer(const std::vector<uint8_t>& room_salt)
        : room_salt_(room_salt)
    {
        // initialize SRP parameters
        N_ = std::make_unique<SRPUtils::BigNum>(SRP_N_HEX_2048);
        g_ = std::make_unique<SRPUtils::BigNum>(SRP_G_HEX);
        k_ = std::make_unique<SRPUtils::BigNum>(SRPUtils::calculate_k(*N_, *g_));
    }

    SRPServer::~SRPServer() = default;

    SRPServer::SRPServer(SRPServer&& other) noexcept
        : N_(std::move(other.N_))
          , g_(std::move(other.g_))
          , k_(std::move(other.k_))
          , users_(std::move(other.users_))
          , sessions_(std::move(other.sessions_))
          , room_salt_(std::move(other.room_salt_))
    {
    }

    SRPServer& SRPServer::operator=(SRPServer&& other) noexcept
    {
        if (this != &other)
        {
            N_         = std::move(other.N_);
            g_         = std::move(other.g_);
            k_         = std::move(other.k_);
            users_     = std::move(other.users_);
            sessions_  = std::move(other.sessions_);
            room_salt_ = std::move(other.room_salt_);
        }
        return *this;
    }

    bool SRPServer::register_user(const std::string& username, const UserCredentials& creds)
    {
        // user already exists
        if (user_exists(username)) return false;

        std::lock_guard<std::mutex> lock(users_mutex_);
        users_[username] = creds;
        return true;
    }

    bool SRPServer::user_exists(const std::string& username)
    {
        std::lock_guard<std::mutex> lock(users_mutex_);
        return users_.find(username) != users_.end();
    }

    void SRPServer::remove_user(const std::string& username)
    {
        std::lock_guard<std::mutex> lock(users_mutex_);
        users_.erase(username);
    }

    void SRPServer::load_users(const std::string& filepath)
    {
        std::ifstream file(filepath);
        if (!file.is_open())
            return; // file doesn't exist yet

        std::lock_guard<std::mutex> lock(users_mutex_);
        users_.clear();

        std::string line;
        while (std::getline(file, line))
        {
            if (line.empty() || line[0] == '#')
                continue;

            std::istringstream iss(line);
            std::string username, salt_hex, verifier_hex;

            if (std::getline(iss, username, ':') &&
                std::getline(iss, salt_hex, ':') &&
                std::getline(iss, verifier_hex))
            {
                UserCredentials creds;
                creds.username   = username;
                creds.salt       = SRPUtils::hex_to_bytes(salt_hex);
                creds.verifier   = SRPUtils::hex_to_bytes(verifier_hex);
                users_[username] = creds;
            }
        }
    }

    void SRPServer::save_users(const std::string& filepath)
    {
        std::ofstream file(filepath);
        if (!file.is_open())
            throw std::runtime_error("Failed to open user database for writing");

        std::lock_guard<std::mutex> lock(users_mutex_);

        file << "# SRP User Database\n";
        file << "# Format: username:salt_hex:verifier_hex\n";

        for (const auto& [username, creds] : users_)
        {
            file << username << ":"
                << SRPUtils::bytes_to_hex(creds.salt) << ":"
                << SRPUtils::bytes_to_hex(creds.verifier) << "\n";
        }
    }

    SRPServer::ChallengeResponse SRPServer::init_authentication(
        const std::string& username,
        const std::vector<uint8_t>& A)
    {
        // get user credentials
        UserCredentials creds;
        {
            std::lock_guard<std::mutex> lock(users_mutex_);
            auto it = users_.find(username);
            if (it == users_.end())
                throw std::runtime_error("User not found");
            creds = it->second;
        }

        // SRP-6a: A ≡ 0 (mod N) would force S = 0. Refuse it.
        const SRPUtils::BigNum A_bn(A);
        if (SRPUtils::is_zero_mod(A_bn, *N_))
            throw std::runtime_error("Invalid client ephemeral A");

        SRPSession session;
        session.user_id  = generate_user_id();
        session.username = username;
        session.A        = A;
        session.salt     = creds.salt;
        session.verifier = creds.verifier;

        // generate random private ephemeral 'b'
        auto b_bytes = SRPUtils::random_bytes(32); // 256-bit random
        session.b    = b_bytes;

        // calculate v (verifier)
        SRPUtils::BigNum v(creds.verifier);

        // calculate b
        SRPUtils::BigNum b(b_bytes);

        // calculate B = kv + g^b mod N
        auto B = SRPUtils::calculate_B(*k_, v, *g_, b, *N_);

        auto B_bytes    = B.to_bytes();
        session.B       = B_bytes;
        std::string user_id = session.user_id;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            sessions_[session.user_id] = std::move(session);
        }

        return ChallengeResponse{
            .user_id = user_id,
            .B = std::move(B_bytes),
            .salt = creds.salt,
            .room_salt = room_salt_
        };
    }

    SRPServer::VerifyResponse SRPServer::verify_authentication(
        const std::string& user_id,
        const std::vector<uint8_t>& M)
    {
        // get session
        SRPSession session;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            auto it = sessions_.find(user_id);
            if (it == sessions_.end())
                throw std::runtime_error("Invalid session");
            session = it->second;
        }

        // convert to BigNum
        SRPUtils::BigNum A(session.A);
        SRPUtils::BigNum B(session.B);
        SRPUtils::BigNum b(session.b);
        SRPUtils::BigNum v(session.verifier);

        // calculate u = H(A, B)
        auto u = SRPUtils::calculate_u(A, B);
        SRPUtils::reject_zero_u(u);

        // calculate S = (A * v^u)^b mod N
        auto S = SRPUtils::calculate_S_server(A, v, u, b, *N_);

        // calculate K = H(S)
        auto K    = SRPUtils::calculate_K(S);
        session.K = K;

        auto expected_M = SRPUtils::calculate_M(
            *N_, *g_, session.username, session.salt, A, B, K);

        if (!SRPUtils::constant_time_equals(M, expected_M))
            throw std::runtime_error("Authentication failed");

        // authentication successful
        session.authenticated = true;

        // calculate H_AMK = H(A, M, K)
        auto H_AMK = SRPUtils::calculate_H_AMK(A, M, K);

        // update session (K is retained so the AES key can be derived locally)
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            sessions_[user_id] = session;
        }

        return VerifyResponse{.H_AMK = H_AMK};
    }

    std::vector<uint8_t> SRPServer::derive_session_key(const std::string& user_id) const
    {
        std::vector<uint8_t> K;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            const auto it = sessions_.find(user_id);
            if (it == sessions_.end() || !it->second.authenticated)
                throw std::runtime_error("No authenticated session for this user id");
            K = it->second.K;
        }

        return crypto::AESEngine::derive_key(K, room_salt_, kSessionKeyInfo);
    }

    bool SRPServer::is_session_valid(const std::string& user_id)
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(user_id);
        return it != sessions_.end() && it->second.authenticated;
    }

    void SRPServer::clear_session(const std::string& user_id)
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_.erase(user_id);
    }

    void SRPServer::clear_expired_sessions(const int timeout_seconds)
    {
        const auto cutoff = std::chrono::steady_clock::now()
                          - std::chrono::seconds(timeout_seconds);

        std::lock_guard<std::mutex> lock(sessions_mutex_);
        std::erase_if(sessions_, [cutoff](const auto& entry) {
            return entry.second.created_at <= cutoff;
        });
    }

    std::string SRPServer::generate_user_id() const
    {
        return "user_" + SRPUtils::random_hex_id(16);
    }
} // namespace chat::auth
