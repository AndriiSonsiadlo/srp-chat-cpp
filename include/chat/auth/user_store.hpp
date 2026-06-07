#pragma once

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "chat/auth/srp_types.hpp"

namespace chat::auth
{
    /**
     * Credential persistence, split out of SRPServer so that protocol state and
     * on-disk state have separate lifetimes and separate tests.
     *
     * File format, one user per line: username:salt_hex:verifier_hex
     * An empty path means in-memory only; load() and save() become no-ops.
     */
    class UserStore
    {
    public:
        static constexpr size_t kMaxUsernameLength = 32;

        explicit UserStore(std::string path = "");

        // Movable (the mutex is not moved, it starts fresh), not copyable —
        // mirrors SRPServer's move semantics so it can live as a plain member.
        UserStore(UserStore&& other) noexcept;
        UserStore& operator=(UserStore&& other) noexcept;
        UserStore(const UserStore&)            = delete;
        UserStore& operator=(const UserStore&) = delete;

        void load();
        void save() const;

        bool insert(const UserCredentials& creds);
        [[nodiscard]] bool contains(const std::string& username) const;
        [[nodiscard]] std::optional<UserCredentials> find(const std::string& username) const;
        [[nodiscard]] size_t size() const;

        // A username must round-trip through the colon-delimited format and
        // must not be able to forge a second record.
        [[nodiscard]] static bool is_valid_username(const std::string& username);

    private:
        std::string path_;
        std::unordered_map<std::string, UserCredentials> users_;
        mutable std::mutex mutex_;
    };
} // namespace chat::auth
