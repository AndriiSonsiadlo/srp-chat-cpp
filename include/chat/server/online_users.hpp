#pragma once

#include <mutex>
#include <string>
#include <unordered_set>

namespace chat::server
{
    /**
     * The set of accounts currently logged in, server-wide.
     *
     * This is what stops one account holding two sessions. It used to be a
     * side effect of Room::try_join refusing a duplicate username, which only
     * worked while there was exactly one room: alice in `lobby` and alice in
     * `dev` would otherwise both succeed.
     */
    class OnlineUsers
    {
    public:
        // Atomic check-and-insert. False means the account is already logged in.
        bool try_claim(const std::string& username)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return names_.insert(username).second;
        }

        // Safe to call for a name that was never claimed — the disconnect path
        // runs for sessions that failed before login.
        void release(const std::string& username)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            names_.erase(username);
        }

        [[nodiscard]] bool is_online(const std::string& username) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return names_.contains(username);
        }

    private:
        mutable std::mutex mutex_;
        std::unordered_set<std::string> names_;
    };
} // namespace chat::server
