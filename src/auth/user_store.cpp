#include "chat/auth/user_store.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <utility>

#include "chat/auth/srp_utils.hpp"

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace chat::auth
{
    UserStore::UserStore(std::string path)
        : path_(std::move(path))
    {
    }

    UserStore::UserStore(UserStore&& other) noexcept
    {
        std::lock_guard<std::mutex> lock(other.mutex_);
        path_  = std::move(other.path_);
        users_ = std::move(other.users_);
    }

    UserStore& UserStore::operator=(UserStore&& other) noexcept
    {
        if (this != &other)
        {
            std::scoped_lock lock(mutex_, other.mutex_);
            path_  = std::move(other.path_);
            users_ = std::move(other.users_);
        }
        return *this;
    }

    bool UserStore::is_valid_username(const std::string& username)
    {
        if (username.empty() || username.size() > kMaxUsernameLength)
            return false;

        return std::ranges::all_of(username, [](const unsigned char c) {
            return std::isalnum(c) || c == '_' || c == '-';
        });
    }

    void UserStore::load()
    {
        if (path_.empty())
            return;

        std::ifstream file(path_);
        if (!file.is_open())
            return; // no database yet — first run

        std::unordered_map<std::string, UserCredentials> loaded;

        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#')
                continue;

            std::istringstream iss(line);
            std::string username, salt_hex, verifier_hex;
            if (!std::getline(iss, username, ':') ||
                !std::getline(iss, salt_hex, ':') ||
                !std::getline(iss, verifier_hex))
                continue; // malformed line — skip, do not half-load it

            if (!is_valid_username(username) || salt_hex.empty() || verifier_hex.empty())
                continue;

            try {
                loaded[username] = UserCredentials{
                    .username = username,
                    .salt = SRPUtils::hex_to_bytes(salt_hex),
                    .verifier = SRPUtils::hex_to_bytes(verifier_hex)
                };
            }
            catch (const std::exception&) {
                continue; // non-hex payload — skip
            }
        }

        std::lock_guard<std::mutex> lock(mutex_);
        users_ = std::move(loaded);
    }

    void UserStore::save() const
    {
        if (path_.empty())
            return;

        const std::string tmp_path = path_ + ".tmp";

        {
            std::ofstream file(tmp_path, std::ios::trunc);
            if (!file.is_open())
                throw std::runtime_error("Failed to open user database for writing");

            std::lock_guard<std::mutex> lock(mutex_);

            file << "# SRP User Database\n";
            file << "# Format: username:salt_hex:verifier_hex\n";
            for (const auto& [username, creds] : users_)
                file << username << ":"
                     << SRPUtils::bytes_to_hex(creds.salt) << ":"
                     << SRPUtils::bytes_to_hex(creds.verifier) << "\n";

            file.flush();
            if (!file)
                throw std::runtime_error("Failed to write user database");
        }

#ifndef _WIN32
        // Credentials are verifiers, not passwords, but they are still
        // offline-attackable. Keep them owner-readable only.
        ::chmod(tmp_path.c_str(), S_IRUSR | S_IWUSR);
#endif

        // Rename over the target so a crash mid-write cannot destroy the
        // existing database.
        std::error_code ec;
        std::filesystem::rename(tmp_path, path_, ec);
        if (ec) {
            std::filesystem::remove(tmp_path, ec);
            throw std::runtime_error("Failed to replace user database");
        }
    }

    bool UserStore::insert(const UserCredentials& creds)
    {
        if (!is_valid_username(creds.username))
            return false;

        std::lock_guard<std::mutex> lock(mutex_);
        return users_.emplace(creds.username, creds).second;
    }

    bool UserStore::contains(const std::string& username) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return users_.contains(username);
    }

    std::optional<UserCredentials> UserStore::find(const std::string& username) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (const auto it = users_.find(username); it != users_.end())
            return it->second;
        return std::nullopt;
    }

    size_t UserStore::size() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return users_.size();
    }
} // namespace chat::auth
