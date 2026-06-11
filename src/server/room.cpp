#include "chat/server/room.hpp"

#include <algorithm>
#include <utility>

#include "chat/auth/srp_utils.hpp"
#include "chat/common/log.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"
#include "chat/crypto/aes_engine.hpp"

namespace chat::server
{
    namespace
    {
        int64_t now_ms()
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }
    }

    Room::Room(std::string name, const std::string& password)
        : name_(std::move(name))
    {
        if (password.empty())
            return;

        // Not PBKDF2: this hash never reaches disk, it lives in a room that ceases
        // to exist when empty, and verification runs under the RoomManager mutex
        // where a deliberately slow KDF would stall every other room operation.
        // See docs/superpowers/specs/2026-08-10-multi-room-chat-design.md.
        salt_          = auth::SRPUtils::random_bytes(16);
        password_hmac_ = auth::SRPUtils::hmac_sha256(
            salt_, std::vector<uint8_t>(password.begin(), password.end()));
    }

    bool Room::verify_password(const std::string& password) const
    {
        if (password_hmac_.empty())
            return true;

        const auto candidate = auth::SRPUtils::hmac_sha256(
            salt_, std::vector<uint8_t>(password.begin(), password.end()));
        return auth::SRPUtils::constant_time_equals(candidate, password_hmac_);
    }

    void Room::join(const std::string& user_id,
                    const std::string& username,
                    std::shared_ptr<Sink> sink,
                    std::vector<uint8_t> key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        members_[user_id] = Member{std::move(sink), username, std::move(key)};
    }

    void Room::leave(const std::string& user_id)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        members_.erase(user_id);
    }

    bool Room::username_online(const std::string& username) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::ranges::any_of(members_, [&username](const auto& entry) {
            return entry.second.username == username;
        });
    }

    std::string Room::username_of(const std::string& user_id) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (const auto it = members_.find(user_id); it != members_.end())
            return it->second.username;
        return "";
    }

    std::vector<User> Room::active_users() const
    {
        std::lock_guard<std::mutex> lock(mutex_);

        std::vector<User> users;
        users.reserve(members_.size());
        for (const auto& [user_id, member] : members_)
            users.emplace_back(member.username, user_id);
        return users;
    }

    size_t Room::size() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return members_.size();
    }

    void Room::record_and_broadcast(const std::string& username, const std::string& text)
    {
        const auto timestamp_ms = now_ms();

        // Build every packet under the lock, but hand them to the sinks after
        // releasing it — send() is non-blocking by contract, yet keeping the
        // critical section to pure computation keeps that contract cheap.
        std::vector<std::pair<std::shared_ptr<Sink>, std::vector<uint8_t>>> outbox;
        {
            std::lock_guard<std::mutex> lock(mutex_);

            history_.push_back(HistoryItem{username, text, timestamp_ms});
            while (history_.size() > kMaxHistory)
                history_.pop_front();

            // Bind the ciphertext to its sender: without this AAD, an on-path
            // attacker could take a valid ciphertext and re-attribute it to a
            // different username (the GCM tag alone only covers the message text).
            const std::vector<uint8_t> aad(username.begin(), username.end());

            outbox.reserve(members_.size());
            for (const auto& [user_id, member] : members_) {
                try {
                    const auto sealed = crypto::AESEngine::encrypt_string(text, member.key, aad);
                    outbox.emplace_back(
                        member.sink,
                        Protocol::encode(
                            MessageType::BROADCAST,
                            BroadcastMsg{username,
                                         auth::SRPUtils::bytes_to_base64(sealed),
                                         timestamp_ms}));
                }
                catch (const std::exception& e) {
                    log::warn("failed to seal broadcast for " + user_id + ": " + e.what());
                }
            }
        }

        for (auto& [sink, packet] : outbox)
            sink->send(std::move(packet));
    }

    void Room::broadcast_packet(const std::vector<uint8_t>& packet, const std::string& exclude_user_id)
    {
        std::vector<std::shared_ptr<Sink>> targets;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            targets.reserve(members_.size());
            for (const auto& [user_id, member] : members_)
                if (user_id != exclude_user_id)
                    targets.push_back(member.sink);
        }

        for (const auto& sink : targets)
            sink->send(packet);
    }

    std::vector<uint8_t> Room::init_packet_for(const std::string& user_id) const
    {
        InitMsg init;
        init.room = name_;
        {
            std::lock_guard<std::mutex> lock(mutex_);

            const auto it = members_.find(user_id);
            if (it == members_.end())
                return Protocol::encode(MessageType::INIT, init);

            const auto& key = it->second.key;

            init.messages.reserve(history_.size());
            for (const auto& item : history_) {
                try {
                    const std::vector<uint8_t> aad(item.username.begin(), item.username.end());
                    const auto sealed = crypto::AESEngine::encrypt_string(item.text, key, aad);
                    init.messages.push_back(HistoryEntry{
                        item.username,
                        auth::SRPUtils::bytes_to_base64(sealed),
                        item.timestamp_ms});
                }
                catch (const std::exception& e) {
                    log::warn(std::string("failed to seal history entry: ") + e.what());
                }
            }

            init.users.reserve(members_.size());
            for (const auto& [member_id, member] : members_)
                init.users.emplace_back(member.username, member_id);
        }

        return Protocol::encode(MessageType::INIT, init);
    }
} // namespace chat::server
