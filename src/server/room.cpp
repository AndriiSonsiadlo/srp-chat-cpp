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

    bool Room::try_join(const std::string& user_id,
                        const std::string& username,
                        std::shared_ptr<Sink> sink,
                        std::vector<uint8_t> key)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        const bool taken = std::ranges::any_of(members_, [&username](const auto& entry) {
            return entry.second.username == username;
        });
        if (taken)
            return false;

        members_[user_id] = Member{std::move(sink), username, std::move(key)};
        return true;
    }

    void Room::leave(const std::string& user_id)
    {
        std::shared_ptr<Sink> departing;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (const auto it = members_.find(user_id); it != members_.end()) {
                departing = it->second.sink;
                members_.erase(it);
            }
        }

        if (departing)
            departing->close();
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

            outbox.reserve(members_.size());
            for (const auto& [user_id, member] : members_) {
                try {
                    const auto sealed = crypto::AESEngine::encrypt_string(text, member.key);
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
        {
            std::lock_guard<std::mutex> lock(mutex_);

            const auto it = members_.find(user_id);
            if (it == members_.end())
                return Protocol::encode(MessageType::INIT, InitMsg{});

            const auto& key = it->second.key;

            init.messages.reserve(history_.size());
            for (const auto& item : history_) {
                try {
                    const auto sealed = crypto::AESEngine::encrypt_string(item.text, key);
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
