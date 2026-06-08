#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "chat/common/types.hpp"
#include "chat/server/sink.hpp"

namespace chat::server
{
    /**
     * The chat room: who is present, their message keys, and recent history.
     *
     * Every method that fans out to members enqueues on each Sink and returns.
     * No socket I/O happens under the mutex, so one slow reader cannot stall
     * the others.
     */
    class Room
    {
    public:
        static constexpr size_t kMaxHistory = 100;

        void join(const std::string& user_id,
                  const std::string& username,
                  std::shared_ptr<Sink> sink,
                  std::vector<uint8_t> key);
        void leave(const std::string& user_id);

        [[nodiscard]] bool username_online(const std::string& username) const;
        [[nodiscard]] std::string username_of(const std::string& user_id) const;
        [[nodiscard]] std::vector<User> active_users() const;
        [[nodiscard]] size_t size() const;

        // Appends to history and delivers to every member, each under their own key.
        void record_and_broadcast(const std::string& username, const std::string& text);

        // Delivers a prebuilt packet to everyone except `exclude_user_id`.
        void broadcast_packet(const std::vector<uint8_t>& packet,
                              const std::string& exclude_user_id = "");

        // INIT packet for one member: history sealed with that member's key,
        // plus the current roster. Returns an empty INIT for an unknown user.
        [[nodiscard]] std::vector<uint8_t> init_packet_for(const std::string& user_id) const;

    private:
        struct Member
        {
            std::shared_ptr<Sink> sink;
            std::string username;
            std::vector<uint8_t> key;
        };

        struct HistoryItem
        {
            std::string username;
            std::string text;
            int64_t timestamp_ms;
        };

        mutable std::mutex mutex_;
        std::unordered_map<std::string, Member> members_;
        std::deque<HistoryItem> history_;
    };
} // namespace chat::server
