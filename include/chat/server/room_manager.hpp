#pragma once

#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "chat/common/messages.hpp"
#include "chat/server/room.hpp"
#include "chat/server/room_name.hpp"
#include "chat/server/sink.hpp"

namespace chat::server
{
    enum class JoinStatus
    {
        Ok,
        NoSuchRoom,
        PasswordRequired,
        WrongPassword,
        RoomFull,
        NameTaken,
        TooManyRooms,
    };

    struct JoinResult
    {
        JoinStatus status;
        std::shared_ptr<Room> room; // null unless status == Ok
    };

    /**
     * Owns every room and their lifetimes.
     *
     * `lobby` is created here and pinned: it always exists, is always public,
     * and drop_if_empty() will not remove it.
     *
     * Lock ordering: this mutex may be taken before a Room's mutex, never
     * after. Room methods only enqueue on sinks — no socket I/O — so the
     * nested hold is microseconds.
     */
    class RoomManager
    {
    public:
        RoomManager(size_t max_rooms, size_t max_members);

        // Find, password check, capacity check, and Room::join happen in one
        // critical section. Doing them as separate calls would let the room
        // empty and be dropped in between, stranding the joiner in a room that
        // is no longer reachable from the map.
        JoinResult join(const std::string& name,
                        const std::string& password,
                        const std::string& user_id,
                        const std::string& username,
                        std::shared_ptr<Sink> sink,
                        std::vector<uint8_t> key);

        // Creating implies joining: a separate join would cost a round trip and
        // could land the creator in someone else's room of the same name.
        JoinResult create_and_join(const std::string& name,
                                   const std::string& password,
                                   const std::string& user_id,
                                   const std::string& username,
                                   std::shared_ptr<Sink> sink,
                                   std::vector<uint8_t> key);

        [[nodiscard]] std::shared_ptr<Room> find(const std::string& name) const;
        [[nodiscard]] std::vector<RoomInfo> list() const;

        // No-op for the lobby and for a room that still has members.
        void drop_if_empty(const std::string& name);

    private:
        const size_t max_rooms_;
        const size_t max_members_;

        mutable std::mutex mutex_;
        std::unordered_map<std::string, std::shared_ptr<Room>> rooms_;
    };
} // namespace chat::server
