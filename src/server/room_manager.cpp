#include "chat/server/room_manager.hpp"

#include <utility>

namespace chat::server
{
    RoomManager::RoomManager(const size_t max_rooms, const size_t max_members)
        : max_rooms_(max_rooms)
          , max_members_(max_members)
    {
        rooms_[room_key(kDefaultRoom)] = std::make_shared<Room>(kDefaultRoom);
    }

    JoinResult RoomManager::join(const std::string& name,
                                 const std::string& password,
                                 const std::string& user_id,
                                 const std::string& username,
                                 std::shared_ptr<Sink> sink,
                                 std::vector<uint8_t> key)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        const auto it = rooms_.find(room_key(name));
        if (it == rooms_.end())
            return {JoinStatus::NoSuchRoom, nullptr};

        const auto& room = it->second;

        // Distinguished from WrongPassword so the session can decline to charge
        // this against the wrong-password budget: it is the ordinary first step
        // when a client's cached room list is stale.
        if (room->has_password() && password.empty())
            return {JoinStatus::PasswordRequired, nullptr};

        if (!room->verify_password(password))
            return {JoinStatus::WrongPassword, nullptr};

        if (room->size() >= max_members_)
            return {JoinStatus::RoomFull, nullptr};

        room->join(user_id, username, std::move(sink), std::move(key));
        return {JoinStatus::Ok, room};
    }

    JoinResult RoomManager::create_and_join(const std::string& name,
                                            const std::string& password,
                                            const std::string& user_id,
                                            const std::string& username,
                                            std::shared_ptr<Sink> sink,
                                            std::vector<uint8_t> key)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        const auto key_name = room_key(name);
        if (rooms_.contains(key_name))
            return {JoinStatus::NameTaken, nullptr};

        if (rooms_.size() >= max_rooms_)
            return {JoinStatus::TooManyRooms, nullptr};

        auto room = std::make_shared<Room>(name, password);
        room->join(user_id, username, std::move(sink), std::move(key));
        rooms_[key_name] = room;

        return {JoinStatus::Ok, std::move(room)};
    }

    std::shared_ptr<Room> RoomManager::find(const std::string& name) const
    {
        std::lock_guard<std::mutex> lock(mutex_);

        const auto it = rooms_.find(room_key(name));
        return it == rooms_.end() ? nullptr : it->second;
    }

    std::vector<RoomInfo> RoomManager::list() const
    {
        std::lock_guard<std::mutex> lock(mutex_);

        std::vector<RoomInfo> infos;
        infos.reserve(rooms_.size());
        for (const auto& [key_name, room] : rooms_)
            infos.push_back(RoomInfo{
                room->name(),
                static_cast<uint32_t>(room->size()),
                static_cast<uint8_t>(room->has_password() ? 1 : 0)});

        return infos;
    }

    void RoomManager::drop_if_empty(const std::string& name)
    {
        const auto key_name = room_key(name);
        if (key_name == room_key(kDefaultRoom))
            return;

        std::lock_guard<std::mutex> lock(mutex_);

        if (const auto it = rooms_.find(key_name); it != rooms_.end() && it->second->size() == 0)
            rooms_.erase(it);
    }
} // namespace chat::server
