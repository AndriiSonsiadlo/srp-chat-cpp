#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>

namespace chat::server
{
    inline constexpr size_t kMaxRoomNameLength = 32;

    // The room every session joins at login and returns to on /leave. Always
    // exists, never has a password, is never dropped when empty.
    inline constexpr const char* kDefaultRoom = "lobby";

    // Same character class as UserStore::is_valid_username: this string is echoed
    // to every other client in the room list, so it must not carry control
    // characters or ANSI escapes.
    inline bool is_valid_room_name(const std::string& name)
    {
        if (name.empty() || name.size() > kMaxRoomNameLength)
            return false;

        return std::ranges::all_of(name, [](const unsigned char c) {
            return std::isalnum(c) || c == '_' || c == '-';
        });
    }

    // Map key for RoomManager. Names are unique case-insensitively while the Room
    // keeps the creator's casing for display, so "Dev" and "dev" are one room.
    inline std::string room_key(const std::string& name)
    {
        std::string key = name;
        std::ranges::transform(key, key.begin(), [](const unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return key;
    }
} // namespace chat::server
