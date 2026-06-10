# Multi-Room Chat Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the chat server multiple named rooms, optionally password-protected, created on demand by any authenticated user and dropped when empty.

**Architecture:** A new `RoomManager` owns a name-keyed map of `shared_ptr<Room>` and performs find + password check + join inside one critical section. `Room` keeps its existing shape and gains a name and a salted HMAC of its password. The duplicate-login check moves out of `Room` into a server-wide `OnlineUsers` registry. Four new protocol messages carry list/create/join; the existing `INIT` packet answers a join and now names the room.

**Tech Stack:** C++20, Boost.Asio (coroutines), OpenSSL (AES-256-GCM, HMAC-SHA256), GoogleTest, CMake + Ninja + vcpkg.

**Spec:** `docs/superpowers/specs/2026-08-10-multi-room-chat-design.md`

## Global Constraints

- **C++20**, no compiler extensions. Warnings are `-Wall -Wextra -Wpedantic -Wshadow`; keep the build warning-clean.
- **No new dependencies.** Everything needed is already in `vcpkg.json` (boost-asio, boost-system, openssl, gtest). Do not add PDCurses/ncurses — the TUI is a separate spec.
- **Branch:** `rooms` (already checked out, holds the design doc commit).
- **Build:** `cmake --preset debug && cmake --build --preset debug`
- **Test:** `ctest --preset debug`, or a single binary directly: `./build/debug/room_tests --gtest_filter=RoomTest.Foo`
- **Naming:** room names are 1–32 chars of `[A-Za-z0-9_-]`, unique case-insensitively. The default room is `lobby`.
- **Caps:** default 64 rooms, 64 members per room, 5 wrong room-password attempts per session.
- **Commit style:** `feat:`, `fix:`, `test:`, `docs:` prefixes, matching existing history. Commit at the end of every task.
- **Crypto:** reuse `auth::SRPUtils::hmac_sha256`, `random_bytes`, `constant_time_equals`. Do not hand-roll comparisons or hashing.
- **Never log plaintext** message text or passwords. Log sizes and usernames only, matching the existing `session.cpp` style.

---

### Task 1: Room vocabulary — protocol messages and name validation

Pure data and pure functions. Nothing behavioral yet, so everything here is directly unit-testable.

**Files:**
- Modify: `include/chat/common/types.hpp` (bump version, add 4 enum values)
- Modify: `include/chat/common/messages.hpp` (add 3 structs, extend `InitMsg`)
- Create: `include/chat/server/room_name.hpp`
- Modify: `tests/wire_tests.cpp`
- Create: `tests/room_name_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: nothing.
- Produces: `MessageType::{ROOM_LIST_REQ, ROOM_LIST, ROOM_CREATE, ROOM_JOIN}`; `chat::RoomInfo{std::string name; uint32_t user_count; uint8_t has_password;}`; `chat::RoomListMsg{std::vector<RoomInfo> rooms;}`; `chat::RoomCreateMsg{std::string name; std::string password_ct_b64;}`; `chat::RoomJoinMsg{std::string name; std::string password_ct_b64;}`; `chat::InitMsg` with a new leading `std::string room`; `chat::server::is_valid_room_name(const std::string&) -> bool`; `chat::server::room_key(const std::string&) -> std::string`; `chat::server::kDefaultRoom`; `chat::server::kMaxRoomNameLength`.

- [ ] **Step 1: Write the failing name-validation tests**

Create `tests/room_name_tests.cpp`:

```cpp
#include "chat/server/room_name.hpp"

#include <gtest/gtest.h>
#include <string>

namespace chat::server
{
    TEST(RoomNameTest, AcceptsAlnumUnderscoreDash)
    {
        EXPECT_TRUE(is_valid_room_name("lobby"));
        EXPECT_TRUE(is_valid_room_name("dev-team_2"));
        EXPECT_TRUE(is_valid_room_name("A"));
    }

    TEST(RoomNameTest, RejectsEmptyAndOverlong)
    {
        EXPECT_FALSE(is_valid_room_name(""));
        EXPECT_TRUE(is_valid_room_name(std::string(kMaxRoomNameLength, 'a')));
        EXPECT_FALSE(is_valid_room_name(std::string(kMaxRoomNameLength + 1, 'a')));
    }

    TEST(RoomNameTest, RejectsSeparatorsAndControlCharacters)
    {
        EXPECT_FALSE(is_valid_room_name("has space"));
        EXPECT_FALSE(is_valid_room_name("has/slash"));
        EXPECT_FALSE(is_valid_room_name("has\ttab"));
        EXPECT_FALSE(is_valid_room_name("esc\033[0m"));
    }

    TEST(RoomNameTest, RejectsHighBytes)
    {
        // std::isalnum on a negative char is undefined; the helper must cast to
        // unsigned char before calling it, and must not accept UTF-8 bytes.
        EXPECT_FALSE(is_valid_room_name("caf\xC3\xA9"));
    }

    TEST(RoomNameTest, KeyIsLowercasedForCaseInsensitiveUniqueness)
    {
        EXPECT_EQ(room_key("Dev"), room_key("dev"));
        EXPECT_EQ(room_key("LOBBY"), "lobby");
        EXPECT_EQ(room_key("mixed-Case_1"), "mixed-case_1");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Add the target first — the file will not compile without it. In `CMakeLists.txt`, inside `if(BUILD_TESTS)`, after the `cli_tests` block:

```cmake
    add_executable(room_name_tests
            tests/room_name_tests.cpp
    )
    target_link_libraries(room_name_tests
            PRIVATE
            chat_common
            GTest::gtest_main
    )
```

and add `gtest_discover_tests(room_name_tests)` beside the other discover calls.

Run: `cmake --preset debug && cmake --build --preset debug`
Expected: FAIL — `fatal error: chat/server/room_name.hpp: No such file or directory`

- [ ] **Step 3: Write the header**

Create `include/chat/server/room_name.hpp`:

```cpp
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
```

- [ ] **Step 4: Run the name tests to verify they pass**

Run: `cmake --build --preset debug && ./build/debug/room_name_tests`
Expected: PASS, 5 tests.

- [ ] **Step 5: Add the protocol enum values and bump the version**

In `include/chat/common/types.hpp`, change the version constant:

```cpp
    // 2: rooms. Adds ROOM_* messages and a room name in InitMsg.
    inline constexpr uint16_t kProtocolVersion = 2;
```

and append to `enum class MessageType`, **after** `SRP_SUCCESS` so existing values keep their numbers:

```cpp
        // rooms
        ROOM_LIST_REQ,  // client asks for the room list
        ROOM_LIST,      // server sends the room list
        ROOM_CREATE,    // client creates a room and joins it
        ROOM_JOIN,      // client joins an existing room
```

- [ ] **Step 6: Add the wire structs**

In `include/chat/common/messages.hpp`, add before `InitMsg`:

```cpp
    struct RoomInfo
    {
        std::string name;   // the creator's casing
        uint32_t user_count;
        uint8_t has_password;

        [[nodiscard]] auto as_tuple() const { return std::tie(name, user_count, has_password); }
        [[nodiscard]] auto as_tuple() { return std::tie(name, user_count, has_password); }
    };
```

and after `InitMsg`:

```cpp
    struct RoomListMsg
    {
        std::vector<RoomInfo> rooms;

        [[nodiscard]] auto as_tuple() const { return std::tie(rooms); }
        [[nodiscard]] auto as_tuple() { return std::tie(rooms); }
    };

    struct RoomCreateMsg
    {
        std::string name;
        // Base64 AES-GCM payload sealed with the sender's session key, AAD = name.
        // Empty means "create a public room".
        std::string password_ct_b64;

        [[nodiscard]] auto as_tuple() const { return std::tie(name, password_ct_b64); }
        [[nodiscard]] auto as_tuple() { return std::tie(name, password_ct_b64); }
    };

    struct RoomJoinMsg
    {
        std::string name;
        // As RoomCreateMsg. Empty means "no password supplied".
        std::string password_ct_b64;

        [[nodiscard]] auto as_tuple() const { return std::tie(name, password_ct_b64); }
        [[nodiscard]] auto as_tuple() { return std::tie(name, password_ct_b64); }
    };
```

Then extend `InitMsg` with a **leading** `room` field — the tuple order is the wire order, and `kProtocolVersion` already covers the break:

```cpp
    struct InitMsg
    {
        std::string room;
        std::vector<HistoryEntry> messages;
        std::vector<User> users;

        [[nodiscard]] auto as_tuple() const { return std::tie(room, messages, users); }
        [[nodiscard]] auto as_tuple() { return std::tie(room, messages, users); }
    };
```

- [ ] **Step 7: Write the failing wire round-trip tests**

Append to `tests/wire_tests.cpp`, inside the existing `namespace chat`:

```cpp
    TEST(WireTest, RoomListRoundTrip)
    {
        const RoomListMsg original{{
            RoomInfo{"lobby", 3, 0},
            RoomInfo{"Dev-Team", 1, 1},
        }};

        const auto packet  = Protocol::encode(MessageType::ROOM_LIST, original);
        const auto payload = std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        const auto decoded = Protocol::decode<RoomListMsg>(payload);

        ASSERT_EQ(decoded.rooms.size(), 2u);
        EXPECT_EQ(decoded.rooms[0].name, "lobby");
        EXPECT_EQ(decoded.rooms[0].user_count, 3u);
        EXPECT_EQ(decoded.rooms[0].has_password, 0);
        EXPECT_EQ(decoded.rooms[1].name, "Dev-Team");
        EXPECT_EQ(decoded.rooms[1].user_count, 1u);
        EXPECT_EQ(decoded.rooms[1].has_password, 1);
    }

    TEST(WireTest, EmptyRoomListRoundTrip)
    {
        const RoomListMsg original{};
        const auto packet  = Protocol::encode(MessageType::ROOM_LIST, original);
        const auto payload = std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        EXPECT_TRUE(Protocol::decode<RoomListMsg>(payload).rooms.empty());
    }

    TEST(WireTest, RoomJoinAndCreateRoundTrip)
    {
        const RoomJoinMsg join{"dev", "c2VhbGVk"};
        auto packet  = Protocol::encode(MessageType::ROOM_JOIN, join);
        auto payload = std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        const auto decoded_join = Protocol::decode<RoomJoinMsg>(payload);
        EXPECT_EQ(decoded_join.name, "dev");
        EXPECT_EQ(decoded_join.password_ct_b64, "c2VhbGVk");

        const RoomCreateMsg create{"public-room", ""};
        packet  = Protocol::encode(MessageType::ROOM_CREATE, create);
        payload = std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        const auto decoded_create = Protocol::decode<RoomCreateMsg>(payload);
        EXPECT_EQ(decoded_create.name, "public-room");
        EXPECT_TRUE(decoded_create.password_ct_b64.empty());
    }

    TEST(WireTest, InitCarriesRoomName)
    {
        InitMsg original;
        original.room = "dev";
        original.messages.push_back(HistoryEntry{"alice", "c2VhbGVk", 1234});
        original.users.push_back(User{"alice", "id-a"});

        const auto packet  = Protocol::encode(MessageType::INIT, original);
        const auto payload = std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        const auto decoded = Protocol::decode<InitMsg>(payload);

        EXPECT_EQ(decoded.room, "dev");
        ASSERT_EQ(decoded.messages.size(), 1u);
        EXPECT_EQ(decoded.messages[0].username, "alice");
        ASSERT_EQ(decoded.users.size(), 1u);
        EXPECT_EQ(decoded.users[0].username, "alice");
    }
```

- [ ] **Step 8: Run the wire tests**

Run: `cmake --build --preset debug && ./build/debug/wire_tests`
Expected: PASS. If `wire_tests.cpp` does not already include `chat/common/messages.hpp`, add it.

- [ ] **Step 9: Run the whole suite**

Run: `ctest --preset debug`
Expected: everything passes. `room_tests` still compiles because `InitMsg`'s new field is default-constructed.

- [ ] **Step 10: Commit**

```bash
git add include/chat/common/types.hpp include/chat/common/messages.hpp \
        include/chat/server/room_name.hpp tests/wire_tests.cpp \
        tests/room_name_tests.cpp CMakeLists.txt
git commit -m "feat(protocol): add room messages, room name validation

Protocol version 2: four ROOM_* message types and a room name on INIT.
Existing message type values are unchanged."
```

---

### Task 2: `Room` gains a name and a password; `leave` stops closing the sink

Two behavior changes in one class. The `leave` change is load-bearing: today `Room::leave` calls `sink->close()`, which is correct when the only exit from a room is disconnecting, but would kill the connection the moment a user switches rooms. `Session` already calls `close()` itself at the end of `run()`, so removing it here loses nothing.

**Files:**
- Modify: `include/chat/server/room.hpp`
- Modify: `src/server/room.cpp`
- Modify: `tests/room_tests.cpp` (the sink assertion at ~line 91 must be inverted)

**Interfaces:**
- Consumes: `InitMsg::room` (Task 1).
- Produces: `Room::Room(std::string name = "", const std::string& password = "")`; `Room::name() -> const std::string&`; `Room::has_password() -> bool`; `Room::verify_password(const std::string&) -> bool`; `Room::join(user_id, username, sink, key) -> void` (renamed from `try_join`, no longer returns bool); `Room::leave` no longer closes the sink; `init_packet_for` fills `InitMsg::room`.

- [ ] **Step 1: Write the failing password and naming tests**

Add to `tests/room_tests.cpp` inside `namespace chat::server`:

```cpp
    TEST(RoomPasswordTest, PublicRoomAcceptsAnything)
    {
        const Room room("lobby");

        EXPECT_EQ(room.name(), "lobby");
        EXPECT_FALSE(room.has_password());
        EXPECT_TRUE(room.verify_password(""));
        EXPECT_TRUE(room.verify_password("anything"));
    }

    TEST(RoomPasswordTest, LockedRoomAcceptsOnlyTheRightPassword)
    {
        const Room room("dev", "hunter2");

        EXPECT_TRUE(room.has_password());
        EXPECT_TRUE(room.verify_password("hunter2"));
        EXPECT_FALSE(room.verify_password("hunter3"));
        EXPECT_FALSE(room.verify_password(""));
        EXPECT_FALSE(room.verify_password("hunter2 "));
    }

    TEST(RoomPasswordTest, EqualPasswordsInDifferentRoomsBothVerify)
    {
        // Distinct random salts per room: two rooms sharing a password must not
        // share a hash, or one leaked hash would identify every room using it.
        const Room a("one", "same-password");
        const Room b("two", "same-password");

        EXPECT_TRUE(a.verify_password("same-password"));
        EXPECT_TRUE(b.verify_password("same-password"));
    }

    TEST(RoomPasswordTest, KeepsCreatorCasing)
    {
        const Room room("Dev-Team");
        EXPECT_EQ(room.name(), "Dev-Team");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cmake --build --preset debug 2>&1 | head -20`
Expected: FAIL — no matching constructor for `Room(const char*, const char*)`, no member `name`.

- [ ] **Step 3: Add the constructor, name, and password members**

In `include/chat/server/room.hpp`, add to the public section above `try_join`:

```cpp
        // A password-less room is public. The password is hashed on construction
        // and the plaintext is not retained.
        explicit Room(std::string name = "", const std::string& password = "");

        [[nodiscard]] const std::string& name() const { return name_; }
        [[nodiscard]] bool has_password() const { return !password_hmac_.empty(); }

        // True for any password when the room is public. Constant-time when locked.
        [[nodiscard]] bool verify_password(const std::string& password) const;
```

Rename the join declaration and drop its return value:

```cpp
        // Adds a member. The caller (RoomManager) holds its own lock across the
        // capacity check and this call, so there is no check-then-act window here.
        void join(const std::string& user_id,
                  const std::string& username,
                  std::shared_ptr<Sink> sink,
                  std::vector<uint8_t> key);
```

Add to the private section, below `std::deque<HistoryItem> history_;`:

```cpp
        // Immutable after construction, so read without the mutex.
        std::string name_;
        std::vector<uint8_t> salt_;
        std::vector<uint8_t> password_hmac_;
```

- [ ] **Step 4: Implement in `src/server/room.cpp`**

Add above `Room::try_join`:

```cpp
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
```

Replace `Room::try_join` with:

```cpp
    void Room::join(const std::string& user_id,
                    const std::string& username,
                    std::shared_ptr<Sink> sink,
                    std::vector<uint8_t> key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        members_[user_id] = Member{std::move(sink), username, std::move(key)};
    }
```

The duplicate-username check that used to live here moves to `OnlineUsers` in Task 3 — with several rooms, "alice is already in *this* room" is not the question worth asking.

- [ ] **Step 5: Stop `leave` from closing the sink**

Replace `Room::leave` with:

```cpp
    void Room::leave(const std::string& user_id)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        members_.erase(user_id);
    }
```

The `sink->close()` it used to perform is now solely `Session`'s business: `Session::run` already calls `close()` after the cleanup block. Leaving it here would disconnect a user the instant they switched rooms.

- [ ] **Step 6: Fill the room name into INIT**

In `Room::init_packet_for`, replace the opening of the function so both the early return and the normal path carry the name:

```cpp
    std::vector<uint8_t> Room::init_packet_for(const std::string& user_id) const
    {
        InitMsg init;
        init.room = name_;
        {
            std::lock_guard<std::mutex> lock(mutex_);

            const auto it = members_.find(user_id);
            if (it == members_.end())
                return Protocol::encode(MessageType::INIT, init);
```

The rest of the function is unchanged.

- [ ] **Step 7: Update the existing tests for the new API**

In `tests/room_tests.cpp`, change `join_both()` to use the new name:

```cpp
        void join_both()
        {
            room_.join("user_a", "alice", alice_, test_key(0xAA));
            room_.join("user_b", "bob", bob_, test_key(0xBB));
        }
```

Replace every other `room_.try_join(...)` call with `room_.join(...)`, dropping any use of the old bool return. Delete the test that asserted a duplicate username is refused (that behavior now belongs to `OnlineUsers`, tested in Task 3), and invert the sink assertion at ~line 91:

```cpp
        room_.leave("user_a");

        EXPECT_EQ(room_.size(), 1u);
        EXPECT_FALSE(room_.username_online("alice"));
        // Leaving a room must not close the connection — a room switch is a leave
        // followed by a join, and Session::run owns the socket teardown.
        EXPECT_FALSE(alice_->closed);
```

- [ ] **Step 8: Run the room tests**

Run: `cmake --build --preset debug --target room_tests && ./build/debug/room_tests`
Expected: PASS. The full build still fails — `session.cpp` calls `try_join` and `server_.room()` until Task 6 — so build the single target here.

- [ ] **Step 9: Commit**

```bash
git add include/chat/server/room.hpp src/server/room.cpp tests/room_tests.cpp
git commit -m "feat(server): give Room a name and an optional password

Rooms hash their password with a per-room random salt and verify in
constant time. try_join becomes join: the duplicate-username check is
meaningless per-room once there is more than one room.

leave() no longer closes the sink. Switching rooms is a leave followed
by a join, and Session already owns socket teardown."
```

---

### Task 3: `OnlineUsers` registry

Where the duplicate-login check goes. A standalone class rather than members on `Server`, because `Server` needs an `io_context` and a bound acceptor to construct and would drag both into the test binary.

**Files:**
- Create: `include/chat/server/online_users.hpp`
- Create: `tests/online_users_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: nothing.
- Produces: `chat::server::OnlineUsers` with `try_claim(const std::string&) -> bool`, `release(const std::string&) -> void`, `is_online(const std::string&) const -> bool`.

- [ ] **Step 1: Write the failing tests**

Create `tests/online_users_tests.cpp`:

```cpp
#include "chat/server/online_users.hpp"

#include <gtest/gtest.h>

namespace chat::server
{
    TEST(OnlineUsersTest, ClaimSucceedsOnceThenRefuses)
    {
        OnlineUsers online;

        EXPECT_TRUE(online.try_claim("alice"));
        EXPECT_TRUE(online.is_online("alice"));
        EXPECT_FALSE(online.try_claim("alice"));
    }

    TEST(OnlineUsersTest, DistinctNamesDoNotCollide)
    {
        OnlineUsers online;

        EXPECT_TRUE(online.try_claim("alice"));
        EXPECT_TRUE(online.try_claim("bob"));
        EXPECT_TRUE(online.is_online("bob"));
    }

    TEST(OnlineUsersTest, ReleaseAllowsReclaim)
    {
        OnlineUsers online;

        ASSERT_TRUE(online.try_claim("alice"));
        online.release("alice");

        EXPECT_FALSE(online.is_online("alice"));
        EXPECT_TRUE(online.try_claim("alice"));
    }

    TEST(OnlineUsersTest, ReleasingSomeoneAbsentIsHarmless)
    {
        OnlineUsers online;

        // The disconnect path releases unconditionally, including for a session
        // that failed before it ever claimed a name.
        online.release("nobody");
        online.release("");

        EXPECT_FALSE(online.is_online("nobody"));
    }
}
```

- [ ] **Step 2: Add the test target and run to verify failure**

In `CMakeLists.txt`, after the `room_name_tests` block:

```cmake
    add_executable(online_users_tests
            tests/online_users_tests.cpp
    )
    target_link_libraries(online_users_tests
            PRIVATE
            chat_common
            GTest::gtest_main
    )
```

plus `gtest_discover_tests(online_users_tests)`.

Run: `cmake --preset debug && cmake --build --preset debug --target online_users_tests`
Expected: FAIL — `chat/server/online_users.hpp: No such file or directory`

- [ ] **Step 3: Write the header**

Create `include/chat/server/online_users.hpp`:

```cpp
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
```

- [ ] **Step 4: Run the tests**

Run: `cmake --build --preset debug --target online_users_tests && ./build/debug/online_users_tests`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add include/chat/server/online_users.hpp tests/online_users_tests.cpp CMakeLists.txt
git commit -m "feat(server): add OnlineUsers registry for duplicate-login refusal"
```

---

### Task 4: `RoomManager`

The lifecycle owner. Find, password check, capacity check, and join all happen in one critical section — splitting them opens a window where the room empties and is dropped between the find and the join, leaving the joiner in a room that is no longer in the map and that nobody else can reach.

**Files:**
- Create: `include/chat/server/room_manager.hpp`
- Create: `src/server/room_manager.cpp`
- Create: `tests/room_manager_tests.cpp`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `Room` (Task 2), `room_key`/`kDefaultRoom` (Task 1), `RoomInfo` (Task 1), `Sink`.
- Produces: `chat::server::JoinStatus` enum (`Ok`, `NoSuchRoom`, `PasswordRequired`, `WrongPassword`, `RoomFull`, `NameTaken`, `TooManyRooms`); `chat::server::JoinResult{JoinStatus status; std::shared_ptr<Room> room;}`; `RoomManager(size_t max_rooms, size_t max_members)`; `RoomManager::join(name, password, user_id, username, sink, key) -> JoinResult`; `RoomManager::create_and_join(...same signature...) -> JoinResult`; `RoomManager::find(name) -> std::shared_ptr<Room>`; `RoomManager::list() -> std::vector<RoomInfo>`; `RoomManager::drop_if_empty(name) -> void`.

- [ ] **Step 1: Write the failing tests**

Create `tests/room_manager_tests.cpp`:

```cpp
#include "chat/server/room_manager.hpp"

#include "chat/crypto/aes_engine.hpp"

#include <algorithm>
#include <gtest/gtest.h>
#include <memory>

namespace chat::server
{
    namespace
    {
        class RecordingSink final : public Sink
        {
        public:
            std::vector<std::vector<uint8_t>> packets;
            bool closed = false;

            void send(std::vector<uint8_t> packet) override { packets.push_back(std::move(packet)); }
            void close() override { closed = true; }
        };

        std::vector<uint8_t> test_key(const uint8_t fill)
        {
            return std::vector<uint8_t>(crypto::AESEngine::KEY_SIZE, fill);
        }

        std::shared_ptr<RecordingSink> sink() { return std::make_shared<RecordingSink>(); }
    }

    TEST(RoomManagerTest, LobbyExistsAndIsPublic)
    {
        const RoomManager manager(64, 64);

        const auto lobby = manager.find(kDefaultRoom);
        ASSERT_NE(lobby, nullptr);
        EXPECT_FALSE(lobby->has_password());
        EXPECT_EQ(lobby->name(), std::string(kDefaultRoom));
    }

    TEST(RoomManagerTest, JoinsAnExistingRoom)
    {
        RoomManager manager(64, 64);

        const auto result = manager.join(kDefaultRoom, "", "id-a", "alice", sink(), test_key(0xAA));

        EXPECT_EQ(result.status, JoinStatus::Ok);
        ASSERT_NE(result.room, nullptr);
        EXPECT_EQ(result.room->size(), 1u);
    }

    TEST(RoomManagerTest, RefusesUnknownRoom)
    {
        RoomManager manager(64, 64);

        const auto result = manager.join("nowhere", "", "id-a", "alice", sink(), test_key(0xAA));

        EXPECT_EQ(result.status, JoinStatus::NoSuchRoom);
        EXPECT_EQ(result.room, nullptr);
    }

    TEST(RoomManagerTest, CreatesAndJoinsInOneStep)
    {
        RoomManager manager(64, 64);

        const auto result = manager.create_and_join("dev", "", "id-a", "alice", sink(), test_key(0xAA));

        ASSERT_EQ(result.status, JoinStatus::Ok);
        EXPECT_EQ(result.room->size(), 1u);
        EXPECT_NE(manager.find("dev"), nullptr);
    }

    TEST(RoomManagerTest, RefusesDuplicateNameCaseInsensitively)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("Dev", "", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        const auto result = manager.create_and_join("dev", "", "id-b", "bob", sink(), test_key(0xBB));

        EXPECT_EQ(result.status, JoinStatus::NameTaken);
    }

    TEST(RoomManagerTest, FindIsCaseInsensitiveButNameKeepsCasing)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("Dev-Team", "", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        const auto room = manager.find("dev-team");
        ASSERT_NE(room, nullptr);
        EXPECT_EQ(room->name(), "Dev-Team");
    }

    TEST(RoomManagerTest, LockedRoomRequiresTheRightPassword)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("dev", "hunter2", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        EXPECT_EQ(manager.join("dev", "", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::PasswordRequired);
        EXPECT_EQ(manager.join("dev", "wrong", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::WrongPassword);
        EXPECT_EQ(manager.join("dev", "hunter2", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::Ok);
    }

    TEST(RoomManagerTest, FailedJoinLeavesRoomUntouched)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("dev", "hunter2", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        ASSERT_EQ(manager.join("dev", "wrong", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::WrongPassword);

        EXPECT_EQ(manager.find("dev")->size(), 1u);
    }

    TEST(RoomManagerTest, EnforcesMemberCap)
    {
        RoomManager manager(64, 1);
        ASSERT_EQ(manager.create_and_join("dev", "", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        EXPECT_EQ(manager.join("dev", "", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::RoomFull);
    }

    TEST(RoomManagerTest, EnforcesRoomCap)
    {
        // The lobby occupies one slot from the start.
        RoomManager manager(2, 64);
        ASSERT_EQ(manager.create_and_join("one", "", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        EXPECT_EQ(manager.create_and_join("two", "", "id-b", "bob", sink(), test_key(0xBB)).status,
                  JoinStatus::TooManyRooms);
    }

    TEST(RoomManagerTest, DropsEmptyRoom)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("dev", "", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        manager.drop_if_empty("dev");
        EXPECT_NE(manager.find("dev"), nullptr); // still occupied

        manager.find("dev")->leave("id-a");
        manager.drop_if_empty("dev");
        EXPECT_EQ(manager.find("dev"), nullptr);
    }

    TEST(RoomManagerTest, NeverDropsTheLobby)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.find(kDefaultRoom)->size(), 0u);

        manager.drop_if_empty(kDefaultRoom);

        EXPECT_NE(manager.find(kDefaultRoom), nullptr);
    }

    TEST(RoomManagerTest, ListsRoomsWithCountsAndLockFlag)
    {
        RoomManager manager(64, 64);
        ASSERT_EQ(manager.create_and_join("dev", "hunter2", "id-a", "alice", sink(), test_key(0xAA)).status,
                  JoinStatus::Ok);

        const auto rooms = manager.list();
        ASSERT_EQ(rooms.size(), 2u);

        const auto dev = std::ranges::find_if(rooms, [](const RoomInfo& r) { return r.name == "dev"; });
        ASSERT_NE(dev, rooms.end());
        EXPECT_EQ(dev->user_count, 1u);
        EXPECT_EQ(dev->has_password, 1);

        const auto lobby = std::ranges::find_if(
            rooms, [](const RoomInfo& r) { return r.name == std::string(kDefaultRoom); });
        ASSERT_NE(lobby, rooms.end());
        EXPECT_EQ(lobby->user_count, 0u);
        EXPECT_EQ(lobby->has_password, 0);
    }
}
```

- [ ] **Step 2: Add the test target and run to verify failure**

In `CMakeLists.txt`, after the `online_users_tests` block:

```cmake
    add_executable(room_manager_tests
            tests/room_manager_tests.cpp
            src/server/room.cpp
            src/server/room_manager.cpp
    )
    target_link_libraries(room_manager_tests
            PRIVATE
            chat_common
            chat_auth
            chat_crypto
            Boost::system
            Threads::Threads
            GTest::gtest_main
    )
```

plus `gtest_discover_tests(room_manager_tests)`.

Run: `cmake --preset debug && cmake --build --preset debug --target room_manager_tests`
Expected: FAIL — `chat/server/room_manager.hpp: No such file or directory`

- [ ] **Step 3: Write the header**

Create `include/chat/server/room_manager.hpp`:

```cpp
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
```

- [ ] **Step 4: Write the implementation**

Create `src/server/room_manager.cpp`:

```cpp
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
```

- [ ] **Step 5: Run the manager tests**

Run: `cmake --build --preset debug --target room_manager_tests && ./build/debug/room_manager_tests`
Expected: PASS, 13 tests.

- [ ] **Step 6: Add `room_manager.cpp` to the server binary**

In `CMakeLists.txt`, in the `add_executable(chat_server ...)` list, after `src/server/room.cpp`:

```cmake
        src/server/room_manager.cpp
```

- [ ] **Step 7: Commit**

```bash
git add include/chat/server/room_manager.hpp src/server/room_manager.cpp \
        tests/room_manager_tests.cpp CMakeLists.txt
git commit -m "feat(server): add RoomManager

Owns room lifetimes and performs find, password check, capacity check
and join in one critical section, so a room cannot be dropped between
the lookup and the join. The lobby is pinned and never dropped."
```

---

### Task 5: Server wiring and CLI flags

**Files:**
- Modify: `include/chat/server/server.hpp`
- Modify: `src/server/server.cpp` (constructor init list only)
- Modify: `src/server/main.cpp`
- Modify: `tests/cli_tests.cpp`

**Interfaces:**
- Consumes: `RoomManager` (Task 4), `OnlineUsers` (Task 3).
- Produces: `ServerConfig::max_rooms` (default 64), `ServerConfig::max_room_members` (default 64); `Server::rooms() -> RoomManager&`; `Server::online() -> OnlineUsers&`. `Server::room()` is **removed** — Task 6 updates its only caller.

- [ ] **Step 1: Write the CLI tests**

Add to `tests/cli_tests.cpp` inside `namespace chat`:

```cpp
    TEST(CliTest, ParsesRoomCaps)
    {
        const auto cli = parse({"--max-rooms", "8", "--max-room-members", "12"});
        EXPECT_EQ(cli.get_int("max-rooms", 64), 8);
        EXPECT_EQ(cli.get_int("max-room-members", 64), 12);
    }

    TEST(CliTest, RoomCapsFallBackToDefaults)
    {
        const auto cli = parse({"--port", "9000"});
        EXPECT_EQ(cli.get_int("max-rooms", 64), 64);
        EXPECT_EQ(cli.get_int("max-room-members", 64), 64);
    }

    TEST(CliTest, RoomCapFlagsAreKnown)
    {
        const auto cli = parse({"--max-rooms", "8", "--max-room-members", "12"});
        EXPECT_NO_THROW(cli.expect_known({"max-rooms", "max-room-members"}));
    }
```

- [ ] **Step 2: Run them**

Run: `cmake --build --preset debug --target cli_tests && ./build/debug/cli_tests`
Expected: PASS immediately. `Cli` is generic, so these pin the flag names and defaults rather than driving new parser code — the behavior they protect lives in `main.cpp`, which has no test seam. That is why this step expects PASS rather than the usual red-first.

- [ ] **Step 3: Add the config fields and accessors**

In `include/chat/server/server.hpp`, replace `#include "chat/server/room.hpp"` with:

```cpp
#include "chat/server/online_users.hpp"
#include "chat/server/room_manager.hpp"
```

Add to `ServerConfig`:

```cpp
        size_t max_rooms                       = 64;
        size_t max_room_members                = 64;
```

Replace the `room()` accessor with:

```cpp
        RoomManager& rooms() { return rooms_; }
        OnlineUsers& online() { return online_; }
```

and replace the `Room room_;` member with:

```cpp
        RoomManager rooms_;
        OnlineUsers online_;
```

Keep `rooms_` declared **after** `config_`, since its initialiser reads `config_`.

- [ ] **Step 4: Initialise the manager in the constructor**

In `src/server/server.cpp`, extend the `Server::Server` init list after `srp_server_(...)`:

```cpp
          , rooms_(config_.max_rooms, config_.max_room_members)
```

- [ ] **Step 5: Wire the flags in `main.cpp`**

In `src/server/main.cpp`, extend `print_usage` after the `--max-connections` line:

```cpp
            "  --max-rooms <n>          Room cap, lobby included (default 64)\n"
            "  --max-room-members <n>   Members per room (default 64)\n"
```

Extend `expect_known`:

```cpp
        cli.expect_known({"port", "users-db", "max-connections",
                          "handshake-timeout", "idle-timeout",
                          "max-rooms", "max-room-members", "help"});
```

and add the parsing after the `max_connections` block:

```cpp
        const int max_rooms = cli.get_int("max-rooms", 64);
        if (max_rooms < 1)
            throw std::runtime_error("--max-rooms must be at least 1");
        config.max_rooms = static_cast<size_t>(max_rooms);

        const int max_room_members = cli.get_int("max-room-members", 64);
        if (max_room_members < 1)
            throw std::runtime_error("--max-room-members must be at least 1");
        config.max_room_members = static_cast<size_t>(max_room_members);
```

- [ ] **Step 6: Verify**

`session.cpp` still calls `server_.room()` and will not compile until Task 6.

Run: `cmake --build --preset debug --target cli_tests && ./build/debug/cli_tests`
Expected: PASS. Full-binary verification happens at the end of Task 6.

- [ ] **Step 7: Commit**

```bash
git add include/chat/server/server.hpp src/server/server.cpp src/server/main.cpp tests/cli_tests.cpp
git commit -m "feat(server): hold a RoomManager and OnlineUsers, add room cap flags"
```

---

### Task 6: `Session` joins the lobby through the manager

Rewires login, the message loop, and cleanup. The build goes green again at the end of this task.

**Files:**
- Modify: `include/chat/server/session.hpp`
- Modify: `src/server/session.cpp`

**Interfaces:**
- Consumes: `Server::rooms()`, `Server::online()` (Task 5); `RoomManager::join`, `JoinStatus` (Task 4); `Room::join`, `Room::name` (Task 2); `kDefaultRoom` (Task 1).
- Produces: `Session::room_`, `Session::key_`, `Session::user_id_`, `Session::room_password_attempts_` members that Task 7's handlers use.

- [ ] **Step 1: Add the new members**

In `include/chat/server/session.hpp`, add the include:

```cpp
#include "chat/server/room.hpp"
```

and add to the private data, after `int auth_attempts_ = 0;`:

```cpp
        // Current room. Null until finish_login() succeeds.
        std::shared_ptr<Room> room_;
        // Derived once at login: the message loop and every room join need it.
        std::vector<uint8_t> key_;
        std::string user_id_;
        int room_password_attempts_ = 0;
```

- [ ] **Step 2: Rewrite `finish_login`**

In `src/server/session.cpp`, add to the includes:

```cpp
#include "chat/server/room_manager.hpp"
#include "chat/server/room_name.hpp"
```

and replace `Session::finish_login` with:

```cpp
    awaitable<std::optional<std::string>> Session::finish_login(
        const std::string& username, const std::string& user_id)
    {
        key_ = server_.srp().derive_session_key(user_id);
        if (key_.size() != crypto::AESEngine::KEY_SIZE) {
            fail("Authentication failed", "handshake: derived key has wrong size");
            co_return std::nullopt;
        }

        // Atomic claim: no window for a second login of the same account. This
        // used to be a side effect of Room::try_join refusing duplicate names,
        // which stops working the moment there is more than one room.
        if (!server_.online().try_claim(username)) {
            fail("User already logged in", "handshake: duplicate login for " + username);
            co_return std::nullopt;
        }

        auto result = server_.rooms().join(
            kDefaultRoom, "", user_id, username, shared_from_this(), key_);
        if (result.status != JoinStatus::Ok) {
            server_.online().release(username);
            fail("Could not join the lobby", "handshake: lobby join refused");
            co_return std::nullopt;
        }

        room_     = std::move(result.room);
        username_ = username;
        user_id_  = user_id;

        log::info("user '" + username_ + "' authenticated from " + remote_);

        send(room_->init_packet_for(user_id));
        room_->broadcast_packet(
            Protocol::encode(MessageType::USER_JOINED, UserJoinedMsg{username_, user_id}),
            user_id);

        co_return user_id;
    }
```

- [ ] **Step 3: Rewrite the cleanup block in `run()`**

Replace the cleanup `try` block inside `Session::run` with:

```cpp
            // This coroutine is detached: anything thrown from here would reach the
            // io_context uncaught and terminate the process, killing every other
            // session over one failed cleanup.
            try {
                if (room_) {
                    room_->leave(*user_id);
                    room_->broadcast_packet(
                        Protocol::encode(MessageType::USER_LEFT, UserLeftMsg{username_}));
                    server_.rooms().drop_if_empty(room_->name());
                    room_.reset();
                }
                server_.online().release(username_);
                server_.srp().clear_session(*user_id);
                log::info("user '" + username_ + "' disconnected");
            }
            catch (const std::exception& e) {
                log::error(remote_ + ": cleanup failed: " + e.what());
            }
```

Leave and broadcast now go through `room_`, and the room is dropped if that emptied it.

- [ ] **Step 4: Use the stored key in the message loop**

In `Session::message_loop`, delete the local re-derivation:

```cpp
        const auto key = server_.srp().derive_session_key(user_id);
```

Change the decrypt call to use `key_`:

```cpp
                        text = crypto::AESEngine::decrypt_string(
                            auth::SRPUtils::base64_to_bytes(msg.ciphertext_b64), key_);
```

Change the broadcast to go through the current room — before and after:

```cpp
                    server_.room().record_and_broadcast(username_, text);   // before
                    room_->record_and_broadcast(username_, text);           // after
```

Leave the `message_loop(const std::string& user_id)` signature as is; `run()` still passes it and `finish_login` has stored the same value in `user_id_`.

- [ ] **Step 5: Build and run the full suite**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: PASS. The build is green again for the first time since Task 2.

- [ ] **Step 6: Smoke-test two clients in the lobby**

First behavioral checkpoint; there is no automated end-to-end harness.

```bash
./build/debug/chat_server --port 8899 --users-db /tmp/rooms-smoke.db &
./build/debug/chat_client --user alice --register --host localhost --port 8899
# in a second terminal:
./build/debug/chat_client --user bob --register --host localhost --port 8899
```

Expected: both authenticate, each sees the other's join, messages appear on both sides — unchanged behavior, now routed through the lobby. Then start a third client as `alice`: expected `User already logged in`. Kill the server and remove `/tmp/rooms-smoke.db` afterwards.

- [ ] **Step 7: Commit**

```bash
git add include/chat/server/session.hpp src/server/session.cpp
git commit -m "feat(server): route sessions through RoomManager and OnlineUsers

Login joins the lobby via the manager, the message loop broadcasts to
the session's current room, and disconnect leaves that room, drops it
if empty, and releases the username."
```

---

### Task 7: `Session` handles list, create, and join

**Files:**
- Modify: `include/chat/server/session.hpp`
- Modify: `src/server/session.cpp` (dispatch only)
- Create: `src/server/session_rooms.cpp`
- Modify: `CMakeLists.txt`

`session.cpp` is 412 lines; these handlers would push it past 500, so they get their own translation unit for the same class.

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces: `Session::handle_room_list()`, `Session::handle_room_join(const std::vector<uint8_t>& payload, bool create)`, `Session::reject(client_message, log_message)`, dispatched from `message_loop`.

- [ ] **Step 1: Declare the handlers**

In `include/chat/server/session.hpp`, add to the private methods after `handle_register`:

```cpp
        // Defined in session_rooms.cpp.
        void handle_room_list();
        // `create` selects create-and-join over join. Room failures send an
        // ERROR_MSG and return; they do not end the session.
        void handle_room_join(const std::vector<uint8_t>& payload, bool create);
        // ERROR_MSG without fail()'s implication that the session is over.
        void reject(const std::string& client_message, const std::string& log_message);
```

- [ ] **Step 2: Write the handlers**

Create `src/server/session_rooms.cpp`:

```cpp
#include "chat/server/session.hpp"

#include <algorithm>

#include "chat/auth/srp_utils.hpp"
#include "chat/common/log.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"
#include "chat/crypto/aes_engine.hpp"
#include "chat/server/room_manager.hpp"
#include "chat/server/room_name.hpp"
#include "chat/server/server.hpp"

namespace chat::server
{
    namespace
    {
        constexpr size_t kMaxRoomPasswordLength = 128;
        // A sealed 128-byte password is 12 (IV) + 128 + 16 (tag) = 156 bytes,
        // ~208 base64 characters. Round up and reject anything larger before
        // spending any work on decryption.
        constexpr size_t kMaxSealedPasswordB64 = 512;
        constexpr int kMaxRoomPasswordAttempts = 5;
    }

    void Session::reject(const std::string& client_message, const std::string& log_message)
    {
        send(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{client_message}));
        log::info(remote_ + ": " + log_message);
    }

    void Session::handle_room_list()
    {
        send(Protocol::encode(MessageType::ROOM_LIST, RoomListMsg{server_.rooms().list()}));
    }

    void Session::handle_room_join(const std::vector<uint8_t>& payload, const bool create)
    {
        // RoomJoinMsg and RoomCreateMsg are the same two fields in the same
        // order, so one decode serves both.
        const auto msg = Protocol::decode<RoomJoinMsg>(payload);

        if (!is_valid_room_name(msg.name)) {
            reject("Invalid room name", "room: bad name");
            return;
        }

        if (room_ && room_key(room_->name()) == room_key(msg.name)) {
            reject("Already in that room", "room: join to current room");
            return;
        }

        std::string password;
        if (!msg.password_ct_b64.empty()) {
            if (msg.password_ct_b64.size() > kMaxSealedPasswordB64) {
                reject("Invalid room password", "room: oversized sealed password");
                return;
            }

            try {
                // AAD is the name exactly as it arrived, not the room's stored
                // casing — the client cannot know the latter. This binds the
                // sealed blob to the room it was minted for, so a captured
                // ROOM_JOIN cannot be replayed against a different room.
                const std::vector<uint8_t> aad(msg.name.begin(), msg.name.end());
                password = crypto::AESEngine::decrypt_string(
                    auth::SRPUtils::base64_to_bytes(msg.password_ct_b64), key_, aad);
            }
            catch (const std::exception&) {
                reject("Invalid room password", "room: password decryption failed");
                return;
            }

            if (password.empty() || password.size() > kMaxRoomPasswordLength) {
                reject("Invalid room password", "room: password length out of range");
                return;
            }

            if (std::ranges::any_of(password, [](const unsigned char c) { return c < 0x20; })) {
                reject("Invalid room password", "room: control character in password");
                return;
            }
        }

        auto result = create
            ? server_.rooms().create_and_join(
                  msg.name, password, user_id_, username_, shared_from_this(), key_)
            : server_.rooms().join(
                  msg.name, password, user_id_, username_, shared_from_this(), key_);

        switch (result.status) {
            case JoinStatus::Ok:
                break;
            case JoinStatus::NoSuchRoom:
                reject("No such room", "room: unknown room");
                return;
            case JoinStatus::PasswordRequired:
                // Deliberately not charged against the attempt budget: this is the
                // ordinary first step when a client's cached room list is stale.
                reject("Room password required", "room: password required");
                return;
            case JoinStatus::WrongPassword:
                ++room_password_attempts_;
                if (room_password_attempts_ >= kMaxRoomPasswordAttempts) {
                    fail("Too many incorrect room passwords",
                         "room: password attempt budget exhausted");
                    close();
                    return;
                }
                reject("Incorrect room password",
                       "room: wrong password (attempt " + std::to_string(room_password_attempts_)
                           + " of " + std::to_string(kMaxRoomPasswordAttempts) + ")");
                return;
            case JoinStatus::RoomFull:
                reject("Room is full", "room: member cap reached");
                return;
            case JoinStatus::NameTaken:
                reject("Room name already taken", "room: duplicate name");
                return;
            case JoinStatus::TooManyRooms:
                reject("Too many rooms on this server", "room: room cap reached");
                return;
        }

        // Joined first, so a refused join leaves the user where they were. Now
        // leave the old room *before* sending the new INIT: any stray broadcast
        // from the old room then arrives ahead of the INIT that replaces the
        // client's history and roster.
        auto previous = std::move(room_);
        room_         = std::move(result.room);

        if (previous) {
            previous->leave(user_id_);
            previous->broadcast_packet(
                Protocol::encode(MessageType::USER_LEFT, UserLeftMsg{username_}));
        }

        send(room_->init_packet_for(user_id_));
        room_->broadcast_packet(
            Protocol::encode(MessageType::USER_JOINED, UserJoinedMsg{username_, user_id_}),
            user_id_);

        if (previous)
            server_.rooms().drop_if_empty(previous->name());

        log::info("user '" + username_ + "' joined room '" + room_->name() + "'");
    }
} // namespace chat::server
```

- [ ] **Step 3: Dispatch the new message types**

In `src/server/session.cpp`, add to the `switch (type)` in `message_loop`, after the `MessageType::MESSAGE` case:

```cpp
                case MessageType::ROOM_LIST_REQ:
                    handle_room_list();
                    break;
                case MessageType::ROOM_CREATE:
                    handle_room_join(payload, true);
                    break;
                case MessageType::ROOM_JOIN:
                    handle_room_join(payload, false);
                    break;
```

- [ ] **Step 4: Add the file to the build**

In `CMakeLists.txt`, in `add_executable(chat_server ...)`, after `src/server/session.cpp`:

```cmake
        src/server/session_rooms.cpp
```

- [ ] **Step 5: Build and run the suite**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: PASS, and `chat_server` links.

- [ ] **Step 6: Commit**

```bash
git add include/chat/server/session.hpp src/server/session_rooms.cpp \
        src/server/session.cpp CMakeLists.txt
git commit -m "feat(server): handle room list, create, and join

Room failures send ERROR_MSG and keep the session alive so the client
can re-prompt. Only an exhausted wrong-password budget closes it."
```

---

### Task 8: Client room commands

**Files:**
- Modify: `include/chat/client/client.hpp`
- Modify: `src/client/client.cpp`

**Interfaces:**
- Consumes: the four message types, `RoomListMsg`, `RoomJoinMsg`, `RoomCreateMsg`, `InitMsg::room` (Task 1); server behavior from Task 7.
- Produces: nothing downstream.

- [ ] **Step 1: Add client state**

In `include/chat/client/client.hpp`, add to the includes:

```cpp
#include "chat/common/messages.hpp"
```

and to the private data, after `std::vector<User> users_;`:

```cpp
        std::string current_room_;
        std::vector<RoomInfo> rooms_;
        std::string room_filter_; // applied when the next ROOM_LIST arrives
        std::mutex rooms_mutex_;
```

Add the method declarations after `void print_banner();`:

```cpp
        // Returns false when the line was not a command and should be sent as chat.
        bool handle_command(const std::string& line);
        void print_rooms();
        // Seals `password` under the session key with the room name as AAD.
        // Returns "" for an empty password.
        [[nodiscard]] std::string seal_room_password(const std::string& room,
                                                     const std::string& password) const;
        boost::asio::awaitable<void> send_packet(std::vector<uint8_t> packet);
```

- [ ] **Step 2: Implement the helpers**

In `src/client/client.cpp`, add `#include <algorithm>` and `#include "chat/auth/srp_utils.hpp"` to the includes if absent, then add above `Client::input_loop`:

```cpp
    boost::asio::awaitable<void> Client::send_packet(std::vector<uint8_t> packet)
    {
        if (!connected_)
            co_return;

        try
        {
            co_await ProtocolHelpers::async_send_packet(socket_, packet);
        }
        catch (const std::exception& e)
        {
            log::error(std::string("failed to send: ") + e.what());
            connected_ = false;
        }
    }

    std::string Client::seal_room_password(const std::string& room, const std::string& password) const
    {
        if (password.empty())
            return "";

        const std::vector<uint8_t> aad(room.begin(), room.end());
        return auth::SRPUtils::bytes_to_base64(
            crypto::AESEngine::encrypt_string(password, room_key_, aad));
    }

    void Client::print_rooms()
    {
        std::vector<RoomInfo> shown;
        std::string filter;
        {
            std::lock_guard<std::mutex> lock(rooms_mutex_);
            filter = room_filter_;

            // Case-insensitive substring match, entirely client-side.
            const auto lower = [](std::string s) {
                std::ranges::transform(s, s.begin(), [](const unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                return s;
            };
            const auto needle = lower(filter);

            for (const auto& room : rooms_)
                if (needle.empty() || lower(room.name).find(needle) != std::string::npos)
                    shown.push_back(room);
        }

        std::lock_guard<std::mutex> lock(ui_mutex_);
        terminal::clear_line();

        std::cout << "\nRooms";
        if (!filter.empty())
            std::cout << " matching \"" << filter << "\"";
        std::cout << ":\n";

        if (shown.empty())
            std::cout << "  (none)\n";

        for (const auto& room : shown)
            std::cout << "  " << (room.has_password ? "[locked] " : "         ")
                << room.name << "  (" << room.user_count << " online)\n";

        std::cout << std::endl;
        std::cout << "[" << current_room_ << "] > " << std::flush;
    }
```

- [ ] **Step 3: Add the command parser**

Add above `Client::input_loop`:

```cpp
    bool Client::handle_command(const std::string& line)
    {
        if (line.empty() || line[0] != '/')
            return false;

        std::istringstream parts(line);
        std::string command;
        parts >> command;

        if (command == "/clear")
        {
            {
                std::lock_guard<std::mutex> lock(messages_mutex_);
                messages_.clear();
            }
            render_ui();
            return true;
        }

        if (command == "/help")
        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cout << "\nCommands:\n";
            std::cout << "  /rooms [filter]         - List rooms, optionally filtered by name\n";
            std::cout << "  /join <name>            - Join a room (prompts if it is locked)\n";
            std::cout << "  /create <name>          - Create and join a public room\n";
            std::cout << "  /create <name> --locked - Create a password-protected room\n";
            std::cout << "  /leave                  - Return to the lobby\n";
            std::cout << "  /clear                  - Clear message history\n";
            std::cout << "  /quit, /q               - Quit the chat\n";
            std::cout << "  /help                   - Show this help\n\n";
            return true;
        }

        if (command == "/rooms")
        {
            std::string filter;
            parts >> filter;
            {
                std::lock_guard<std::mutex> lock(rooms_mutex_);
                room_filter_ = filter;
            }
            boost::asio::co_spawn(
                io_context_,
                [this] { return send_packet(Protocol::encode(MessageType::ROOM_LIST_REQ)); },
                boost::asio::detached);
            return true;
        }

        if (command == "/leave")
        {
            boost::asio::co_spawn(
                io_context_,
                [this] {
                    return send_packet(Protocol::encode(
                        MessageType::ROOM_JOIN, RoomJoinMsg{"lobby", ""}));
                },
                boost::asio::detached);
            return true;
        }

        if (command == "/join" || command == "/create")
        {
            std::string name;
            parts >> name;
            if (name.empty())
            {
                std::lock_guard<std::mutex> lock(ui_mutex_);
                std::cout << "Usage: " << command << " <name>" << std::endl;
                return true;
            }

            std::string password;
            if (command == "/create")
            {
                std::string flag;
                parts >> flag;
                // Prompted rather than taken inline: a password typed on the
                // command line sits in the terminal scrollback.
                if (flag == "--locked")
                    password = terminal::read_password("Room password: ");
            }
            else
            {
                bool locked = false;
                {
                    std::lock_guard<std::mutex> lock(rooms_mutex_);
                    for (const auto& room : rooms_)
                        if (room.name == name && room.has_password)
                            locked = true;
                }
                if (locked)
                    password = terminal::read_password("Room password: ");
            }

            const auto sealed = seal_room_password(name, password);
            terminal::wipe(password);

            const auto packet = command == "/create"
                ? Protocol::encode(MessageType::ROOM_CREATE, RoomCreateMsg{name, sealed})
                : Protocol::encode(MessageType::ROOM_JOIN, RoomJoinMsg{name, sealed});

            boost::asio::co_spawn(
                io_context_,
                [this, packet] { return send_packet(packet); },
                boost::asio::detached);
            return true;
        }

        return false; // unknown /command: send it as chat, as before
    }
```

The `/join` path prompts only when the **cached** list marks the room locked. A stale cache means the server answers `Room password required`; the user runs `/rooms` and retries.

- [ ] **Step 4: Route `input_loop` through the parser**

Replace the body of `Client::input_loop` with:

```cpp
    void Client::input_loop()
    {
        std::string line;
        while (running_ && connected_)
        {
            {
                std::lock_guard<std::mutex> lock(ui_mutex_);
                std::cout << "[" << current_room_ << "] > ";
            }

            if (!std::getline(std::cin, line))
                break;

            if (line.empty())
                continue;

            if (line == "/quit" || line == "/q")
                break;

            if (handle_command(line))
                continue;

            boost::asio::co_spawn(
                io_context_,
                [this, line] { return send_message(line); },
                boost::asio::detached);
        }
    }
```

- [ ] **Step 5: Handle `ROOM_LIST` and the room name on `INIT`**

In `Client::handle_packet`, in the `MessageType::INIT` case, after the `users_` assignment and before `break;`:

```cpp
                {
                    std::lock_guard<std::mutex> lock(ui_mutex_);
                    current_room_ = msg.room;
                }
                render_ui();
```

`messages_` and `users_` are already replaced wholesale on INIT, which is exactly what a room switch needs.

Add a new case after `USER_LEFT`:

```cpp
            case MessageType::ROOM_LIST: {
                auto msg = Protocol::decode<RoomListMsg>(payload);
                {
                    std::lock_guard<std::mutex> lock(rooms_mutex_);
                    rooms_ = std::move(msg.rooms);
                }
                print_rooms();
                break;
            }
```

- [ ] **Step 6: Stop `ERROR_MSG` from killing the session**

Room errors are recoverable — the server keeps the connection open, so the client must too. Replace the `MessageType::ERROR_MSG` case with:

```cpp
            case MessageType::ERROR_MSG: {
                auto msg = Protocol::decode<ErrorMsg>(payload);
                std::lock_guard<std::mutex> lock(ui_mutex_);
                terminal::clear_line();
                std::cout << terminal::color("\033[31m") << "*** " << msg.error_msg << " ***"
                    << terminal::color("\033[0m") << std::endl;
                std::cout << "[" << current_room_ << "] > " << std::flush;
                break;
            }
```

The connection still ends when the server actually closes it: `receive_loop` catches the read failure and clears `connected_`. Handshake-time errors are unaffected — `srp_authenticate` inspects `ERROR_MSG` inline and throws before `receive_loop` ever starts.

- [ ] **Step 7: Show the room in the reprinted prompt**

Every site in `client.cpp` that reprints the bare prompt — in `handle_broadcast`, `USER_JOINED`, and `USER_LEFT` — changes from:

```cpp
                    std::cout << "> " << std::flush;
```

to:

```cpp
                    std::cout << "[" << current_room_ << "] > " << std::flush;
```

`current_room_` is written under `ui_mutex_`, and every one of these sites already holds it.

- [ ] **Step 8: Update the render header**

In `Client::render_ui`, add the room line inside the `users_mutex_` block:

```cpp
        {
            std::lock_guard<std::mutex> lock(users_mutex_);
            std::cout << "Room: " << current_room_ << "\n";
            std::cout << "Online users: ";
```

- [ ] **Step 9: Build and smoke-test rooms end to end**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: PASS.

```bash
./build/debug/chat_server --port 8899 --users-db /tmp/rooms-smoke.db &
./build/debug/chat_client --user alice --register --host localhost --port 8899
# second terminal:
./build/debug/chat_client --user bob --register --host localhost --port 8899
```

Walk through, from alice's client unless stated:
1. `/rooms` → shows `lobby (2 online)`.
2. `/create dev --locked`, password `hunter2` → prompt becomes `[dev] >`; bob sees alice leave the lobby.
3. In bob's client: `/rooms` → `dev` appears with `[locked]` and 1 online. `/join dev` prompts; enter `wrong` → `*** Incorrect room password ***` and the session survives. Enter `hunter2` → joins, prompt `[dev] >`.
4. Chat in `dev`; confirm both see the messages.
5. `/leave` on both → `/rooms` no longer lists `dev`.
6. `/join nowhere` → `*** No such room ***`, session survives.
7. `/create dev` twice → the second gives `*** Room name already taken ***`.

Kill the server and remove `/tmp/rooms-smoke.db`.

- [ ] **Step 10: Commit**

```bash
git add include/chat/client/client.hpp src/client/client.cpp
git commit -m "feat(client): add /rooms, /join, /create, and /leave

Room passwords are prompted, never taken inline, and sealed under the
session key with the room name as AAD. ERROR_MSG is no longer fatal:
room errors are recoverable and the server keeps the connection open."
```

---

### Task 9: Documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: everything.
- Produces: nothing.

- [ ] **Step 1: Document the rooms**

Add a `## Rooms` section after the existing "Run" section:

```markdown
## Rooms

Everyone starts in `lobby`. Rooms are created on demand and cease to exist when
their last member leaves — nothing about them is written to disk.

| Command | Effect |
|---|---|
| `/rooms [filter]` | List rooms. The filter is a case-insensitive substring match on the name. |
| `/join <name>` | Join a room. Prompts for the password when the room is locked. |
| `/create <name>` | Create and join a public room. |
| `/create <name> --locked` | Create a password-protected room, prompting for the password. |
| `/leave` | Return to `lobby`. |

Room names are 1–32 characters of `A-Z a-z 0-9 _ -` and are unique
case-insensitively: `Dev` and `dev` are the same room.

A room password is sealed under your session key before it leaves the client and
is stored server-side as a salted HMAC, never in the clear. The server does see
it at the moment it verifies — as it already sees every message — so **do not
reuse your account password as a room password.**

Room names and occupancy counts are visible to every logged-in user, including
for password-protected rooms. Discovery is the point of the list; the password
is what gates entry.
```

- [ ] **Step 2: Update the flag reference**

In the `chat_server` usage block, add after `--max-connections`:

```
  --max-rooms <n>          Room cap, lobby included (default 64)
  --max-room-members <n>   Members per room (default 64)
```

- [ ] **Step 3: Note the protocol version**

In the limitations/threat-model area, add:

```markdown
- **Protocol version 2.** A version-1 client is rejected at the handshake with a
  clear message rather than failing obscurely later.
```

- [ ] **Step 4: Verify and commit**

Run: `ctest --preset debug`
Expected: PASS.

```bash
git add README.md
git commit -m "docs: document rooms, room commands, and the new server flags"
```

---

## Self-Review

**Spec coverage.** Every spec section maps to a task: `RoomManager` → 4; `Room` name/password and the `try_join` → `join` rename → 2; `OnlineUsers` → 3; `Server`/`Session` wiring → 5, 6; protocol messages, `InitMsg::room`, version bump → 1; password sealing with room-name AAD → 1 (structs), 7 (server), 8 (client); validation and caps → 1 (names), 5 (flags), 7 (password); non-fatal error handling → 7 (server), 8 (client); disconnect cleanup → 6; client commands → 8; tests → 1–5; documentation → 9.

**Two things the spec did not anticipate**, both found while reading the code and both folded in above:

1. `Room::leave` calls `sink->close()`. Correct when disconnecting is the only way out of a room, fatal once a room switch is a leave followed by a join. Removed in Task 2, with the existing assertion at `tests/room_tests.cpp:91` inverted.
2. The client's `ERROR_MSG` handler sets `connected_ = false`, which would disconnect on every recoverable room error the spec requires the server to survive. Fixed in Task 8 Step 6.

**Type consistency.** `join` (not `try_join`) from Task 2 onward; `JoinStatus`/`JoinResult` spelled identically in Tasks 4, 6, 7 with the enumerator order fixed in Task 4's header; `room_key`/`is_valid_room_name`/`kDefaultRoom` from Task 1 used unchanged in 2, 4, 6, 7; `RoomInfo` field names (`name`, `user_count`, `has_password`) identical in Tasks 1, 4, 8; `room_password_attempts_` declared in Task 6, used in Task 7.

**Coverage gap, stated rather than papered over.** `Session` has no unit tests, because there is no end-to-end harness in this repository and building one is out of scope. Tasks 6 and 7 are verified by the manual two-client walkthroughs in Task 6 Step 6 and Task 8 Step 9. Everything below `Session` — `Room`, `RoomManager`, `OnlineUsers`, the wire format, name validation, CLI parsing — is unit-tested.
