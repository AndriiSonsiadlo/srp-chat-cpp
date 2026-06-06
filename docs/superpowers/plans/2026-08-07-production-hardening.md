# SRP Chat Production Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SRP-6a chat server and client cryptographically correct, resource-bounded, portable, configurable, and documented.

**Architecture:** The AES key stops travelling on the wire and is instead derived on both peers from the SRP shared secret via HKDF. The blocking thread-per-connection server is replaced by Boost.Asio C++20 coroutines with a strand-serialized write queue per session. Credential persistence is split out of the SRP protocol object into a `UserStore` with atomic writes. The wire format becomes explicitly little-endian with hard input limits.

**Tech Stack:** C++20, Boost.Asio 1.91 (coroutines: `awaitable`, `co_spawn`, `use_awaitable`), OpenSSL 3.6 (SHA-256, HKDF, AES-256-GCM, BIGNUM), GoogleTest 1.17, CMake ≥3.25 with presets, vcpkg manifest mode.

**Spec:** `docs/superpowers/specs/2026-08-07-production-hardening-design.md`

## Global Constraints

- C++20. `CMAKE_CXX_STANDARD 20`, `CMAKE_CXX_EXTENSIONS OFF`.
- `cmake_minimum_required(VERSION 3.25)`. Not 4.0.0.
- vcpkg baseline pinned to `8f57207a8a1b96a4a864e11f85d57b0a252b3ac3`.
- Dependencies are exactly: `boost-asio`, `boost-system`, `openssl`, plus `gtest` behind the `tests` feature. No new dependency may be added.
- Every integer on the wire is little-endian, written byte by byte. No `memcpy` of a struct or of a host-order integer into a packet.
- HKDF info string is exactly `"srp-chat/aes-256-gcm/v1"`.
- `kProtocolVersion = 1`.
- Wire limits: payload 1 MiB, string field 65536 bytes, vector count 1024, message text 4096 bytes, username 32 chars matching `[A-Za-z0-9_-]+`.
- No key material, and no plaintext message content, may appear in any packet or any log line.
- Commit messages are concise, lower-case, conventional-commit prefixed. **No `Co-Authored-By` trailer and no "Generated with" trailer.** Never `git push`.
- Every task ends green: `cmake --build --preset debug && ctest --preset debug`.

---

## File Structure

**Created:**

| File | Responsibility |
| --- | --- |
| `vcpkg.json` | Dependency manifest |
| `CMakePresets.json` | `release` / `debug` / `asan` configure, build, test presets |
| `include/chat/common/log.hpp` | Timestamped stderr logging, header-only |
| `include/chat/common/cli.hpp`, `src/common/cli.cpp` | `--flag value` parsing shared by both binaries |
| `include/chat/auth/user_store.hpp`, `src/auth/user_store.cpp` | Credential persistence, atomic writes |
| `include/chat/server/sink.hpp` | `Sink` — abstract packet destination, lets `Room` be tested without sockets |
| `include/chat/server/room.hpp`, `src/server/room.cpp` | Membership, per-user keys, history, broadcast |
| `include/chat/server/session.hpp`, `src/server/session.cpp` | One connection: coroutine handshake, read loop, write queue |
| `include/chat/client/terminal.hpp`, `src/client/terminal.cpp` | Echo-off password entry, ANSI output, TTY/`NO_COLOR` detection |
| `tests/wire_tests.cpp` | Encoding round-trip, byte order, limits |
| `tests/srp_tests.cpp` | Full in-process handshake, safety checks, key agreement |
| `tests/user_store_tests.cpp` | Persistence round-trip, atomicity, validation |
| `tests/room_tests.cpp` | Replaces `connection_manager_tests.cpp` |
| `README.md` | Threat model, build, run, flags, protocol, limitations |

**Deleted:** `include/chat/server/connection_manager.hpp`, `src/server/connection_manager.cpp`, `tests/connection_manager_tests.cpp`.

**Deviation from the spec's commit list:** the spec listed thirteen commits with slightly different
boundaries. Two changed here, for the same count: history encryption merged into the `Room` task
(commit 7) because `Room` owns the history, and the server rewrite split into "async sessions"
(commit 8) and "limits and timeouts" (commit 9) because the second is verification work over the
first. Test commits are folded into the feature task that introduces them, so each commit is green
on its own; commit 12 covers only the AEAD tests, which belong to no single feature.

**Heavily modified:** `include/chat/common/buffer.hpp`, `src/common/buffer.cpp`, `include/chat/common/types.hpp`, `include/chat/common/protocol.hpp`, `include/chat/common/messages.hpp`, `include/chat/auth/srp_*`, `src/auth/srp_*`, `include/chat/server/server.hpp`, `src/server/server.cpp`, `src/server/main.cpp`, `include/chat/client/client.hpp`, `src/client/client.cpp`, `src/client/main.cpp`, `CMakeLists.txt`.

---

## Task 1: Build system — vcpkg manifest and CMake presets

**Files:**
- Create: `vcpkg.json`, `CMakePresets.json`
- Modify: `CMakeLists.txt`, `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: presets `release`, `debug`, `asan`. Every later task verifies with `cmake --build --preset debug && ctest --preset debug`. CMake option `BUILD_TESTS` (already exists) and new option `CHAT_WERROR` (default `OFF`).

- [ ] **Step 1: Write `vcpkg.json`**

```json
{
  "name": "srp-chat",
  "version": "1.0.0",
  "description": "SRP-6a authenticated chat server and client",
  "builtin-baseline": "8f57207a8a1b96a4a864e11f85d57b0a252b3ac3",
  "dependencies": [
    "boost-asio",
    "boost-system",
    "openssl"
  ],
  "features": {
    "tests": {
      "description": "Build the unit test suite",
      "dependencies": [
        "gtest"
      ]
    }
  }
}
```

- [ ] **Step 2: Write `CMakePresets.json`**

`VCPKG_ROOT` is already set to `/home/dev/vcpkg` in this environment; the preset reads it from the environment so the file stays portable.

```json
{
  "version": 6,
  "cmakeMinimumRequired": {
    "major": 3,
    "minor": 25,
    "patch": 0
  },
  "configurePresets": [
    {
      "name": "base",
      "hidden": true,
      "generator": "Ninja",
      "binaryDir": "${sourceDir}/build/${presetName}",
      "toolchainFile": "$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
    },
    {
      "name": "release",
      "inherits": "base",
      "displayName": "Release (no tests)",
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Release",
        "BUILD_TESTS": "OFF"
      }
    },
    {
      "name": "debug",
      "inherits": "base",
      "displayName": "Debug with tests",
      "cacheVariables": {
        "CMAKE_BUILD_TYPE": "Debug",
        "BUILD_TESTS": "ON",
        "VCPKG_MANIFEST_FEATURES": "tests"
      }
    },
    {
      "name": "asan",
      "inherits": "debug",
      "displayName": "Debug with ASan and UBSan",
      "cacheVariables": {
        "CMAKE_CXX_FLAGS": "-fsanitize=address,undefined -fno-omit-frame-pointer",
        "CMAKE_EXE_LINKER_FLAGS": "-fsanitize=address,undefined"
      }
    }
  ],
  "buildPresets": [
    { "name": "release", "configurePreset": "release" },
    { "name": "debug", "configurePreset": "debug" },
    { "name": "asan", "configurePreset": "asan" }
  ],
  "testPresets": [
    {
      "name": "debug",
      "configurePreset": "debug",
      "output": { "outputOnFailure": true }
    },
    {
      "name": "asan",
      "configurePreset": "asan",
      "output": { "outputOnFailure": true }
    }
  ]
}
```

- [ ] **Step 3: Update the `CMakeLists.txt` header and warning block**

Replace lines 1–37 (through the existing `include_directories` call) with:

```cmake
cmake_minimum_required(VERSION 3.25)
project(SRPChat VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build tests" ON)
option(CHAT_WERROR "Treat warnings as errors" OFF)

# required for Boost.Asio
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)
    if(CHAT_WERROR)
        add_compile_options(-Werror)
    endif()
elseif(MSVC)
    add_compile_options(/W4 /wd4996)
    if(CHAT_WERROR)
        add_compile_options(/WX)
    endif()
endif()

find_package(Boost REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
```

Removed on purpose: the manual `-g -O0` / `-O2` block (`CMAKE_BUILD_TYPE` already supplies these, and the old code only checked `MATCHES "Debug"`), and the global `include_directories`. The existing `option(BUILD_TESTS ...)` further down the file (old line 105) must be deleted, since it now lives at the top.

- [ ] **Step 4: Fix the inverted `chat_crypto` dependency**

`chat_crypto` links `chat_auth` (old line 71), but `src/crypto/aes_engine.cpp` includes only OpenSSL headers. Task 3 needs the dependency in the opposite direction, so remove it now. The block becomes:

```cmake
# Crypto library
add_library(chat_crypto STATIC
        src/crypto/aes_engine.cpp
)
target_link_libraries(chat_crypto
        PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_include_directories(chat_crypto PUBLIC ${PROJECT_SOURCE_DIR}/include)
```

The three libraries already declare `target_include_directories(... PUBLIC ${PROJECT_SOURCE_DIR}/include)`; the executables inherit from them, so no executable needs its own include line.

- [ ] **Step 5: Ignore the generated database files**

Append to `.gitignore`:

```gitignore

# runtime state
users.db
users.db.tmp
```

- [ ] **Step 6: Configure and build both presets**

Run:
```bash
cmake --preset release && cmake --build --preset release
```
Expected: vcpkg installs `boost-asio`, `boost-system`, `openssl` on first run (several minutes), then `chat_server` and `chat_client` link. No test targets built.

Run:
```bash
cmake --preset debug && cmake --build --preset debug && ctest --preset debug
```
Expected: vcpkg additionally installs `gtest`; the four existing test binaries build and all tests pass.

If `-Wshadow` breaks the build, fix the shadowing variable — do not remove the flag.

- [ ] **Step 7: Commit**

```bash
git add vcpkg.json CMakePresets.json CMakeLists.txt .gitignore
git commit -m "build: add vcpkg manifest and cmake presets"
```

---

## Task 2: Wire format — little-endian encoding, input limits, version gate

**Files:**
- Modify: `include/chat/common/buffer.hpp`, `src/common/buffer.cpp`, `include/chat/common/types.hpp:10-16`, `include/chat/common/protocol.hpp`, `include/chat/common/messages.hpp:90-97`, `src/server/server.cpp:64`, `src/client/client.cpp:296`, `tests/protocol_tests.cpp:20-32`, `CMakeLists.txt`
- Create: `tests/wire_tests.cpp`

**Interfaces:**
- Consumes: Task 1's presets.
- Produces:
  - `chat::kMaxStringLength = 65536u`, `chat::kMaxVectorCount = 1024u` (in `buffer.hpp`).
  - `chat::kProtocolVersion = uint16_t{1}` (in `types.hpp`).
  - `MsgHeader::kWireSize = 6`, plus `chat::encode_header(const MsgHeader&) -> std::array<uint8_t, 6>` and `chat::decode_header(const std::array<uint8_t, 6>&) -> MsgHeader`.
  - `SrpInitMsg` field order becomes `{uint16_t protocol_version; std::string username; std::string A_b64;}`.
  - `BufferWriter::write<T>` / `BufferReader::read<T>` accept integral types only.
  - `struct Message` loses both `as_tuple()` overloads and is no longer serializable.

- [ ] **Step 1: Write the failing test file `tests/wire_tests.cpp`**

```cpp
#include "chat/common/buffer.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"
#include "chat/common/types.hpp"

#include <gtest/gtest.h>

namespace chat
{
    TEST(WireTest, Uint32IsLittleEndian)
    {
        BufferWriter w;
        w.write(uint32_t{0x01020304});
        ASSERT_EQ(w.data.size(), 4u);
        EXPECT_EQ(w.data[0], 0x04);
        EXPECT_EQ(w.data[1], 0x03);
        EXPECT_EQ(w.data[2], 0x02);
        EXPECT_EQ(w.data[3], 0x01);
    }

    TEST(WireTest, SignedRoundTripPreservesNegativeValues)
    {
        BufferWriter w;
        w.write(int64_t{-1234567890123LL});

        BufferReader r(w.data);
        EXPECT_EQ(r.read<int64_t>(), -1234567890123LL);
    }

    TEST(WireTest, HeaderRoundTrip)
    {
        const MsgHeader in{.type = static_cast<uint16_t>(MessageType::BROADCAST), .size = 300u};
        const MsgHeader out = decode_header(encode_header(in));

        EXPECT_EQ(out.type, in.type);
        EXPECT_EQ(out.size, in.size);
        EXPECT_EQ(MsgHeader::kWireSize, 6u);
    }

    TEST(WireTest, TruncatedIntegerThrows)
    {
        const std::vector<uint8_t> truncated{0x01, 0x02};
        BufferReader r(truncated);
        EXPECT_THROW((void)r.read<uint32_t>(), std::runtime_error);
    }

    TEST(WireTest, TruncatedStringBodyThrows)
    {
        BufferWriter w;
        w.write(uint32_t{16}); // claims 16 bytes
        w.write_bytes({'a', 'b', 'c'});

        BufferReader r(w.data);
        EXPECT_THROW((void)r.read_string(), std::runtime_error);
    }

    TEST(WireTest, OversizedStringLengthIsRejected)
    {
        BufferWriter w;
        w.write(static_cast<uint32_t>(kMaxStringLength + 1));

        BufferReader r(w.data);
        EXPECT_THROW((void)r.read_string(), std::runtime_error);
    }

    TEST(WireTest, OversizedVectorCountIsRejectedWithoutAllocating)
    {
        // A four-byte count claiming ~4 billion elements must be refused before
        // reserve() is reached, not after.
        BufferWriter w;
        w.write(uint32_t{0xFFFFFFFFu});

        EXPECT_THROW((void)Protocol::decode<InitMsg>(w.data), std::runtime_error);
    }

    TEST(WireTest, WritingAnOversizedStringIsRejected)
    {
        const std::string huge(kMaxStringLength + 1, 'x');
        BufferWriter w;
        EXPECT_THROW(w.write_string(huge), std::runtime_error);
    }

    TEST(WireTest, SrpInitCarriesProtocolVersionFirst)
    {
        const auto packet = Protocol::encode(
            MessageType::SRP_INIT,
            SrpInitMsg{kProtocolVersion, "alice", "QUJD"});

        const std::vector<uint8_t> payload(packet.begin() + MsgHeader::kWireSize, packet.end());
        const auto decoded = Protocol::decode<SrpInitMsg>(payload);

        EXPECT_EQ(decoded.protocol_version, kProtocolVersion);
        EXPECT_EQ(decoded.username, "alice");
        EXPECT_EQ(decoded.A_b64, "QUJD");
    }
} // namespace chat
```

- [ ] **Step 2: Register `wire_tests` in `CMakeLists.txt`**

Inside the `if(BUILD_TESTS)` block, beside the other test executables:

```cmake
    add_executable(wire_tests
            tests/wire_tests.cpp
    )
    target_link_libraries(wire_tests
            PRIVATE
            chat_common
            GTest::gtest_main
    )
```

and add `gtest_discover_tests(wire_tests)` beside the existing discovery calls.

- [ ] **Step 3: Run the build to verify it fails**

Run: `cmake --build --preset debug 2>&1 | tail -20`
Expected: compile errors — `encode_header`/`decode_header` not declared, `kMaxStringLength` not declared, `SrpInitMsg` has no member `protocol_version`.

- [ ] **Step 4: Rewrite `include/chat/common/buffer.hpp`**

```cpp
#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <stdexcept>

namespace chat
{
    // Hard limits applied while decoding untrusted input, before any allocation.
    inline constexpr uint32_t kMaxStringLength = 65536u;
    inline constexpr uint32_t kMaxVectorCount  = 1024u;

    class BufferWriter
    {
    public:
        std::vector<uint8_t> data;

        // Integers are written little-endian, byte by byte, so the wire format
        // depends on neither host byte order nor struct layout.
        template <typename T>
        void write(const T& value)
        {
            static_assert(std::is_integral_v<T>, "BufferWriter::write supports integral types only");

            auto bits = static_cast<std::make_unsigned_t<T>>(value);
            for (size_t i = 0; i < sizeof(T); ++i) {
                data.push_back(static_cast<uint8_t>(bits & 0xFFu));
                bits = static_cast<std::make_unsigned_t<T>>(bits >> 8);
            }
        }

        void write_string(const std::string& str);
        void write_bytes(const std::vector<uint8_t>& bytes);
    };

    class BufferReader
    {
    public:
        const std::vector<uint8_t>& data;
        size_t pos = 0;

        explicit BufferReader(const std::vector<uint8_t>& d);

        template <typename T>
        T read()
        {
            static_assert(std::is_integral_v<T>, "BufferReader::read supports integral types only");

            if (sizeof(T) > data.size() - pos)
                throw std::runtime_error("Buffer underflow");

            std::make_unsigned_t<T> bits = 0;
            for (size_t i = 0; i < sizeof(T); ++i)
                bits = static_cast<std::make_unsigned_t<T>>(
                    bits | (static_cast<std::make_unsigned_t<T>>(data[pos + i]) << (8 * i)));

            pos += sizeof(T);
            return static_cast<T>(bits);
        }

        std::string read_string();
        void read_bytes(uint8_t* dest, size_t count);
    };
}
```

The underflow check is written `sizeof(T) > data.size() - pos`, not `pos + sizeof(T) > data.size()`. `pos` is always `<= data.size()`, so the subtraction cannot wrap and the comparison cannot overflow for any input.

- [ ] **Step 5: Rewrite `src/common/buffer.cpp`**

```cpp
#include "chat/common/buffer.hpp"

namespace chat
{
    void BufferWriter::write_string(const std::string& str)
    {
        if (str.size() > kMaxStringLength)
            throw std::runtime_error("String field exceeds maximum length");

        write(static_cast<uint32_t>(str.size()));

        const size_t old_size = data.size();
        data.resize(old_size + str.size());
        std::memcpy(data.data() + old_size, str.data(), str.size());
    }

    void BufferWriter::write_bytes(const std::vector<uint8_t>& bytes)
    {
        const size_t old_size = data.size();
        data.resize(old_size + bytes.size());
        std::memcpy(data.data() + old_size, bytes.data(), bytes.size());
    }

    BufferReader::BufferReader(const std::vector<uint8_t>& d)
        : data(d)
    {
    }

    std::string BufferReader::read_string()
    {
        const auto length = read<uint32_t>();

        if (length > kMaxStringLength)
            throw std::runtime_error("String field exceeds maximum length");

        if (length > data.size() - pos)
            throw std::runtime_error("Buffer underflow");

        std::string str(reinterpret_cast<const char*>(data.data() + pos), length);
        pos += length;
        return str;
    }

    void BufferReader::read_bytes(uint8_t* dest, const size_t count)
    {
        if (count > data.size() - pos)
            throw std::runtime_error("Buffer underflow");

        std::memcpy(dest, data.data() + pos, count);
        pos += count;
    }
} // namespace chat
```

- [ ] **Step 6: Replace the packed `MsgHeader` in `include/chat/common/types.hpp`**

Add `#include <array>` and `#include <cstddef>` to the includes, then replace the `#pragma pack` block (lines 10–16) with:

```cpp
    inline constexpr uint16_t kProtocolVersion = 1;

    struct MsgHeader
    {
        uint16_t type; // MessageType
        uint32_t size; // payload size in bytes

        // Bytes on the wire: 2 for type, 4 for size. Deliberately not
        // sizeof(MsgHeader) — the struct is never memcpy'd into a packet.
        static constexpr size_t kWireSize = 6;
    };

    inline std::array<uint8_t, MsgHeader::kWireSize> encode_header(const MsgHeader& header)
    {
        return {
            static_cast<uint8_t>(header.type & 0xFFu),
            static_cast<uint8_t>((header.type >> 8) & 0xFFu),
            static_cast<uint8_t>(header.size & 0xFFu),
            static_cast<uint8_t>((header.size >> 8) & 0xFFu),
            static_cast<uint8_t>((header.size >> 16) & 0xFFu),
            static_cast<uint8_t>((header.size >> 24) & 0xFFu),
        };
    }

    inline MsgHeader decode_header(const std::array<uint8_t, MsgHeader::kWireSize>& raw)
    {
        return MsgHeader{
            .type = static_cast<uint16_t>(raw[0] | (raw[1] << 8)),
            .size = static_cast<uint32_t>(raw[2])
                  | (static_cast<uint32_t>(raw[3]) << 8)
                  | (static_cast<uint32_t>(raw[4]) << 16)
                  | (static_cast<uint32_t>(raw[5]) << 24),
        };
    }
```

Also delete both `as_tuple()` overloads from `struct Message` (lines 61–69). `Message` is an in-memory type from here on and must never be serialized directly, because its `text` is plaintext. `struct User` keeps its `as_tuple()` overloads unchanged.

- [ ] **Step 7: Update `include/chat/common/protocol.hpp`**

Add `#include <array>`. Replace `make_packet` (lines 116–130):

```cpp
        static std::vector<uint8_t> make_packet(MessageType type, const std::vector<uint8_t>& payload)
        {
            const auto raw = encode_header(MsgHeader{
                .type = static_cast<uint16_t>(type),
                .size = static_cast<uint32_t>(payload.size())
            });

            std::vector<uint8_t> packet;
            packet.reserve(MsgHeader::kWireSize + payload.size());
            packet.insert(packet.end(), raw.begin(), raw.end());
            packet.insert(packet.end(), payload.begin(), payload.end());
            return packet;
        }
```

Replace `read_field` for `std::vector<T>` (lines 69–84). Both guards must precede the allocation they protect:

```cpp
        template <class T>
        static std::vector<T> read_field(BufferReader& r, std::type_identity<std::vector<T>>)
        {
            const auto count = r.read<uint32_t>();
            if (count > kMaxVectorCount)
                throw std::runtime_error("Vector field exceeds maximum element count");

            std::vector<T> result;
            result.reserve(count);

            for (uint32_t i = 0; i < count; ++i) {
                const auto item_size = r.read<uint32_t>();
                if (item_size > kMaxStringLength)
                    throw std::runtime_error("Vector element exceeds maximum size");

                std::vector<uint8_t> item_data(item_size);
                r.read_bytes(item_data.data(), item_size);
                result.push_back(deserialize_object<T>(item_data));
            }

            return result;
        }
```

Replace `receive_packet` (lines 144–158):

```cpp
        inline std::pair<MessageType, std::vector<uint8_t>> receive_packet(boost::asio::ip::tcp::socket& socket)
        {
            std::array<uint8_t, MsgHeader::kWireSize> raw{};
            boost::asio::read(socket, boost::asio::buffer(raw));

            const auto header = decode_header(raw);
            if (header.size > kMaxPayloadSize)
                throw std::runtime_error("Incoming payload exceeds maximum allowed size");

            std::vector<uint8_t> payload(header.size);
            if (header.size > 0)
                boost::asio::read(socket, boost::asio::buffer(payload));

            return {static_cast<MessageType>(header.type), std::move(payload)};
        }
```

- [ ] **Step 8: Add the version field to `SrpInitMsg`**

In `include/chat/common/messages.hpp`, add `#include <cstdint>` and replace `struct SrpInitMsg` (lines 90–97):

```cpp
    struct SrpInitMsg
    {
        uint16_t protocol_version;
        std::string username;
        std::string A_b64;

        [[nodiscard]] auto as_tuple() const { return std::tie(protocol_version, username, A_b64); }
        [[nodiscard]] auto as_tuple() { return std::tie(protocol_version, username, A_b64); }
    };
```

- [ ] **Step 9: Update both `SrpInitMsg` construction sites and add the server-side check**

In `src/client/client.cpp`, both `SRP_INIT` packets — the first at line 296 and the registration retry at line 316 — gain the version as the leading field:

```cpp
        send_packet(Protocol::encode(
            MessageType::SRP_INIT,
            SrpInitMsg{kProtocolVersion, username_, auth::SRPUtils::bytes_to_base64(A)}));
```

In `src/server/server.cpp`, replace the structured binding at line 64 with a named decode plus the version gate:

```cpp
                auto init = Protocol::decode<SrpInitMsg>(msg);
                if (init.protocol_version != kProtocolVersion) {
                    conn->send_packet(Protocol::encode(
                        MessageType::ERROR_MSG,
                        ErrorMsg{"Unsupported protocol version " + std::to_string(init.protocol_version)
                                 + "; server speaks version " + std::to_string(kProtocolVersion)}));
                    return std::nullopt;
                }

                if (init.username.empty() || init.A_b64.empty()) {
                    conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Invalid SRP_INIT"}));
                    return std::nullopt;
                }

                auto A = auth::SRPUtils::base64_to_bytes(init.A_b64);
```

The two later uses of `init_username` in that block (the `init_authentication` call and the `username = std::move(init_username)` assignment) become `init.username`.

- [ ] **Step 10: Update `tests/protocol_tests.cpp` helpers**

Add `#include <array>` and `#include <algorithm>`, then replace the two helpers (lines 20–32) that currently `memcpy` the header struct:

```cpp
        MsgHeader extract_header(const std::vector<uint8_t>& packet)
        {
            EXPECT_GE(packet.size(), MsgHeader::kWireSize);
            std::array<uint8_t, MsgHeader::kWireSize> raw{};
            std::copy_n(packet.begin(), MsgHeader::kWireSize, raw.begin());
            return decode_header(raw);
        }

        std::vector<uint8_t> extract_payload(const std::vector<uint8_t>& packet)
        {
            EXPECT_GE(packet.size(), MsgHeader::kWireSize);
            return std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        }
```

Then run `grep -n "InitMsg\|Message{" tests/protocol_tests.cpp`. Any test that puts `Message` objects into an `InitMsg` no longer compiles, because `Message` lost `as_tuple`. Delete those assertions; `InitMsg::messages` gets real coverage in Task 7 once it holds `HistoryEntry`. Keep any assertions over `InitMsg::users`.

- [ ] **Step 11: Run the tests**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: `wire_tests`, `protocol_tests`, `types_tests`, `aes_tests`, and `connection_manager_tests` all pass.

- [ ] **Step 12: Commit**

```bash
git add include/chat/common src/common src/server/server.cpp src/client/client.cpp tests/wire_tests.cpp tests/protocol_tests.cpp CMakeLists.txt
git commit -m "refactor(wire): little-endian framing, input limits, version gate"
```

---

## Task 3: Derive the session key from the SRP shared secret

This is the critical security fix. Today the server invents a random key and mails it to the client
in cleartext; after this task no key material appears on the wire at all.

**Files:**
- Modify: `include/chat/auth/srp_types.hpp`, `include/chat/auth/srp_server.hpp:66-76`, `src/auth/srp_server.cpp:208-227`, `include/chat/auth/srp_client.hpp:44-58`, `src/auth/srp_client.cpp:9-19,42-67`, `include/chat/common/messages.hpp:119-126`, `src/server/server.cpp:126-148`, `src/client/client.cpp:373-387`, `CMakeLists.txt`
- Create: `tests/srp_tests.cpp`

**Interfaces:**
- Consumes: Task 2's `kProtocolVersion` and encoding.
- Produces:
  - `chat::auth::kSessionKeyInfo` — `inline constexpr const char* kSessionKeyInfo = "srp-chat/aes-256-gcm/v1";` in `srp_types.hpp`.
  - `SRPServer::VerifyResponse` becomes `{ std::vector<uint8_t> H_AMK; }` — the `session_key` member is gone.
  - `SRPServer::derive_session_key(const std::string& user_id) const -> std::vector<uint8_t>` — 32 bytes, throws `std::runtime_error` if the session is unknown or unauthenticated.
  - `SRPClient::derive_session_key(const std::vector<uint8_t>& room_salt) const -> std::vector<uint8_t>` — 32 bytes, throws if `process_challenge` has not run.
  - `SRPClient` constructor becomes `SRPClient(std::string username, std::string password)` — by value, no pointer.
  - `SrpSuccessMsg` becomes `{ std::string H_AMK_b64; }`.

- [ ] **Step 1: Write the failing test file `tests/srp_tests.cpp`**

This drives the whole handshake in-process, with no sockets, so it is fast and deterministic.

```cpp
#include "chat/auth/srp_client.hpp"
#include "chat/auth/srp_server.hpp"
#include "chat/auth/srp_types.hpp"
#include "chat/crypto/aes_engine.hpp"

#include <gtest/gtest.h>

namespace chat::auth
{
    namespace
    {
        // Registers `username` on `server` and returns a client ready to authenticate.
        SRPServer make_server_with_user(const std::string& username, const std::string& password)
        {
            SRPServer server;
            server.register_user(username, SRPClient::register_user(username, password));
            return server;
        }
    }

    TEST(SrpTest, BothSidesDeriveTheSameKeyWithoutExchangingIt)
    {
        const std::string username = "alice";
        const std::string password = "correct horse battery staple";

        auto server = make_server_with_user(username, password);
        SRPClient client(username, password);

        const auto A         = client.generate_A();
        const auto challenge = server.init_authentication(username, A);
        const auto M         = client.process_challenge(challenge.B, challenge.salt);
        const auto verify    = server.verify_authentication(challenge.user_id, M);

        ASSERT_TRUE(client.verify_server(verify.H_AMK));

        const auto client_key = client.derive_session_key(challenge.room_salt);
        const auto server_key = server.derive_session_key(challenge.user_id);

        EXPECT_EQ(client_key.size(), crypto::AESEngine::KEY_SIZE);
        EXPECT_EQ(client_key, server_key);
    }

    TEST(SrpTest, DerivedKeyActuallyDecryptsAMessage)
    {
        auto server = make_server_with_user("bob", "hunter2");
        SRPClient client("bob", "hunter2");

        const auto A         = client.generate_A();
        const auto challenge = server.init_authentication("bob", A);
        const auto M         = client.process_challenge(challenge.B, challenge.salt);
        const auto verify    = server.verify_authentication(challenge.user_id, M);
        ASSERT_TRUE(client.verify_server(verify.H_AMK));

        const auto client_key = client.derive_session_key(challenge.room_salt);
        const auto server_key = server.derive_session_key(challenge.user_id);

        const auto sealed = crypto::AESEngine::encrypt_string("ping", client_key);
        EXPECT_EQ(crypto::AESEngine::decrypt_string(sealed, server_key), "ping");
    }

    TEST(SrpTest, WrongPasswordFailsVerification)
    {
        auto server = make_server_with_user("carol", "right-password");
        SRPClient client("carol", "wrong-password");

        const auto A         = client.generate_A();
        const auto challenge = server.init_authentication("carol", A);
        const auto M         = client.process_challenge(challenge.B, challenge.salt);

        EXPECT_THROW((void)server.verify_authentication(challenge.user_id, M), std::runtime_error);
    }

    TEST(SrpTest, DeriveSessionKeyBeforeVerificationThrows)
    {
        auto server = make_server_with_user("dave", "pw");
        SRPClient client("dave", "pw");

        EXPECT_THROW((void)client.derive_session_key(std::vector<uint8_t>(16, 0x00)), std::runtime_error);
        EXPECT_THROW((void)server.derive_session_key("user_does_not_exist"), std::runtime_error);
    }

    TEST(SrpTest, DifferentUsersDeriveDifferentKeys)
    {
        SRPServer server;
        server.register_user("erin", SRPClient::register_user("erin", "pw-1"));
        server.register_user("frank", SRPClient::register_user("frank", "pw-2"));

        auto authenticate = [&server](const std::string& user, const std::string& pass) {
            SRPClient client(user, pass);
            const auto A         = client.generate_A();
            const auto challenge = server.init_authentication(user, A);
            const auto M         = client.process_challenge(challenge.B, challenge.salt);
            const auto verify    = server.verify_authentication(challenge.user_id, M);
            EXPECT_TRUE(client.verify_server(verify.H_AMK));
            return client.derive_session_key(challenge.room_salt);
        };

        EXPECT_NE(authenticate("erin", "pw-1"), authenticate("frank", "pw-2"));
    }
} // namespace chat::auth
```

- [ ] **Step 2: Register `srp_tests` in `CMakeLists.txt`**

```cmake
    add_executable(srp_tests
            tests/srp_tests.cpp
    )
    target_link_libraries(srp_tests
            PRIVATE
            chat_auth
            chat_crypto
            GTest::gtest_main
    )
```

and add `gtest_discover_tests(srp_tests)`.

Then make `chat_auth` depend on `chat_crypto`, which is now legal because Task 1 removed the reverse edge:

```cmake
target_link_libraries(chat_auth
        PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        chat_crypto
)
```

- [ ] **Step 3: Run the build to verify it fails**

Run: `cmake --build --preset debug 2>&1 | tail -20`
Expected: compile errors — `SRPClient` has no two-`std::string` constructor, and neither class declares `derive_session_key`.

- [ ] **Step 4: Add the info constant and the session `K` field**

In `include/chat/auth/srp_types.hpp`, after `SRP_G_HEX`:

```cpp
    // HKDF context string binding the derived key to this protocol and version.
    inline constexpr const char* kSessionKeyInfo = "srp-chat/aes-256-gcm/v1";
```

`SRPSession` already has a `K` member; it is currently assigned to a local copy and then written
back, which works. Leave the struct alone in this task.

- [ ] **Step 5: Strip the key out of the server and add the derivation**

In `include/chat/auth/srp_server.hpp`, replace the `VerifyResponse` struct (lines 68–72) and add
the new method beneath `verify_authentication`:

```cpp
        struct VerifyResponse
        {
            std::vector<uint8_t> H_AMK;
        };

        VerifyResponse verify_authentication(
            const std::string& user_id,
            const std::vector<uint8_t>& M);

        // AES-256-GCM key for this session: HKDF(K, salt = room_salt, info = kSessionKeyInfo).
        // Never transmitted. Throws if the session is unknown or not yet authenticated.
        [[nodiscard]] std::vector<uint8_t> derive_session_key(const std::string& user_id) const;
```

`derive_session_key` is `const` but touches `sessions_mutex_`, so mark that mutex `mutable`:

```cpp
        mutable std::mutex sessions_mutex_;
```

In `src/auth/srp_server.cpp`, replace the tail of `verify_authentication` (lines 207–227):

```cpp
        // authentication successful
        session.authenticated = true;

        // calculate H_AMK = H(A, M, K)
        auto H_AMK = SRPUtils::calculate_H_AMK(A, M, K);

        // update session (K is retained so the AES key can be derived locally)
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            sessions_[user_id] = session;
        }

        return VerifyResponse{.H_AMK = H_AMK};
    }

    std::vector<uint8_t> SRPServer::derive_session_key(const std::string& user_id) const
    {
        std::vector<uint8_t> K;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            const auto it = sessions_.find(user_id);
            if (it == sessions_.end() || !it->second.authenticated)
                throw std::runtime_error("No authenticated session for this user id");
            K = it->second.K;
        }

        return crypto::AESEngine::derive_key(K, room_salt_, kSessionKeyInfo);
    }
```

Add `#include "chat/crypto/aes_engine.hpp"` and `#include <stdexcept>` to the file. Delete the two
lines that generated `session_key_bytes` / `session_key_b64` — that random key is the defect.

- [ ] **Step 6: Give the client the matching derivation and a value-typed password**

In `include/chat/auth/srp_client.hpp`, change the member and constructor and add the method:

```cpp
        std::string password_;
```

```cpp
        SRPClient(std::string username, std::string password);
        ~SRPClient();
```

```cpp
        // AES-256-GCM key for this session: HKDF(K, salt = room_salt, info = kSessionKeyInfo).
        // Never transmitted. Throws if process_challenge() has not run.
        [[nodiscard]] std::vector<uint8_t> derive_session_key(const std::vector<uint8_t>& room_salt) const;
```

Keep `get_session_key()` returning `K_` — it is the SRP shared secret, distinct from the AES key,
and the tests do not use it. In `src/auth/srp_client.cpp`:

```cpp
    SRPClient::SRPClient(std::string username, std::string password)
        : username_(std::move(username))
          , password_(std::move(password))
    {
        N_ = std::make_unique<SRPUtils::BigNum>(SRP_N_HEX_2048);
        g_ = std::make_unique<SRPUtils::BigNum>(SRP_G_HEX);
        k_ = std::make_unique<SRPUtils::BigNum>(SRPUtils::calculate_k(*N_, *g_));
    }

    SRPClient::~SRPClient()
    {
        OPENSSL_cleanse(password_.data(), password_.size());
        if (!K_.empty()) OPENSSL_cleanse(K_.data(), K_.size());
    }
```

Change the one use of `*password_` inside `process_challenge` to `password_`, and append the new
method:

```cpp
    std::vector<uint8_t> SRPClient::derive_session_key(const std::vector<uint8_t>& room_salt) const
    {
        if (K_.empty())
            throw std::runtime_error("Must call process_challenge() first");

        return crypto::AESEngine::derive_key(K_, room_salt, kSessionKeyInfo);
    }
```

Add `#include "chat/crypto/aes_engine.hpp"` and `#include <openssl/crypto.h>`.

- [ ] **Step 7: Shrink `SrpSuccessMsg`**

In `include/chat/common/messages.hpp`, replace `struct SrpSuccessMsg` (lines 119–126):

```cpp
    struct SrpSuccessMsg
    {
        std::string H_AMK_b64;

        [[nodiscard]] auto as_tuple() const { return std::tie(H_AMK_b64); }
        [[nodiscard]] auto as_tuple() { return std::tie(H_AMK_b64); }
    };
```

- [ ] **Step 8: Update the server handshake**

In `src/server/server.cpp`, replace lines 126–148 (the `SRP_SUCCESS` send through the
`connection_manager_->add` call):

```cpp
            // send SRP_SUCCESS — proof only, no key material
            conn->send_packet(Protocol::encode(
                MessageType::SRP_SUCCESS,
                SrpSuccessMsg{auth::SRPUtils::bytes_to_base64(verify.H_AMK)}));

            std::string user_id = response_user_id;
            auto session_key    = srp_server_->derive_session_key(user_id);
            if (session_key.size() != crypto::AESEngine::KEY_SIZE) {
                conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Invalid session key size"}));
                return std::nullopt;
            }

            connection_manager_->add(user_id, username, conn);
```

Both `base64_to_bytes(std::string(verify.session_key.begin(), ...))` calls disappear with it.

- [ ] **Step 9: Update the client handshake**

In `src/client/client.cpp`, replace lines 373–387 (from `auto srpSuccessMsg = ...` through the key
size check):

```cpp
        auto srpSuccessMsg = Protocol::decode<SrpSuccessMsg>(success_payload);
        auto H_AMK         = auth::SRPUtils::base64_to_bytes(srpSuccessMsg.H_AMK_b64);

        // verify server
        if (!srp_client_->verify_server(H_AMK))
            throw std::runtime_error("Server verification failed");

        room_key_ = srp_client_->derive_session_key(room_salt);
        if (room_key_.size() != crypto::AESEngine::KEY_SIZE)
            throw std::runtime_error("Invalid AES room key size");
```

The `(void)room_salt;` line at 382 is deleted — `room_salt` is now load-bearing.

The `SRPClient` construction at line 40 becomes `std::make_unique<auth::SRPClient>(username_, password_)`.
Note the ordering problem this exposes: `run()` constructs `SRPClient` before `srp_authenticate()`
prompts for the password, so with a by-value password the client would hash an empty string. Move
the construction to the point in `srp_authenticate()` **after** the password has been read (that is,
after the `std::getline(std::cin, password_)` at line 346 and after the one at line 420 in
`srp_register`), and delete the construction at line 40. Both `srp_register()` and the challenge
path must construct it before use; `generate_A()` is called before the password is read, so the
construction must move to the top of `srp_authenticate()` and the password must be prompted before
`generate_A()`. Restructure `srp_authenticate()` so the order is: connect → prompt password →
construct `SRPClient` → `generate_A()` → send `SRP_INIT`. Task 11 revisits this prompt for
echo suppression.

- [ ] **Step 10: Run the tests**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: all five `SrpTest` cases pass, and the previously passing suites stay green.

- [ ] **Step 11: Verify no key is on the wire**

Run: `grep -rn "session_key" include/ src/`
Expected: no hits in `messages.hpp` and no hits anywhere that construct or parse a packet. Hits
inside `srp_client.cpp` / `srp_server.cpp` for `derive_session_key` are correct.

- [ ] **Step 12: Commit**

```bash
git add include src tests/srp_tests.cpp CMakeLists.txt
git commit -m "fix(auth): derive session key from srp shared secret"
```

---

## Task 4: SRP-6a safety checks, constant-time comparison, unpredictable ids

**Files:**
- Modify: `include/chat/auth/srp_utils.hpp`, `src/auth/srp_utils.cpp`, `include/chat/auth/srp_types.hpp:30-40`, `include/chat/auth/srp_server.hpp`, `src/auth/srp_server.cpp`, `src/auth/srp_client.cpp`, `tests/srp_tests.cpp`

**Interfaces:**
- Consumes: Task 3's `derive_session_key` and test fixture.
- Produces, all on `SRPUtils`:
  - `class BnCtx` — RAII `BN_CTX*`, `BnCtx()` throws on failure, `BN_CTX* get()`.
  - `static bool is_zero_mod(const BigNum& value, const BigNum& N)` — true when `value mod N == 0`.
  - `static bool constant_time_equals(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b)`.
  - `static std::string random_hex_id(size_t byte_count)`.
- `SRPSession` gains `std::string username;` and `std::chrono::steady_clock::time_point created_at;`.
- `SRPServer::clear_expired_sessions(int timeout_seconds = 3600)` becomes functional.

- [ ] **Step 1: Add the failing tests to `tests/srp_tests.cpp`**

```cpp
    TEST(SrpTest, ServerRejectsZeroA)
    {
        auto server = make_server_with_user("grace", "pw");

        // A ≡ 0 (mod N) forces S = 0 on the server side and must be refused
        // outright. Both a literal zero and a bare N are rejected.
        const std::vector<uint8_t> zero_A{0x00};
        EXPECT_THROW((void)server.init_authentication("grace", zero_A), std::runtime_error);

        const auto N_bytes = SRPUtils::BigNum(std::string(SRP_N_HEX_2048)).to_bytes();
        EXPECT_THROW((void)server.init_authentication("grace", N_bytes), std::runtime_error);
    }

    TEST(SrpTest, ClientRejectsZeroB)
    {
        SRPClient client("heidi", "pw");
        (void)client.generate_A();

        const std::vector<uint8_t> zero_B{0x00};
        const std::vector<uint8_t> salt(SRP_SALT_SIZE, 0x01);
        EXPECT_THROW((void)client.process_challenge(zero_B, salt), std::runtime_error);
    }

    TEST(SrpTest, ConstantTimeEqualsMatchesValueEquality)
    {
        const std::vector<uint8_t> a{1, 2, 3, 4};
        const std::vector<uint8_t> b{1, 2, 3, 4};
        const std::vector<uint8_t> c{1, 2, 3, 5};
        const std::vector<uint8_t> shorter{1, 2, 3};

        EXPECT_TRUE(SRPUtils::constant_time_equals(a, b));
        EXPECT_FALSE(SRPUtils::constant_time_equals(a, c));
        EXPECT_FALSE(SRPUtils::constant_time_equals(a, shorter));
    }

    TEST(SrpTest, UserIdsAreLongAndDistinct)
    {
        std::set<std::string> ids;
        for (int i = 0; i < 200; ++i) {
            auto id = SRPUtils::random_hex_id(16);
            EXPECT_EQ(id.size(), 32u); // 16 bytes, hex encoded
            ids.insert(id);
        }
        EXPECT_EQ(ids.size(), 200u);
    }

    TEST(SrpTest, ExpiredSessionsAreSweptAway)
    {
        auto server = make_server_with_user("ivan", "pw");
        SRPClient client("ivan", "pw");

        const auto A         = client.generate_A();
        const auto challenge = server.init_authentication("ivan", A);
        const auto M         = client.process_challenge(challenge.B, challenge.salt);
        (void)server.verify_authentication(challenge.user_id, M);

        EXPECT_TRUE(server.is_session_valid(challenge.user_id));

        server.clear_expired_sessions(0); // everything older than zero seconds
        EXPECT_FALSE(server.is_session_valid(challenge.user_id));
    }

    TEST(SrpTest, SessionRemembersItsUsername)
    {
        // Two users deliberately share a salt so that the old salt-scanning
        // lookup would resolve the wrong identity.
        SRPServer server;
        auto judy = SRPClient::register_user("judy", "pw-judy");
        auto karl = SRPClient::register_user("karl", "pw-karl");
        karl.salt = judy.salt;

        server.register_user("judy", judy);
        server.register_user("karl", karl);

        SRPClient client("karl", "pw-karl");
        const auto A         = client.generate_A();
        const auto challenge = server.init_authentication("karl", A);
        const auto M         = client.process_challenge(challenge.B, challenge.salt);

        EXPECT_NO_THROW((void)server.verify_authentication(challenge.user_id, M));
    }
```

Add `#include <set>` to the test file.

- [ ] **Step 2: Run the build to verify it fails**

Run: `cmake --build --preset debug 2>&1 | tail -20`
Expected: `constant_time_equals` and `random_hex_id` are not members of `SRPUtils`.

- [ ] **Step 3: Add the new `SRPUtils` members**

In `include/chat/auth/srp_utils.hpp`, inside `class SRPUtils`, above the `BigNum` class:

```cpp
        // RAII BN_CTX. Replaces the manual allocate/free-on-every-error-path
        // pattern that the SRP maths used to repeat in each function.
        class BnCtx
        {
        private:
            BN_CTX* ctx_;

        public:
            BnCtx();
            ~BnCtx();

            BnCtx(const BnCtx&)            = delete;
            BnCtx& operator=(const BnCtx&) = delete;

            BN_CTX* get() { return ctx_; }
        };
```

and in the public function list:

```cpp
        // SRP-6a safety check: reject ephemeral values congruent to zero mod N.
        static bool is_zero_mod(const BigNum& value, const BigNum& N);

        // Timing-safe byte comparison. Returns false for differing sizes.
        static bool constant_time_equals(
            const std::vector<uint8_t>& a,
            const std::vector<uint8_t>& b);

        // Cryptographically random hex identifier, `byte_count` bytes of entropy.
        static std::string random_hex_id(size_t byte_count);
```

In `src/auth/srp_utils.cpp`, add `#include <openssl/crypto.h>` and implement:

```cpp
    SRPUtils::BnCtx::BnCtx() : ctx_(BN_CTX_new())
    {
        if (!ctx_) throw std::runtime_error("Failed to create BN_CTX");
    }

    SRPUtils::BnCtx::~BnCtx()
    {
        if (ctx_) BN_CTX_free(ctx_);
    }

    bool SRPUtils::is_zero_mod(const BigNum& value, const BigNum& N)
    {
        BnCtx ctx;
        BigNum remainder;
        if (!BN_mod(remainder.get(), value.get(), N.get(), ctx.get()))
            throw std::runtime_error("Failed to reduce value mod N");

        return BN_is_zero(remainder.get()) == 1;
    }

    bool SRPUtils::constant_time_equals(
        const std::vector<uint8_t>& a,
        const std::vector<uint8_t>& b)
    {
        if (a.size() != b.size())
            return false;

        return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
    }

    std::string SRPUtils::random_hex_id(const size_t byte_count)
    {
        return bytes_to_hex(random_bytes(byte_count));
    }
```

- [ ] **Step 4: Convert the SRP maths to `BnCtx`**

In `src/auth/srp_utils.cpp`, rewrite `calculate_verifier`, `calculate_B`, `calculate_S_client`, and
`calculate_S_server` to declare `BnCtx ctx;` once at the top and drop every `BN_CTX_free` call. Each
`if (!BN_...) { BN_CTX_free(ctx); throw ...; }` collapses to `if (!BN_...) throw ...;`. For example
`calculate_verifier` becomes:

```cpp
    SRPUtils::BigNum SRPUtils::calculate_verifier(
        const BigNum& g,
        const BigNum& x,
        const BigNum& N)
    {
        // v = g^x mod N
        BnCtx ctx;
        BigNum v;
        if (!BN_mod_exp(v.get(), g.get(), x.get(), N.get(), ctx.get()))
            throw std::runtime_error("Failed to calculate verifier");

        return v;
    }
```

Apply the same transformation to the other three, preserving each existing error message verbatim.
Do the same in `src/auth/srp_client.cpp::generate_A`, which has its own manual `BN_CTX`.

- [ ] **Step 5: Add the session fields**

In `include/chat/auth/srp_types.hpp`, add `#include <chrono>` and extend `SRPSession`:

```cpp
    struct SRPSession
    {
        std::string user_id;
        std::string username;          // recorded at init; never re-derived from the salt
        std::vector<uint8_t> A;        // client's public ephemeral key
        std::vector<uint8_t> b;        // server's private ephemeral key
        std::vector<uint8_t> B;        // server's public ephemeral key
        std::vector<uint8_t> salt;     // user's salt
        std::vector<uint8_t> verifier; // user's verifier (v = g^x)
        std::vector<uint8_t> K;        // shared session secret
        std::chrono::steady_clock::time_point created_at{std::chrono::steady_clock::now()};
        bool authenticated{false};
    };
```

- [ ] **Step 6: Harden `SRPServer`**

In `src/auth/srp_server.cpp::init_authentication`, after fetching the credentials and before
building the session, add the `A` check; record the username; and return the local `B`:

```cpp
        // SRP-6a: A ≡ 0 (mod N) would force S = 0. Refuse it.
        const SRPUtils::BigNum A_bn(A);
        if (SRPUtils::is_zero_mod(A_bn, *N_))
            throw std::runtime_error("Invalid client ephemeral A");

        SRPSession session;
        session.user_id  = generate_user_id();
        session.username = username;
        session.A        = A;
        session.salt     = creds.salt;
        session.verifier = creds.verifier;
```

and the return statement becomes, with `auto B_bytes = B.to_bytes();` captured before the session is
moved into the map:

```cpp
        auto B_bytes    = B.to_bytes();
        session.B       = B_bytes;
        std::string user_id = session.user_id;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            sessions_[session.user_id] = std::move(session);
        }

        return ChallengeResponse{
            .user_id = user_id,
            .B = std::move(B_bytes),
            .salt = creds.salt,
            .room_salt = room_salt_
        };
```

This removes the unsynchronized `sessions_[user_id].B` read at the old line 142.

In `verify_authentication`, add the `u` check after computing `u`, replace the username scan with
`session.username`, and replace the XOR loop:

```cpp
        auto u = SRPUtils::calculate_u(A, B);
        if (BN_is_zero(u.get()) == 1)
            throw std::runtime_error("Invalid u parameter");
```

```cpp
        auto expected_M = SRPUtils::calculate_M(
            *N_, *g_, session.username, session.salt, A, B, K);

        if (!SRPUtils::constant_time_equals(M, expected_M))
            throw std::runtime_error("Authentication failed");
```

Delete the whole `std::string username; { lock; for (...) if (creds.salt == session.salt) ... }`
block and the manual `diff` loop.

Replace `generate_user_id`:

```cpp
    std::string SRPServer::generate_user_id() const
    {
        return "user_" + SRPUtils::random_hex_id(16);
    }
```

and delete the now-unused `#include <random>`.

Implement the sweep:

```cpp
    void SRPServer::clear_expired_sessions(const int timeout_seconds)
    {
        const auto cutoff = std::chrono::steady_clock::now()
                          - std::chrono::seconds(timeout_seconds);

        std::lock_guard<std::mutex> lock(sessions_mutex_);
        std::erase_if(sessions_, [cutoff](const auto& entry) {
            return entry.second.created_at <= cutoff;
        });
    }
```

Add `#include <chrono>` and `#include <algorithm>`.

- [ ] **Step 7: Harden `SRPClient`**

In `src/auth/srp_client.cpp::process_challenge`, immediately after constructing `B_`:

```cpp
        // SRP-6a: B ≡ 0 (mod N) would force a degenerate shared secret.
        if (SRPUtils::is_zero_mod(*B_, *N_))
            throw std::runtime_error("Invalid server ephemeral B");
```

and after computing `u`:

```cpp
        auto u = SRPUtils::calculate_u(*A_, *B_);
        if (BN_is_zero(u.get()) == 1)
            throw std::runtime_error("Invalid u parameter");
```

Replace the XOR loop in `verify_server`:

```cpp
        auto expected_H_AMK = SRPUtils::calculate_H_AMK(*A_, M_, K_);
        authenticated_      = SRPUtils::constant_time_equals(H_AMK, expected_H_AMK);
        return authenticated_;
```

- [ ] **Step 8: Run the tests**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: all `SrpTest` cases pass, including the six added in Step 1.

- [ ] **Step 9: Prove the checks are load-bearing**

Temporarily comment out the `is_zero_mod` guard in `init_authentication`, rebuild, and run
`ctest --preset debug -R SrpTest.ServerRejectsZeroA`.
Expected: FAIL. Restore the guard and confirm it passes again. This confirms the test would catch a
regression rather than passing vacuously.

- [ ] **Step 10: Commit**

```bash
git add include/chat/auth src/auth tests/srp_tests.cpp
git commit -m "fix(auth): add srp-6a safety checks and constant-time comparison"
```

---

## Task 5: Extract `UserStore` with atomic writes

**Files:**
- Create: `include/chat/auth/user_store.hpp`, `src/auth/user_store.cpp`, `tests/user_store_tests.cpp`
- Modify: `include/chat/auth/srp_server.hpp`, `src/auth/srp_server.cpp:26-96`, `src/server/server.cpp:19-41,186-208`, `CMakeLists.txt`

**Interfaces:**
- Consumes: `chat::auth::UserCredentials`, `SRPUtils::bytes_to_hex` / `hex_to_bytes`.
- Produces:
  - `class chat::auth::UserStore` with `explicit UserStore(std::string path = "")`, `void load()`, `void save() const`, `bool insert(const UserCredentials&)`, `bool contains(const std::string&) const`, `std::optional<UserCredentials> find(const std::string&) const`, `size_t size() const`, and `static bool is_valid_username(const std::string&)`.
  - An empty path means in-memory only: `load()` and `save()` are no-ops. This keeps `SRPServer`'s default constructor usable from tests.
  - `SRPServer` constructors become `SRPServer()`, `explicit SRPServer(std::string users_path)`, and `SRPServer(std::string users_path, std::vector<uint8_t> room_salt)`. `load_users(path)` / `save_users(path)` are replaced by `load()` / `save()`.

- [ ] **Step 1: Write the failing test file `tests/user_store_tests.cpp`**

```cpp
#include "chat/auth/user_store.hpp"
#include "chat/auth/srp_utils.hpp"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

namespace chat::auth
{
    class UserStoreTest : public ::testing::Test
    {
    protected:
        std::filesystem::path path_;

        void SetUp() override
        {
            path_ = std::filesystem::temp_directory_path()
                  / ("user_store_test_" + SRPUtils::random_hex_id(8) + ".db");
        }

        void TearDown() override
        {
            std::error_code ec;
            std::filesystem::remove(path_, ec);
            std::filesystem::remove(path_.string() + ".tmp", ec);
        }

        static UserCredentials make_creds(const std::string& username)
        {
            return UserCredentials{
                .username = username,
                .salt = SRPUtils::random_bytes(SRP_SALT_SIZE),
                .verifier = SRPUtils::random_bytes(64)
            };
        }
    };

    TEST_F(UserStoreTest, RoundTripsThroughDisk)
    {
        const auto creds = make_creds("alice");
        {
            UserStore store(path_.string());
            EXPECT_TRUE(store.insert(creds));
            store.save();
        }

        UserStore reloaded(path_.string());
        reloaded.load();

        ASSERT_TRUE(reloaded.contains("alice"));
        const auto found = reloaded.find("alice");
        ASSERT_TRUE(found.has_value());
        EXPECT_EQ(found->salt, creds.salt);
        EXPECT_EQ(found->verifier, creds.verifier);
    }

    TEST_F(UserStoreTest, DuplicateInsertIsRefused)
    {
        UserStore store(path_.string());
        EXPECT_TRUE(store.insert(make_creds("bob")));
        EXPECT_FALSE(store.insert(make_creds("bob")));
        EXPECT_EQ(store.size(), 1u);
    }

    TEST_F(UserStoreTest, MalformedLinesAreSkipped)
    {
        {
            std::ofstream file(path_);
            file << "# SRP User Database\n";
            file << "this-line-has-no-colons\n";
            file << "onlyone:field\n";
            file << "\n";
            file << "carol:00112233:aabbcc\n";
        }

        UserStore store(path_.string());
        store.load();

        EXPECT_EQ(store.size(), 1u);
        EXPECT_TRUE(store.contains("carol"));
    }

    TEST_F(UserStoreTest, SaveLeavesNoTemporaryFileBehind)
    {
        UserStore store(path_.string());
        store.insert(make_creds("dave"));
        store.save();

        EXPECT_TRUE(std::filesystem::exists(path_));
        EXPECT_FALSE(std::filesystem::exists(path_.string() + ".tmp"));
    }

    TEST_F(UserStoreTest, RejectsUsernamesThatWouldCorruptTheFormat)
    {
        EXPECT_FALSE(UserStore::is_valid_username("has:colon"));
        EXPECT_FALSE(UserStore::is_valid_username("has\nnewline"));
        EXPECT_FALSE(UserStore::is_valid_username(""));
        EXPECT_FALSE(UserStore::is_valid_username(std::string(33, 'a')));
        EXPECT_FALSE(UserStore::is_valid_username("has space"));

        EXPECT_TRUE(UserStore::is_valid_username("alice"));
        EXPECT_TRUE(UserStore::is_valid_username("a_b-c9"));
        EXPECT_TRUE(UserStore::is_valid_username(std::string(32, 'a')));
    }

    TEST_F(UserStoreTest, InsertRejectsInvalidUsername)
    {
        UserStore store(path_.string());
        auto creds = make_creds("bad:name");
        EXPECT_FALSE(store.insert(creds));
        EXPECT_EQ(store.size(), 0u);
    }

    TEST_F(UserStoreTest, EmptyPathMeansInMemoryOnly)
    {
        UserStore store;
        EXPECT_TRUE(store.insert(make_creds("erin")));
        EXPECT_NO_THROW(store.save());
        EXPECT_NO_THROW(store.load());
        EXPECT_TRUE(store.contains("erin")); // load() must not wipe an in-memory store
    }
} // namespace chat::auth
```

- [ ] **Step 2: Register the target in `CMakeLists.txt`**

Add `src/auth/user_store.cpp` to the `chat_auth` source list, then:

```cmake
    add_executable(user_store_tests
            tests/user_store_tests.cpp
    )
    target_link_libraries(user_store_tests
            PRIVATE
            chat_auth
            GTest::gtest_main
    )
```

plus `gtest_discover_tests(user_store_tests)`.

- [ ] **Step 3: Run the build to verify it fails**

Run: `cmake --build --preset debug 2>&1 | tail -20`
Expected: `chat/auth/user_store.hpp: No such file or directory`.

- [ ] **Step 4: Write `include/chat/auth/user_store.hpp`**

```cpp
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
```

- [ ] **Step 5: Write `src/auth/user_store.cpp`**

```cpp
#include "chat/auth/user_store.hpp"

#include <algorithm>
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
```

Add `#include <cctype>` for `std::isalnum`.

- [ ] **Step 6: Delegate from `SRPServer`**

In `include/chat/auth/srp_server.hpp`: add `#include "chat/auth/user_store.hpp"`, replace the
`users_` map and `users_mutex_` members with `UserStore users_;`, and replace the constructors and
the two persistence methods:

```cpp
        SRPServer();
        explicit SRPServer(std::string users_path);
        SRPServer(std::string users_path, std::vector<uint8_t> room_salt);
        ~SRPServer();

        bool register_user(const std::string& username, const UserCredentials& creds);
        bool user_exists(const std::string& username);
        void remove_user(const std::string& username) = delete;

        void load();
        void save() const;
```

`remove_user` has no caller anywhere in the tree (`grep -rn remove_user src/ tests/` confirms), so
delete its declaration and definition outright rather than porting it.

In `src/auth/srp_server.cpp`:

```cpp
    SRPServer::SRPServer()
        : SRPServer("", SRPUtils::random_bytes(SRP_SALT_SIZE))
    {
    }

    SRPServer::SRPServer(std::string users_path)
        : SRPServer(std::move(users_path), SRPUtils::random_bytes(SRP_SALT_SIZE))
    {
    }

    SRPServer::SRPServer(std::string users_path, std::vector<uint8_t> room_salt)
        : users_(std::move(users_path))
          , room_salt_(std::move(room_salt))
    {
        N_ = std::make_unique<SRPUtils::BigNum>(SRP_N_HEX_2048);
        g_ = std::make_unique<SRPUtils::BigNum>(SRP_G_HEX);
        k_ = std::make_unique<SRPUtils::BigNum>(SRPUtils::calculate_k(*N_, *g_));
    }

    bool SRPServer::register_user(const std::string& username, const UserCredentials& creds)
    {
        if (creds.username != username)
            return false;
        return users_.insert(creds);
    }

    bool SRPServer::user_exists(const std::string& username)
    {
        return users_.contains(username);
    }

    void SRPServer::load() { users_.load(); }
    void SRPServer::save() const { users_.save(); }
```

Delete `load_users`, `save_users`, and the old `register_user` / `user_exists` bodies. In
`init_authentication`, replace the locked map lookup with:

```cpp
        const auto found = users_.find(username);
        if (!found.has_value())
            throw std::runtime_error("User not found");
        const UserCredentials creds = *found;
```

Note the member initialiser order: declare `users_` before `room_salt_` in the header so the
initialiser list matches and `-Wall` stays quiet.

- [ ] **Step 7: Update the two call sites in `src/server/server.cpp`**

The constructor at line 27 becomes `std::make_unique<auth::SRPServer>("users.db")` and the
`load_users("users.db")` call at line 33 becomes `srp_server_->load()`. The destructor's
`save_users("users.db")` at line 39 becomes `srp_server_->save()`. The immediate save after
registration at line 204 becomes `srp_server_->save()`. Task 11 replaces the hard-coded path with
the `--users-db` flag.

- [ ] **Step 8: Run the tests**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: all eight `UserStoreTest` cases pass; `SrpTest` stays green (it uses the in-memory default
constructor).

- [ ] **Step 9: Commit**

```bash
git add include/chat/auth src/auth src/server/server.cpp tests/user_store_tests.cpp CMakeLists.txt
git commit -m "refactor(auth): extract user store with atomic writes"
```

---

## Task 6: Remove the username enumeration oracle

**Files:**
- Modify: `include/chat/auth/srp_utils.hpp`, `src/auth/srp_utils.cpp`, `include/chat/auth/srp_server.hpp`, `src/auth/srp_server.cpp`, `include/chat/common/types.hpp:36`, `src/server/server.cpp:49-82`, `src/client/client.cpp:298-329`, `tests/srp_tests.cpp`

**Interfaces:**
- Consumes: Task 5's `UserStore`.
- Produces:
  - `SRPUtils::hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) -> std::vector<uint8_t>`.
  - `MessageType::SRP_USER_NOT_FOUND` is deleted. Because the enum is unnumbered, removing a member shifts every later value — acceptable, since Task 2's version gate already makes this a breaking change and both peers are rebuilt together.
  - `SRPServer::init_authentication` no longer throws for an unknown user; it returns a challenge derived from a per-process secret. Only `verify_authentication` fails.
  - The client's implicit "register? (y/n)" prompt is gone; registration happens only when the caller invokes `srp_register()` first. Task 11 wires that to `--register`.

- [ ] **Step 1: Add the failing tests to `tests/srp_tests.cpp`**

```cpp
    TEST(SrpTest, UnknownUserStillGetsAWellFormedChallenge)
    {
        auto server = make_server_with_user("known", "pw");

        SRPClient client("ghost", "any-password");
        const auto A = client.generate_A();

        // No throw, and the challenge is indistinguishable in shape from a real one.
        SRPServer::ChallengeResponse challenge;
        ASSERT_NO_THROW(challenge = server.init_authentication("ghost", A));

        EXPECT_FALSE(challenge.user_id.empty());
        EXPECT_FALSE(challenge.B.empty());
        EXPECT_EQ(challenge.salt.size(), SRP_SALT_SIZE);

        // It fails at proof verification, exactly like a wrong password does.
        const auto M = client.process_challenge(challenge.B, challenge.salt);
        EXPECT_THROW((void)server.verify_authentication(challenge.user_id, M), std::runtime_error);
    }

    TEST(SrpTest, FakeSaltIsStableAcrossProbes)
    {
        SRPServer server;
        SRPClient probe_one("ghost", "pw");
        SRPClient probe_two("ghost", "pw");

        const auto first  = server.init_authentication("ghost", probe_one.generate_A());
        const auto second = server.init_authentication("ghost", probe_two.generate_A());

        // A real account returns the same salt every time; the decoy must too,
        // or repeated probing distinguishes it.
        EXPECT_EQ(first.salt, second.salt);
    }

    TEST(SrpTest, FakeSaltDiffersBetweenUsernames)
    {
        SRPServer server;
        SRPClient a("ghost-a", "pw");
        SRPClient b("ghost-b", "pw");

        EXPECT_NE(server.init_authentication("ghost-a", a.generate_A()).salt,
                  server.init_authentication("ghost-b", b.generate_A()).salt);
    }

    TEST(SrpTest, HmacIsDeterministicAndKeyDependent)
    {
        const std::vector<uint8_t> key_one(32, 0x01);
        const std::vector<uint8_t> key_two(32, 0x02);
        const std::vector<uint8_t> data{'h', 'i'};

        EXPECT_EQ(SRPUtils::hmac_sha256(key_one, data), SRPUtils::hmac_sha256(key_one, data));
        EXPECT_NE(SRPUtils::hmac_sha256(key_one, data), SRPUtils::hmac_sha256(key_two, data));
        EXPECT_EQ(SRPUtils::hmac_sha256(key_one, data).size(), 32u);
    }
```

- [ ] **Step 2: Run the build to verify it fails**

Run: `cmake --build --preset debug 2>&1 | tail -20`
Expected: `hmac_sha256` is not a member of `SRPUtils`; and once that compiles,
`UnknownUserStillGetsAWellFormedChallenge` fails because `init_authentication` throws
`"User not found"`.

- [ ] **Step 3: Add `hmac_sha256`**

Declare in `include/chat/auth/srp_utils.hpp` beside the other hash functions:

```cpp
        // HMAC-SHA256, used to derive decoy credentials for unknown usernames.
        static std::vector<uint8_t> hmac_sha256(
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& data);
```

Implement in `src/auth/srp_utils.cpp` with `#include <openssl/hmac.h>`:

```cpp
    std::vector<uint8_t> SRPUtils::hmac_sha256(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data)
    {
        std::vector<uint8_t> mac(SHA256_DIGEST_LENGTH);
        unsigned int mac_len = 0;

        if (!HMAC(EVP_sha256(),
                  key.data(), static_cast<int>(key.size()),
                  data.data(), data.size(),
                  mac.data(), &mac_len))
            throw std::runtime_error("HMAC-SHA256 failed");

        mac.resize(mac_len);
        return mac;
    }
```

- [ ] **Step 4: Give `SRPServer` a per-process secret and decoy credentials**

In `include/chat/auth/srp_server.hpp`, add the member and the private helper:

```cpp
        // Random per process, never persisted, never transmitted. Makes decoy
        // credentials for unknown usernames deterministic without being guessable.
        std::vector<uint8_t> server_secret_;
```

```cpp
        [[nodiscard]] UserCredentials decoy_credentials(const std::string& username) const;
```

In `src/auth/srp_server.cpp`, initialise `server_secret_(SRPUtils::random_bytes(32))` in the
delegating constructor's member list (declared after `room_salt_`), and add:

```cpp
    UserCredentials SRPServer::decoy_credentials(const std::string& username) const
    {
        const std::vector<uint8_t> username_bytes(username.begin(), username.end());

        auto salt_seed = std::vector<uint8_t>{'s', 'a', 'l', 't', ':'};
        salt_seed.insert(salt_seed.end(), username_bytes.begin(), username_bytes.end());
        auto salt = SRPUtils::hmac_sha256(server_secret_, salt_seed);
        salt.resize(SRP_SALT_SIZE);

        auto verifier_seed = std::vector<uint8_t>{'v', 'e', 'r', 'i', 'f', 'i', 'e', 'r', ':'};
        verifier_seed.insert(verifier_seed.end(), username_bytes.begin(), username_bytes.end());
        const auto verifier_hash = SRPUtils::hmac_sha256(server_secret_, verifier_seed);

        // Reduce mod N so the value is a legal group element. The client cannot
        // produce a matching proof without the corresponding password, so the
        // handshake fails at M verification just as a wrong password would.
        const SRPUtils::BigNum raw(verifier_hash);
        SRPUtils::BnCtx ctx;
        SRPUtils::BigNum verifier;
        if (!BN_mod(verifier.get(), raw.get(), N_->get(), ctx.get()))
            throw std::runtime_error("Failed to derive decoy verifier");

        return UserCredentials{
            .username = username,
            .salt = std::move(salt),
            .verifier = verifier.to_bytes()
        };
    }
```

In `init_authentication`, replace the throw with a fall back to the decoy:

```cpp
        const auto found = users_.find(username);
        const UserCredentials creds = found.has_value() ? *found : decoy_credentials(username);
```

Everything downstream is unchanged: the session is built, `B` is computed, and `verify_authentication`
rejects the proof.

- [ ] **Step 5: Delete `SRP_USER_NOT_FOUND`**

Remove the enumerator from `include/chat/common/types.hpp:36`, including its trailing comment.

- [ ] **Step 6: Simplify the server handshake loop**

In `src/server/server.cpp`, the `while (true)` loop at lines 49–82 exists only to retry after a
`SRP_USER_NOT_FOUND` round trip. Collapse it: read one packet; if it is `SRP_REGISTER`, handle it
and read one more; otherwise it must be `SRP_INIT`. Replace lines 46–82 with:

```cpp
            auth::SRPServer::ChallengeResponse challenge;
            std::string username;

            auto [type, msg] = conn->receive_packet();
            if (type == MessageType::SRP_REGISTER) {
                handle_srp_register(conn, msg);
                std::tie(type, msg) = conn->receive_packet();
            }

            if (type != MessageType::SRP_INIT) {
                conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Expected SRP_INIT"}));
                return std::nullopt;
            }

            auto init = Protocol::decode<SrpInitMsg>(msg);
            if (init.protocol_version != kProtocolVersion) {
                conn->send_packet(Protocol::encode(
                    MessageType::ERROR_MSG,
                    ErrorMsg{"Unsupported protocol version " + std::to_string(init.protocol_version)
                             + "; server speaks version " + std::to_string(kProtocolVersion)}));
                return std::nullopt;
            }

            if (init.username.empty() || init.A_b64.empty()) {
                conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Invalid SRP_INIT"}));
                return std::nullopt;
            }

            challenge = srp_server_->init_authentication(
                init.username, auth::SRPUtils::base64_to_bytes(init.A_b64));
            username = init.username;
```

`std::tie` needs `#include <tuple>`, and `type`/`msg` must be declared as named variables rather
than a structured binding for `std::tie` to assign to them:

```cpp
            auto first_packet = conn->receive_packet();
            MessageType type = first_packet.first;
            std::vector<uint8_t> msg = std::move(first_packet.second);
```

- [ ] **Step 7: Remove the client's mid-handshake registration prompt**

In `src/client/client.cpp::srp_authenticate`, delete the whole `if (type == MessageType::SRP_USER_NOT_FOUND) { ... }`
block (lines 298–329), including the retry send and the `"Authentication cancelled"` throw. What
remains after receiving the response to `SRP_INIT` is the existing `ERROR_MSG` check followed by the
`SRP_CHALLENGE` check.

Change `run()` so registration is an explicit, up-front step. Add a `bool register_first_` member to
`include/chat/client/client.hpp`, set from a new constructor parameter, and in `run()`:

```cpp
            if (register_first_)
                srp_register();

            srp_authenticate();
```

The constructor becomes `Client(std::string host, int port, std::string username, bool register_first)`.
`srp_register()` must connect the socket before sending, so move the resolve/connect pair out of
`srp_authenticate()` into a small private `connect()` helper called at the top of `run()`:

```cpp
    void Client::connect()
    {
        boost::asio::ip::tcp::resolver resolver(io_context_);
        auto endpoints = resolver.resolve(host_, std::to_string(port_));
        boost::asio::connect(socket_, endpoints);
    }
```

Update `src/client/main.cpp` to pass `false` for now; Task 11 replaces the whole argument-parsing
block with flags and wires `--register` through.

- [ ] **Step 8: Run the tests**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: the four new `SrpTest` cases pass and every other suite stays green.

- [ ] **Step 9: Manual end-to-end check**

Run the server and two clients by hand to confirm the flow still works:

```bash
./build/debug/chat_server 8888 &
./build/debug/chat_client localhost 8888 alice
```
Expected: authentication fails cleanly for an unregistered `alice` with a generic failure, not a
"user not found" message. There is no registration path from the CLI until Task 11 — that is
expected at this point, and the `SrpTest` suite is what proves registration still works.

Kill the server with `kill %1` when done.

- [ ] **Step 10: Commit**

```bash
git add include src tests/srp_tests.cpp
git commit -m "fix(auth): remove username enumeration oracle"
```

---

## Task 7: `Room` — membership, per-user keys, encrypted history

`Room` replaces `ConnectionManager` and takes over the message history that `Server` currently owns.
It talks to connections through a `Sink` interface, so it is fully unit-testable without sockets.
This task also fixes the plaintext history leak and the dropped timestamp.

**Files:**
- Create: `include/chat/server/sink.hpp`, `include/chat/server/room.hpp`, `src/server/room.cpp`, `tests/room_tests.cpp`
- Delete: `tests/connection_manager_tests.cpp`
- Modify: `include/chat/common/messages.hpp`, `CMakeLists.txt`

`connection_manager.{hpp,cpp}` stay on disk until Task 8 deletes them, so `chat_server` keeps
building in between.

**Interfaces:**
- Consumes: `AESEngine::encrypt_string`, `SRPUtils::bytes_to_base64`, `Protocol::encode`.
- Produces:
  - `struct chat::HistoryEntry { std::string username; std::string ciphertext_b64; int64_t timestamp_ms; }` with both `as_tuple()` overloads.
  - `InitMsg` becomes `{ std::vector<HistoryEntry> messages; std::vector<User> users; }`.
  - `class chat::server::Sink` — pure virtual `void send(std::vector<uint8_t> packet)` and `void close()`.
  - `class chat::server::Room` with `join`, `leave`, `username_online`, `username_of`, `active_users`, `record_and_broadcast`, `broadcast_packet`, `init_packet_for`, `size`.

- [ ] **Step 1: Write the failing test file `tests/room_tests.cpp`**

```cpp
#include "chat/server/room.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"
#include "chat/crypto/aes_engine.hpp"
#include "chat/auth/srp_utils.hpp"

#include <gtest/gtest.h>
#include <memory>

namespace chat::server
{
    namespace
    {
        // Captures packets instead of writing them to a socket.
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

        MessageType type_of(const std::vector<uint8_t>& packet)
        {
            std::array<uint8_t, MsgHeader::kWireSize> raw{};
            std::copy_n(packet.begin(), MsgHeader::kWireSize, raw.begin());
            return static_cast<MessageType>(decode_header(raw).type);
        }

        std::vector<uint8_t> payload_of(const std::vector<uint8_t>& packet)
        {
            return std::vector<uint8_t>(packet.begin() + MsgHeader::kWireSize, packet.end());
        }
    }

    class RoomTest : public ::testing::Test
    {
    protected:
        Room room_;
        std::shared_ptr<RecordingSink> alice_ = std::make_shared<RecordingSink>();
        std::shared_ptr<RecordingSink> bob_   = std::make_shared<RecordingSink>();

        void join_both()
        {
            room_.join("user_a", "alice", alice_, test_key(0xAA));
            room_.join("user_b", "bob", bob_, test_key(0xBB));
        }
    };

    TEST_F(RoomTest, TracksMembership)
    {
        join_both();

        EXPECT_EQ(room_.size(), 2u);
        EXPECT_TRUE(room_.username_online("alice"));
        EXPECT_FALSE(room_.username_online("carol"));
        EXPECT_EQ(room_.username_of("user_b"), "bob");
        EXPECT_EQ(room_.username_of("nobody"), "");
        EXPECT_EQ(room_.active_users().size(), 2u);
    }

    TEST_F(RoomTest, LeaveRemovesAndCloses)
    {
        join_both();
        room_.leave("user_a");

        EXPECT_EQ(room_.size(), 1u);
        EXPECT_FALSE(room_.username_online("alice"));
        EXPECT_TRUE(alice_->closed);
    }

    TEST_F(RoomTest, BroadcastPacketExcludesTheNamedUser)
    {
        join_both();
        room_.broadcast_packet(Protocol::encode(MessageType::USER_LEFT, UserLeftMsg{"carol"}), "user_a");

        EXPECT_TRUE(alice_->packets.empty());
        ASSERT_EQ(bob_->packets.size(), 1u);
        EXPECT_EQ(type_of(bob_->packets[0]), MessageType::USER_LEFT);
    }

    TEST_F(RoomTest, EachRecipientGetsTheMessageUnderTheirOwnKey)
    {
        join_both();
        room_.record_and_broadcast("alice", "hello everyone");

        ASSERT_EQ(alice_->packets.size(), 1u);
        ASSERT_EQ(bob_->packets.size(), 1u);

        const auto for_alice = Protocol::decode<BroadcastMsg>(payload_of(alice_->packets[0]));
        const auto for_bob   = Protocol::decode<BroadcastMsg>(payload_of(bob_->packets[0]));

        EXPECT_EQ(for_alice.username, "alice");
        EXPECT_GT(for_alice.timestamp_ms, 0);

        // Same plaintext, different keys, therefore different ciphertext.
        EXPECT_NE(for_alice.ciphertext_b64, for_bob.ciphertext_b64);

        EXPECT_EQ(crypto::AESEngine::decrypt_string(
                      auth::SRPUtils::base64_to_bytes(for_alice.ciphertext_b64), test_key(0xAA)),
                  "hello everyone");
        EXPECT_EQ(crypto::AESEngine::decrypt_string(
                      auth::SRPUtils::base64_to_bytes(for_bob.ciphertext_b64), test_key(0xBB)),
                  "hello everyone");
    }

    TEST_F(RoomTest, HistoryIsEncryptedForTheJoiningUserAndKeepsTimestamps)
    {
        room_.join("user_a", "alice", alice_, test_key(0xAA));
        room_.record_and_broadcast("alice", "first");
        room_.record_and_broadcast("alice", "second");

        room_.join("user_b", "bob", bob_, test_key(0xBB));
        const auto init = Protocol::decode<InitMsg>(payload_of(room_.init_packet_for("user_b")));

        ASSERT_EQ(init.messages.size(), 2u);
        EXPECT_EQ(init.messages[0].username, "alice");
        EXPECT_GT(init.messages[0].timestamp_ms, 0);
        EXPECT_LE(init.messages[0].timestamp_ms, init.messages[1].timestamp_ms);

        // Decryptable only with bob's key — the history is not plaintext.
        EXPECT_EQ(crypto::AESEngine::decrypt_string(
                      auth::SRPUtils::base64_to_bytes(init.messages[0].ciphertext_b64), test_key(0xBB)),
                  "first");
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(
                         auth::SRPUtils::base64_to_bytes(init.messages[0].ciphertext_b64), test_key(0xAA)),
                     std::runtime_error);
    }

    TEST_F(RoomTest, HistoryIsCappedAtOneHundredMessages)
    {
        room_.join("user_a", "alice", alice_, test_key(0xAA));
        for (int i = 0; i < 150; ++i)
            room_.record_and_broadcast("alice", "msg " + std::to_string(i));

        room_.join("user_b", "bob", bob_, test_key(0xBB));
        const auto init = Protocol::decode<InitMsg>(payload_of(room_.init_packet_for("user_b")));

        EXPECT_EQ(init.messages.size(), 100u);
        EXPECT_EQ(crypto::AESEngine::decrypt_string(
                      auth::SRPUtils::base64_to_bytes(init.messages[0].ciphertext_b64), test_key(0xBB)),
                  "msg 50"); // oldest 50 dropped
    }

    TEST_F(RoomTest, InitPacketForUnknownUserIsEmpty)
    {
        join_both();
        const auto init = Protocol::decode<InitMsg>(payload_of(room_.init_packet_for("nobody")));
        EXPECT_TRUE(init.messages.empty());
    }
} // namespace chat::server
```

- [ ] **Step 2: Wire up CMake and delete the old test**

```bash
git rm tests/connection_manager_tests.cpp
```

In `CMakeLists.txt`, delete the `connection_manager_tests` executable block and its
`gtest_discover_tests` line, then add:

```cmake
    add_executable(room_tests
            tests/room_tests.cpp
            src/server/room.cpp
    )
    target_link_libraries(room_tests
            PRIVATE
            chat_common
            chat_auth
            chat_crypto
            Boost::system
            Threads::Threads
            GTest::gtest_main
    )
```

plus `gtest_discover_tests(room_tests)`, and add `src/server/room.cpp` to the `chat_server`
source list.

- [ ] **Step 3: Run the build to verify it fails**

Run: `cmake --build --preset debug 2>&1 | tail -20`
Expected: `chat/server/room.hpp: No such file or directory`.

- [ ] **Step 4: Add `HistoryEntry` and change `InitMsg`**

In `include/chat/common/messages.hpp`, add `#include <cstdint>` if not already present from Task 2,
then insert above `InitMsg` and replace `InitMsg`:

```cpp
    struct HistoryEntry
    {
        std::string username;
        // Base64-encoded AES-GCM payload (IV || ciphertext || tag), sealed with
        // the receiving user's key. History is never sent in the clear.
        std::string ciphertext_b64;
        int64_t timestamp_ms;

        [[nodiscard]] auto as_tuple() const { return std::tie(username, ciphertext_b64, timestamp_ms); }
        [[nodiscard]] auto as_tuple() { return std::tie(username, ciphertext_b64, timestamp_ms); }
    };

    struct InitMsg
    {
        std::vector<HistoryEntry> messages;
        std::vector<User> users;

        [[nodiscard]] auto as_tuple() const { return std::tie(messages, users); }
        [[nodiscard]] auto as_tuple() { return std::tie(messages, users); }
    };
```

Also delete `struct ConnectMsg` and `struct ConnectAckMsg` (lines 10–24). `grep -rn "ConnectMsg\|ConnectAckMsg" src/ tests/`
returns nothing — they are leftovers from the pre-SRP protocol.

- [ ] **Step 5: Write `include/chat/server/sink.hpp`**

```cpp
#pragma once

#include <cstdint>
#include <vector>

namespace chat::server
{
    /**
     * Somewhere a packet can be delivered. Session implements it over a socket;
     * tests implement it over a vector. Room depends only on this, which is why
     * Room needs no io_context to be tested.
     */
    class Sink
    {
    public:
        virtual ~Sink() = default;

        // Must not block: implementations enqueue and return.
        virtual void send(std::vector<uint8_t> packet) = 0;
        virtual void close()                           = 0;
    };
} // namespace chat::server
```

- [ ] **Step 6: Write `include/chat/server/room.hpp`**

```cpp
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
```

- [ ] **Step 7: Write `src/server/room.cpp`**

```cpp
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
```

`kMaxHistory` is 100 and `kMaxVectorCount` is 1024, so a full history always fits inside the
decoder's element limit.

- [ ] **Step 8: Write `include/chat/common/log.hpp`**

`Room` uses it, so it lands here. Header-only, no dependency.

```cpp
#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace chat::log
{
    namespace detail
    {
        inline std::mutex& mutex()
        {
            static std::mutex m;
            return m;
        }

        inline void write(const char* level, const std::string& message)
        {
            const auto now    = std::chrono::system_clock::now();
            const auto as_time = std::chrono::system_clock::to_time_t(now);

            std::tm utc{};
#ifdef _WIN32
            gmtime_s(&utc, &as_time);
#else
            gmtime_r(&as_time, &utc);
#endif

            std::ostringstream line;
            line << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ") << " [" << level << "] " << message;

            std::lock_guard<std::mutex> lock(mutex());
            std::cerr << line.str() << std::endl;
        }
    }

    inline void info(const std::string& message) { detail::write("info", message); }
    inline void warn(const std::string& message) { detail::write("warn", message); }
    inline void error(const std::string& message) { detail::write("error", message); }
} // namespace chat::log
```

`std::gmtime` in the existing code is not thread-safe; `gmtime_r` / `gmtime_s` is why this helper
exists rather than reusing the inline formatting scattered through `server.cpp` and `client.cpp`.

- [ ] **Step 9: Run the tests**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: all eight `RoomTest` cases pass. `chat_server` still builds against the old
`ConnectionManager`, which Task 8 removes.

- [ ] **Step 10: Commit**

```bash
git add include/chat/server include/chat/common src/server/room.cpp tests/room_tests.cpp CMakeLists.txt
git rm --cached tests/connection_manager_tests.cpp 2>/dev/null || true
git commit -m "feat(server): add room with encrypted message history"
```

---

## Task 8: Async coroutine sessions

**Files:**
- Create: `include/chat/server/session.hpp`, `src/server/session.cpp`
- Delete: `include/chat/server/connection_manager.hpp`, `src/server/connection_manager.cpp`
- Rewrite: `include/chat/server/server.hpp`, `src/server/server.cpp`, `src/server/main.cpp`
- Modify: `include/chat/common/protocol.hpp`, `CMakeLists.txt`

**Interfaces:**
- Consumes: `Room`, `Sink`, `SRPServer`, `log`.
- Produces:
  - `chat::ProtocolHelpers::async_send_packet(socket, packet) -> awaitable<void>` and `async_receive_packet(socket) -> awaitable<std::pair<MessageType, std::vector<uint8_t>>>`. The blocking `send_packet` / `receive_packet` free functions are deleted along with `make_empty_packet`, which has no callers.
  - `class chat::server::Session : public Sink, public std::enable_shared_from_this<Session>` with `explicit Session(boost::asio::ip::tcp::socket socket, Server& server)`, `void start()`, `void send(std::vector<uint8_t>) override`, `void close() override`.
  - `struct chat::server::ServerConfig` (fields listed in Step 4) and `class chat::server::Server` with `explicit Server(ServerConfig config)`, `void run()`, `void stop()`, plus the accessors `Session` needs: `Room& room()`, `auth::SRPServer& srp()`, `std::chrono::seconds handshake_timeout() const`, `std::chrono::seconds idle_timeout() const`, `void on_session_closed()`.

- [ ] **Step 1: Add the async packet helpers**

In `include/chat/common/protocol.hpp`, add the includes and replace the two blocking helpers:

```cpp
#include <boost/asio/awaitable.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
```

```cpp
        inline boost::asio::awaitable<void> async_send_packet(
            boost::asio::ip::tcp::socket& socket,
            const std::vector<uint8_t>& packet)
        {
            co_await boost::asio::async_write(
                socket, boost::asio::buffer(packet), boost::asio::use_awaitable);
        }

        inline boost::asio::awaitable<std::pair<MessageType, std::vector<uint8_t>>>
        async_receive_packet(boost::asio::ip::tcp::socket& socket)
        {
            std::array<uint8_t, MsgHeader::kWireSize> raw{};
            co_await boost::asio::async_read(
                socket, boost::asio::buffer(raw), boost::asio::use_awaitable);

            const auto header = decode_header(raw);
            if (header.size > kMaxPayloadSize)
                throw std::runtime_error("Incoming payload exceeds maximum allowed size");

            std::vector<uint8_t> payload(header.size);
            if (header.size > 0)
                co_await boost::asio::async_read(
                    socket, boost::asio::buffer(payload), boost::asio::use_awaitable);

            co_return std::pair{static_cast<MessageType>(header.type), std::move(payload)};
        }
```

Keep the blocking `send_packet` / `receive_packet` for now — Task 10 converts the client and deletes
them. Delete `make_empty_packet`'s declaration and its definition in `src/common/protocol.cpp`
(`grep -rn make_empty_packet src/ tests/` shows no callers); if that leaves `src/common/protocol.cpp`
empty, remove the file from the `chat_common` source list and `git rm` it.

- [ ] **Step 2: Write `include/chat/server/session.hpp`**

```cpp
#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "chat/common/types.hpp"
#include "chat/server/sink.hpp"

namespace chat::server
{
    class Server;

    /**
     * One client connection, driven by coroutines.
     *
     * Reads happen in run(); writes are queued and drained by a single writer
     * coroutine on the session's strand, so concurrent broadcasts never
     * interleave frames and never block the broadcaster.
     */
    class Session final : public Sink, public std::enable_shared_from_this<Session>
    {
    public:
        Session(boost::asio::ip::tcp::socket socket, Server& server);

        void start();

        void send(std::vector<uint8_t> packet) override;
        void close() override;

    private:
        boost::asio::awaitable<void> run();
        boost::asio::awaitable<void> writer();
        boost::asio::awaitable<void> watchdog();

        // Returns the authenticated user id, or nullopt if the handshake failed.
        boost::asio::awaitable<std::optional<std::string>> handshake();
        boost::asio::awaitable<void> message_loop(const std::string& user_id);
        boost::asio::awaitable<bool> handle_register(const std::vector<uint8_t>& payload);

        void fail(const std::string& client_message, const std::string& log_message);
        void extend_deadline();

        boost::asio::ip::tcp::socket socket_;
        boost::asio::strand<boost::asio::any_io_executor> strand_;
        Server& server_;

        std::deque<std::vector<uint8_t>> write_queue_;
        boost::asio::steady_timer write_signal_;

        boost::asio::steady_timer deadline_timer_;
        std::chrono::steady_clock::time_point deadline_;

        std::string username_;
        std::string remote_;
        int auth_attempts_ = 0;
    };
} // namespace chat::server
```

- [ ] **Step 3: Write `src/server/session.cpp`**

The write queue uses the standard Asio "timer as condition variable" idiom: the writer coroutine
waits on a timer set to `time_point::max()`, and `send()` cancels the timer to wake it.

```cpp
#include "chat/server/session.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "chat/auth/srp_utils.hpp"
#include "chat/auth/user_store.hpp"
#include "chat/common/log.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"
#include "chat/crypto/aes_engine.hpp"
#include "chat/server/server.hpp"

namespace chat::server
{
    using boost::asio::awaitable;
    using boost::asio::co_spawn;
    using boost::asio::detached;
    using boost::asio::use_awaitable;
    using namespace boost::asio::experimental::awaitable_operators;

    namespace
    {
        constexpr size_t kMaxMessageLength = 4096;
        constexpr int kMaxAuthAttempts     = 3;
    }

    Session::Session(boost::asio::ip::tcp::socket socket, Server& server)
        : socket_(std::move(socket))
          , strand_(boost::asio::make_strand(socket_.get_executor()))
          , server_(server)
          , write_signal_(socket_.get_executor(), std::chrono::steady_clock::time_point::max())
          , deadline_timer_(socket_.get_executor())
          , deadline_(std::chrono::steady_clock::now() + server.handshake_timeout())
    {
        boost::system::error_code ec;
        const auto endpoint = socket_.remote_endpoint(ec);
        remote_ = ec ? std::string("unknown") : endpoint.address().to_string();
    }

    void Session::start()
    {
        auto self = shared_from_this();
        co_spawn(strand_, [self] { return self->run(); }, detached);
        co_spawn(strand_, [self] { return self->writer(); }, detached);
        co_spawn(strand_, [self] { return self->watchdog(); }, detached);
    }

    void Session::send(std::vector<uint8_t> packet)
    {
        auto self = shared_from_this();
        boost::asio::post(strand_, [self, packet = std::move(packet)]() mutable {
            self->write_queue_.push_back(std::move(packet));
            self->write_signal_.cancel_one();
        });
    }

    void Session::close()
    {
        auto self = shared_from_this();
        boost::asio::post(strand_, [self] {
            boost::system::error_code ec;
            self->socket_.close(ec);
            self->write_signal_.cancel();
            self->deadline_timer_.cancel();
        });
    }

    void Session::extend_deadline()
    {
        deadline_ = std::chrono::steady_clock::now() + server_.idle_timeout();
    }

    void Session::fail(const std::string& client_message, const std::string& log_message)
    {
        // Clients get a fixed string; details never leave the server.
        send(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{client_message}));
        log::warn(remote_ + ": " + log_message);
    }

    awaitable<void> Session::writer()
    {
        while (socket_.is_open()) {
            if (write_queue_.empty()) {
                boost::system::error_code ec;
                co_await write_signal_.async_wait(
                    boost::asio::redirect_error(use_awaitable, ec));
                continue; // woken by send() or by close()
            }

            auto packet = std::move(write_queue_.front());
            write_queue_.pop_front();

            try {
                co_await ProtocolHelpers::async_send_packet(socket_, packet);
            }
            catch (const std::exception&) {
                close();
                co_return;
            }
        }
    }

    awaitable<void> Session::watchdog()
    {
        while (socket_.is_open()) {
            deadline_timer_.expires_at(deadline_);

            boost::system::error_code ec;
            co_await deadline_timer_.async_wait(boost::asio::redirect_error(use_awaitable, ec));

            if (!socket_.is_open())
                co_return;

            if (deadline_ <= std::chrono::steady_clock::now()) {
                log::info(remote_ + ": timed out");
                close();
                co_return;
            }
            // Deadline moved forward while we waited: loop and wait again.
        }
    }

    awaitable<void> Session::run()
    {
        auto self = shared_from_this();
        std::optional<std::string> user_id;

        try {
            user_id = co_await handshake();
        }
        catch (const std::exception& e) {
            log::warn(remote_ + ": handshake failed: " + e.what());
        }

        if (user_id.has_value()) {
            extend_deadline();
            try {
                co_await message_loop(*user_id);
            }
            catch (const std::exception& e) {
                log::info(remote_ + ": connection ended: " + e.what());
            }

            server_.room().leave(*user_id);
            server_.srp().clear_session(*user_id);
            server_.room().broadcast_packet(
                Protocol::encode(MessageType::USER_LEFT, UserLeftMsg{username_}));
            log::info("user '" + username_ + "' disconnected");
        }

        server_.on_session_closed();
        close();
    }

    awaitable<bool> Session::handle_register(const std::vector<uint8_t>& payload)
    {
        const auto msg = Protocol::decode<SrpRegisterMsg>(payload);

        if (!auth::UserStore::is_valid_username(msg.username)) {
            fail("Invalid username", "registration rejected: bad username");
            co_return false;
        }

        if (msg.salt_b64.empty() || msg.verifier_b64.empty()) {
            fail("Invalid registration data", "registration rejected: empty credential");
            co_return false;
        }

        if (server_.srp().user_exists(msg.username)) {
            fail("Username already exists", "registration rejected: duplicate");
            co_return false;
        }

        const auth::UserCredentials creds{
            .username = msg.username,
            .salt = auth::SRPUtils::base64_to_bytes(msg.salt_b64),
            .verifier = auth::SRPUtils::base64_to_bytes(msg.verifier_b64)
        };

        if (!server_.srp().register_user(msg.username, creds)) {
            fail("Registration failed", "registration rejected: store refused insert");
            co_return false;
        }

        log::info("user '" + msg.username + "' registered");
        server_.srp().save();
        send(Protocol::encode(MessageType::SRP_REGISTER_ACK));
        co_return true;
    }

    awaitable<std::optional<std::string>> Session::handshake()
    {
        auto [type, payload] = co_await ProtocolHelpers::async_receive_packet(socket_);

        if (type == MessageType::SRP_REGISTER) {
            if (!co_await handle_register(payload))
                co_return std::nullopt;

            std::tie(type, payload) = co_await ProtocolHelpers::async_receive_packet(socket_);
        }

        if (type != MessageType::SRP_INIT) {
            fail("Expected SRP_INIT", "handshake: wrong first message");
            co_return std::nullopt;
        }

        const auto init = Protocol::decode<SrpInitMsg>(payload);
        if (init.protocol_version != kProtocolVersion) {
            fail("Unsupported protocol version " + std::to_string(init.protocol_version)
                     + "; server speaks version " + std::to_string(kProtocolVersion),
                 "handshake: version mismatch");
            co_return std::nullopt;
        }

        if (!auth::UserStore::is_valid_username(init.username) || init.A_b64.empty()) {
            fail("Invalid SRP_INIT", "handshake: malformed init");
            co_return std::nullopt;
        }

        auth::SRPServer::ChallengeResponse challenge;
        try {
            challenge = server_.srp().init_authentication(
                init.username, auth::SRPUtils::base64_to_bytes(init.A_b64));
        }
        catch (const std::exception& e) {
            // Only the SRP safety checks reach here; an unknown user gets a decoy.
            fail("Authentication failed", std::string("handshake: ") + e.what());
            co_return std::nullopt;
        }

        send(Protocol::encode(MessageType::SRP_CHALLENGE, SrpChallengeMsg{
                                  challenge.user_id,
                                  auth::SRPUtils::bytes_to_base64(challenge.B),
                                  auth::SRPUtils::bytes_to_base64(challenge.salt),
                                  auth::SRPUtils::bytes_to_base64(challenge.room_salt)}));

        auto [response_type, response_payload] = co_await ProtocolHelpers::async_receive_packet(socket_);
        if (response_type != MessageType::SRP_RESPONSE) {
            fail("Expected SRP_RESPONSE", "handshake: wrong response message");
            co_return std::nullopt;
        }

        const auto response = Protocol::decode<SrpResponseMsg>(response_payload);
        if (response.user_id != challenge.user_id) {
            fail("Authentication failed", "handshake: user id mismatch");
            co_return std::nullopt;
        }

        if (server_.room().username_online(init.username)) {
            fail("User already logged in", "handshake: duplicate login for " + init.username);
            co_return std::nullopt;
        }

        try {
            const auto verify = server_.srp().verify_authentication(
                response.user_id, auth::SRPUtils::base64_to_bytes(response.M_b64));

            send(Protocol::encode(MessageType::SRP_SUCCESS,
                                  SrpSuccessMsg{auth::SRPUtils::bytes_to_base64(verify.H_AMK)}));
        }
        catch (const std::exception& e) {
            ++auth_attempts_;
            fail("Authentication failed",
                 "handshake: proof rejected (attempt " + std::to_string(auth_attempts_)
                     + " of " + std::to_string(kMaxAuthAttempts) + "): " + e.what());
            co_return std::nullopt;
        }

        auto key = server_.srp().derive_session_key(response.user_id);
        if (key.size() != crypto::AESEngine::KEY_SIZE) {
            fail("Authentication failed", "handshake: derived key has wrong size");
            co_return std::nullopt;
        }

        username_ = init.username;
        server_.room().join(response.user_id, username_, shared_from_this(), std::move(key));

        log::info("user '" + username_ + "' authenticated from " + remote_);

        send(server_.room().init_packet_for(response.user_id));
        server_.room().broadcast_packet(
            Protocol::encode(MessageType::USER_JOINED, UserJoinedMsg{username_, response.user_id}),
            response.user_id);

        co_return response.user_id;
    }

    awaitable<void> Session::message_loop(const std::string& user_id)
    {
        const auto key = server_.srp().derive_session_key(user_id);

        while (socket_.is_open()) {
            auto [type, payload] = co_await ProtocolHelpers::async_receive_packet(socket_);
            extend_deadline();

            switch (type) {
                case MessageType::MESSAGE: {
                    const auto msg = Protocol::decode<TextMsg>(payload);

                    std::string text;
                    try {
                        text = crypto::AESEngine::decrypt_string(
                            auth::SRPUtils::base64_to_bytes(msg.ciphertext_b64), key);
                    }
                    catch (const std::exception&) {
                        fail("Message could not be decrypted", "message: decryption failed");
                        co_return;
                    }

                    if (text.empty() || text.size() > kMaxMessageLength) {
                        fail("Message rejected", "message: length out of range");
                        break;
                    }

                    // Deliberately logs no plaintext.
                    log::info("message from '" + username_ + "' (" + std::to_string(text.size()) + " bytes)");
                    server_.room().record_and_broadcast(username_, text);
                    break;
                }
                case MessageType::DISCONNECT:
                    co_return;
                default:
                    log::warn(remote_ + ": unexpected message type "
                              + std::to_string(static_cast<int>(type)));
                    co_return;
            }
        }
    }
} // namespace chat::server
```

- [ ] **Step 4: Rewrite `include/chat/server/server.hpp`**

```cpp
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include "chat/auth/srp_server.hpp"
#include "chat/server/room.hpp"

namespace chat::server
{
    struct ServerConfig
    {
        uint16_t port                          = 8888;
        std::string users_db                   = "users.db";
        size_t max_connections                 = 256;
        std::chrono::seconds handshake_timeout = std::chrono::seconds(30);
        std::chrono::seconds idle_timeout      = std::chrono::seconds(120);
    };

    class Server
    {
    public:
        explicit Server(ServerConfig config);
        ~Server();

        void run();
        void stop();

        // Used by Session.
        Room& room() { return room_; }
        auth::SRPServer& srp() { return *srp_server_; }
        [[nodiscard]] std::chrono::seconds handshake_timeout() const { return config_.handshake_timeout; }
        [[nodiscard]] std::chrono::seconds idle_timeout() const { return config_.idle_timeout; }
        void on_session_closed() { --open_connections_; }

    private:
        boost::asio::awaitable<void> accept_loop();
        boost::asio::awaitable<void> session_sweeper();

        ServerConfig config_;
        boost::asio::io_context io_context_;
        boost::asio::ip::tcp::acceptor acceptor_;
        std::unique_ptr<auth::SRPServer> srp_server_;
        Room room_;
        std::atomic<size_t> open_connections_{0};
    };
} // namespace chat::server
```

- [ ] **Step 5: Rewrite `src/server/server.cpp`**

```cpp
#include "chat/server/server.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>

#include "chat/common/log.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"
#include "chat/server/session.hpp"

namespace chat::server
{
    using boost::asio::awaitable;
    using boost::asio::co_spawn;
    using boost::asio::detached;
    using boost::asio::use_awaitable;

    Server::Server(ServerConfig config)
        : config_(std::move(config))
          , acceptor_(io_context_,
                      boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), config_.port))
          , srp_server_(std::make_unique<auth::SRPServer>(config_.users_db))
    {
        srp_server_->load();
    }

    Server::~Server()
    {
        stop();
    }

    void Server::run()
    {
        log::info("listening on port " + std::to_string(config_.port)
                  + " (max " + std::to_string(config_.max_connections) + " connections)");

        co_spawn(io_context_, [this] { return accept_loop(); }, detached);
        co_spawn(io_context_, [this] { return session_sweeper(); }, detached);

        // Signals are delivered on the io_context, not in a signal handler, so
        // shutdown can do real work: close the acceptor and persist the database.
        boost::asio::signal_set signals(io_context_, SIGINT, SIGTERM);
        signals.async_wait([this](const boost::system::error_code&, int) {
            log::info("shutting down");
            stop();
        });

        const auto threads = std::max(1u, std::thread::hardware_concurrency());
        std::vector<std::thread> pool;
        pool.reserve(threads - 1);
        for (unsigned i = 1; i < threads; ++i)
            pool.emplace_back([this] { io_context_.run(); });

        io_context_.run();

        for (auto& thread : pool)
            thread.join();

        try {
            srp_server_->save();
            log::info("user database saved");
        }
        catch (const std::exception& e) {
            log::error(std::string("failed to save user database: ") + e.what());
        }
    }

    void Server::stop()
    {
        boost::system::error_code ec;
        acceptor_.close(ec);
        io_context_.stop();
    }

    awaitable<void> Server::accept_loop()
    {
        while (acceptor_.is_open()) {
            boost::system::error_code ec;
            auto socket = co_await acceptor_.async_accept(
                boost::asio::redirect_error(use_awaitable, ec));

            if (ec) {
                if (acceptor_.is_open())
                    log::warn("accept failed: " + ec.message());
                co_return;
            }

            if (open_connections_.load() >= config_.max_connections) {
                log::warn("connection refused: limit of "
                          + std::to_string(config_.max_connections) + " reached");
                boost::system::error_code close_ec;
                socket.close(close_ec);
                continue;
            }

            ++open_connections_;
            std::make_shared<Session>(std::move(socket), *this)->start();
        }
    }

    awaitable<void> Server::session_sweeper()
    {
        boost::asio::steady_timer timer(io_context_);

        while (!io_context_.stopped()) {
            timer.expires_after(std::chrono::seconds(60));

            boost::system::error_code ec;
            co_await timer.async_wait(boost::asio::redirect_error(use_awaitable, ec));
            if (ec)
                co_return;

            srp_server_->clear_expired_sessions(3600);
        }
    }
} // namespace chat::server
```

Add `#include <algorithm>`, `#include <thread>`, and `#include <vector>`.

- [ ] **Step 6: Rewrite `src/server/main.cpp`**

Keep positional arguments for one more task; Task 11 replaces this wholesale.

```cpp
#include "chat/common/log.hpp"
#include "chat/server/server.hpp"

#include <cstdlib>
#include <string>

int main(const int argc, char* argv[])
{
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    try {
        const int port = std::stoi(argv[1]);
        if (port < 1024 || port > 65535) {
            std::fprintf(stderr, "Port must be between 1024 and 65535\n");
            return EXIT_FAILURE;
        }

        chat::server::ServerConfig config;
        config.port = static_cast<uint16_t>(port);

        chat::server::Server server(config);
        server.run();
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        chat::log::error(std::string("fatal: ") + e.what());
        return EXIT_FAILURE;
    }
}
```

Add `#include <cstdio>`.

- [ ] **Step 7: Delete `ConnectionManager` and update CMake**

```bash
git rm include/chat/server/connection_manager.hpp src/server/connection_manager.cpp
```

In `CMakeLists.txt`, the `chat_server` source list becomes:

```cmake
add_executable(chat_server
        src/server/main.cpp
        src/server/server.cpp
        src/server/session.cpp
        src/server/room.cpp
)
```

- [ ] **Step 8: Build and run the tests**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: everything compiles and all suites pass. `RoomTest` is unaffected — it never touched
`ConnectionManager`.

If the compiler reports that `awaitable_operators` is unused, delete the `using namespace` line from
`session.cpp`; it is only needed if a later step introduces `||` composition.

- [ ] **Step 9: Manual smoke test with two clients**

```bash
./build/debug/chat_server 8888 &
```
In two more terminals, run `./build/debug/chat_client localhost 8888 alice` and
`... bob`. Registration is not reachable from the CLI until Task 11, so instead confirm the
server accepts connections, logs `listening on port 8888`, rejects the unknown users cleanly
without crashing, and that `kill -INT %1` prints `shutting down` followed by `user database saved`
and exits — the old build leaked out through `exit(0)` and never saved.

- [ ] **Step 10: Commit**

```bash
git add include src CMakeLists.txt
git commit -m "refactor(server): async coroutine sessions"
```

---

## Task 9: Connection limits, timeouts, graceful shutdown — verification

Tasks 8 built the mechanisms; this task proves they work and fixes what the proof exposes.

**Files:**
- Modify: `src/server/session.cpp`, `src/server/server.cpp`, `tests/srp_tests.cpp`

**Interfaces:**
- Consumes: `ServerConfig`, `Session::watchdog`, `Server::accept_loop`.
- Produces: no new API. `kMaxAuthAttempts` becomes enforced across a connection rather than merely counted.

- [ ] **Step 1: Enforce the auth attempt budget**

In `src/server/session.cpp::handshake`, the counter is incremented but the session closes after one
failure, so the budget is meaningless. Wrap the challenge/response exchange in a loop so a client may
retry up to `kMaxAuthAttempts` times on one connection before being dropped. Replace the block from
the `SRP_CHALLENGE` send through the proof verification with:

```cpp
        while (auth_attempts_ < kMaxAuthAttempts) {
            send(Protocol::encode(MessageType::SRP_CHALLENGE, SrpChallengeMsg{
                                      challenge.user_id,
                                      auth::SRPUtils::bytes_to_base64(challenge.B),
                                      auth::SRPUtils::bytes_to_base64(challenge.salt),
                                      auth::SRPUtils::bytes_to_base64(challenge.room_salt)}));

            auto [response_type, response_payload] =
                co_await ProtocolHelpers::async_receive_packet(socket_);

            if (response_type != MessageType::SRP_RESPONSE) {
                fail("Expected SRP_RESPONSE", "handshake: wrong response message");
                co_return std::nullopt;
            }

            const auto response = Protocol::decode<SrpResponseMsg>(response_payload);
            if (response.user_id != challenge.user_id) {
                fail("Authentication failed", "handshake: user id mismatch");
                co_return std::nullopt;
            }

            try {
                const auto verify = server_.srp().verify_authentication(
                    response.user_id, auth::SRPUtils::base64_to_bytes(response.M_b64));

                send(Protocol::encode(MessageType::SRP_SUCCESS,
                                      SrpSuccessMsg{auth::SRPUtils::bytes_to_base64(verify.H_AMK)}));

                co_return co_await finish_login(init.username, response.user_id);
            }
            catch (const std::exception& e) {
                ++auth_attempts_;
                log::warn(remote_ + ": proof rejected (attempt " + std::to_string(auth_attempts_)
                          + " of " + std::to_string(kMaxAuthAttempts) + "): " + e.what());
                send(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Authentication failed"}));
            }
        }

        log::warn(remote_ + ": authentication attempt budget exhausted");
        co_return std::nullopt;
```

Extract the post-success work (duplicate-login check, key derivation, `room().join`, INIT, and the
`USER_JOINED` broadcast) into a private helper so the loop stays readable:

```cpp
        boost::asio::awaitable<std::optional<std::string>> finish_login(
            const std::string& username, const std::string& user_id);
```

Its body is the code that currently follows the successful `verify_authentication`, unchanged, ending
with `co_return user_id;`.

- [ ] **Step 2: Add the failing test for the attempt budget**

Session-level behaviour is not unit-testable without a socket, so assert the invariant at the SRP
layer in `tests/srp_tests.cpp`:

```cpp
    TEST(SrpTest, RepeatedBadProofsKeepFailing)
    {
        auto server = make_server_with_user("mallory", "real-password");

        for (int attempt = 0; attempt < 3; ++attempt) {
            SRPClient client("mallory", "guess-" + std::to_string(attempt));
            const auto A         = client.generate_A();
            const auto challenge = server.init_authentication("mallory", A);
            const auto M         = client.process_challenge(challenge.B, challenge.salt);

            EXPECT_THROW((void)server.verify_authentication(challenge.user_id, M), std::runtime_error);
            EXPECT_FALSE(server.is_session_valid(challenge.user_id));
        }
    }
```

- [ ] **Step 3: Run the tests**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: all suites pass, including the new case.

- [ ] **Step 4: Verify the connection cap by hand**

Temporarily set `config.max_connections = 2;` in `src/server/main.cpp`, rebuild, start the server,
and open three connections with `nc`:

```bash
./build/debug/chat_server 8888 &
for i in 1 2 3; do (nc localhost 8888 &) ; done
```
Expected: the server log shows `connection refused: limit of 2 reached` exactly once, and the server
keeps serving. Restore the line to the default afterwards.

- [ ] **Step 5: Verify the handshake timeout**

Start the server, connect with `nc localhost 8888`, and send nothing.
Expected: after 30 seconds the server logs `timed out` and drops the connection while remaining
responsive to a fresh `nc`. To avoid a 30-second wait, temporarily set
`config.handshake_timeout = std::chrono::seconds(2);` for the check, then restore it.

- [ ] **Step 6: Verify graceful shutdown under load**

Start the server, connect two `nc` clients, then `kill -INT %1`.
Expected: log shows `shutting down`, then `user database saved`, and the process exits with status 0
within a second. No hang, no core dump.

- [ ] **Step 7: Run the sanitizer build**

Run: `cmake --preset asan && cmake --build --preset asan && ctest --preset asan`
Expected: all tests pass with no ASan or UBSan reports. Fix anything reported before committing —
the coroutine lifetimes and the `shared_from_this` captures are exactly what this catches.

- [ ] **Step 8: Commit**

```bash
git add src tests/srp_tests.cpp
git commit -m "feat(server): enforce connection limits and timeouts"
```

---

## Task 10: Client — async receive loop and terminal handling

**Files:**
- Create: `include/chat/client/terminal.hpp`, `src/client/terminal.cpp`
- Modify: `include/chat/client/client.hpp`, `src/client/client.cpp`, `include/chat/common/protocol.hpp`, `CMakeLists.txt`

**Interfaces:**
- Consumes: `async_send_packet` / `async_receive_packet` from Task 8.
- Produces, in namespace `chat::client::terminal`:
  - `std::string read_password(const std::string& prompt)` — echo suppressed, newline emitted after.
  - `bool colors_enabled()` — false when `NO_COLOR` is set or stdout is not a TTY; result cached.
  - `const char* color(const char* ansi)` — returns `ansi` when colours are on, `""` otherwise.
  - `void clear_screen()`, `void clear_line()` — ANSI, no subprocess.
  - `void wipe(std::string& secret)` — `OPENSSL_cleanse` then `clear()`.

After this task the blocking `ProtocolHelpers::send_packet` / `receive_packet` have no callers and
are deleted.

- [ ] **Step 1: Write `include/chat/client/terminal.hpp`**

```cpp
#pragma once

#include <string>

namespace chat::client::terminal
{
    // Reads a line with terminal echo disabled. Falls back to a plain read when
    // stdin is not a terminal (a pipe in a test or a script).
    std::string read_password(const std::string& prompt);

    // False when NO_COLOR is set or stdout is not a TTY.
    bool colors_enabled();

    // Returns the escape sequence, or "" when colours are disabled.
    const char* color(const char* ansi);

    void clear_screen();
    void clear_line();

    // Overwrites the contents before clearing, so the password does not linger.
    void wipe(std::string& secret);
} // namespace chat::client::terminal
```

- [ ] **Step 2: Write `src/client/terminal.cpp`**

```cpp
#include "chat/client/terminal.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>

#include <openssl/crypto.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace chat::client::terminal
{
    namespace
    {
        bool stdin_is_tty()
        {
#ifdef _WIN32
            return _isatty(_fileno(stdin)) != 0;
#else
            return ::isatty(STDIN_FILENO) != 0;
#endif
        }

        bool stdout_is_tty()
        {
#ifdef _WIN32
            return _isatty(_fileno(stdout)) != 0;
#else
            return ::isatty(STDOUT_FILENO) != 0;
#endif
        }

        // RAII echo suppression: restores the original mode even if the read throws.
        class EchoOff
        {
        public:
            EchoOff()
            {
#ifdef _WIN32
                handle_ = GetStdHandle(STD_INPUT_HANDLE);
                if (GetConsoleMode(handle_, &original_)) {
                    active_ = true;
                    SetConsoleMode(handle_, original_ & ~ENABLE_ECHO_INPUT);
                }
#else
                if (tcgetattr(STDIN_FILENO, &original_) == 0) {
                    active_        = true;
                    termios quiet  = original_;
                    quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
                    tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
                }
#endif
            }

            ~EchoOff()
            {
                if (!active_) return;
#ifdef _WIN32
                SetConsoleMode(handle_, original_);
#else
                tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
#endif
            }

            EchoOff(const EchoOff&)            = delete;
            EchoOff& operator=(const EchoOff&) = delete;

        private:
            bool active_ = false;
#ifdef _WIN32
            HANDLE handle_{};
            DWORD original_{};
#else
            termios original_{};
#endif
        };
    }

    std::string read_password(const std::string& prompt)
    {
        std::cout << prompt << std::flush;

        std::string password;
        if (stdin_is_tty()) {
            const EchoOff guard;
            std::getline(std::cin, password);
            std::cout << std::endl; // the user's Enter was not echoed
        }
        else {
            std::getline(std::cin, password);
        }

        return password;
    }

    bool colors_enabled()
    {
        static const bool enabled = (std::getenv("NO_COLOR") == nullptr) && stdout_is_tty();
        return enabled;
    }

    const char* color(const char* ansi)
    {
        return colors_enabled() ? ansi : "";
    }

    void clear_screen()
    {
        if (colors_enabled())
            std::cout << "\033[2J\033[H" << std::flush; // clear, cursor home
    }

    void clear_line()
    {
        if (colors_enabled())
            std::cout << "\r\033[2K" << std::flush; // carriage return, erase line
        else
            std::cout << "\n";
    }

    void wipe(std::string& secret)
    {
        if (!secret.empty())
            OPENSSL_cleanse(secret.data(), secret.size());
        secret.clear();
    }
} // namespace chat::client::terminal
```

Add `#include <io.h>` inside the `_WIN32` branch for `_isatty`.

- [ ] **Step 3: Register the new source**

In `CMakeLists.txt`, add `src/client/terminal.cpp` to the `chat_client` source list and link
`OpenSSL::Crypto` into `chat_client` (it already arrives transitively through `chat_auth`, but naming
it is honest since `terminal.cpp` calls `OPENSSL_cleanse` directly).

- [ ] **Step 4: Convert the client to coroutines**

In `include/chat/client/client.hpp`, replace the receive thread with an io_context thread and make
the packet paths coroutines:

```cpp
        void connect();
        void input_loop();   // blocking stdin loop, runs on the main thread
        boost::asio::awaitable<void> receive_loop();
        boost::asio::awaitable<void> srp_authenticate();
        boost::asio::awaitable<void> srp_register();
        boost::asio::awaitable<void> send_message(const std::string& text);

        std::thread io_thread_;   // runs io_context_, replaces receive_thread_
        bool register_first_ = false;
```

`run()` stays a normal function: it owns the blocking stdin loop on the main thread and dispatches
work into the io_context. In `src/client/client.cpp`:

```cpp
    void Client::run()
    {
        try {
            connect();

            auto login = boost::asio::co_spawn(
                io_context_,
                [this]() -> boost::asio::awaitable<void> {
                    if (register_first_)
                        co_await srp_register();
                    co_await srp_authenticate();
                },
                boost::asio::use_future);

            io_thread_ = std::thread([this] { io_context_.run(); });
            login.get(); // rethrows any handshake exception on this thread

            running_ = true;
            boost::asio::co_spawn(io_context_, [this] { return receive_loop(); }, boost::asio::detached);

            render_ui();
            input_loop();
        }
        catch (const std::exception& e) {
            log::error(std::string("client error: ") + e.what());
        }

        stop();
    }
```

`input_loop()` is the existing `while (running_ && connected_)` body from lines 53–83, unchanged
except that `send_message(line)` becomes:

```cpp
                        boost::asio::co_spawn(
                            io_context_,
                            [this, line] { return send_message(line); },
                            boost::asio::detached);
```

`stop()` becomes:

```cpp
    void Client::stop()
    {
        if (running_.exchange(false)) {
            boost::asio::post(io_context_, [this] { disconnect(); });
            io_context_.stop();
        }

        if (io_thread_.joinable())
            io_thread_.join();

        terminal::wipe(password_);
    }
```

`disconnect()` now runs on the io_context thread, so it no longer closes the socket underneath a
blocking read — that race is gone. Its body keeps the `send DISCONNECT`, `socket_.close()`,
`connected_ = false` sequence but drops the `try`/`catch(...)` around the send, replaced by an
error-code close:

```cpp
    void Client::disconnect()
    {
        if (socket_.is_open()) {
            boost::system::error_code ec;
            const auto packet = Protocol::encode(MessageType::DISCONNECT);
            boost::asio::write(socket_, boost::asio::buffer(packet), ec);
            socket_.close(ec);
        }
        connected_ = false;
    }
```

`receive_loop`, `send_message`, `srp_authenticate`, and `srp_register` each convert mechanically:
every `send_packet(p)` becomes `co_await ProtocolHelpers::async_send_packet(socket_, p)`, every
`receive_packet()` becomes `co_await ProtocolHelpers::async_receive_packet(socket_)`, and the return
type becomes `boost::asio::awaitable<...>`. Delete the `Client::send_packet` and
`Client::receive_packet` wrappers.

Add includes: `<boost/asio/co_spawn.hpp>`, `<boost/asio/detached.hpp>`, `<boost/asio/use_future.hpp>`,
`"chat/client/terminal.hpp"`, `"chat/common/log.hpp"`.

- [ ] **Step 5: Handle the new `INIT` shape**

`InitMsg::messages` now holds `HistoryEntry`, which the client must decrypt into its in-memory
`Message` vector. In `handle_packet`'s `INIT` case:

```cpp
            case MessageType::INIT: {
                auto msg = Protocol::decode<InitMsg>(payload);

                std::vector<Message> decrypted;
                decrypted.reserve(msg.messages.size());
                for (const auto& entry : msg.messages) {
                    try {
                        const auto text = crypto::AESEngine::decrypt_string(
                            auth::SRPUtils::base64_to_bytes(entry.ciphertext_b64), room_key_);
                        decrypted.emplace_back(
                            entry.username, text,
                            std::chrono::system_clock::time_point(
                                std::chrono::milliseconds(entry.timestamp_ms)));
                    }
                    catch (const std::exception&) {
                        continue; // skip an entry we cannot read rather than aborting the join
                    }
                }

                {
                    std::lock_guard<std::mutex> lock(messages_mutex_);
                    messages_ = std::move(decrypted);
                }
                {
                    std::lock_guard<std::mutex> lock(users_mutex_);
                    users_ = std::move(msg.users);
                }
                break;
            }
```

Note this also replaces the `std::unique_lock<std::mutex> lock;` reassignment pattern used
throughout `handle_packet` — a default-constructed `unique_lock` reassigned per case is needlessly
subtle. Convert every case in that switch to a scoped `std::lock_guard` the same way.

- [ ] **Step 6: Route all terminal output through `terminal`**

Replace, throughout `src/client/client.cpp`:

- `system("cls")` / `system("clear")` in `clear_screen()` → delete the method, call `terminal::clear_screen()`.
- every `std::cout << "\r" << std::string(80, ' ') << "\r";` → `terminal::clear_line();`
- every hard-coded escape, for example `"\033[33m"` → `terminal::color("\033[33m")`, and each matching `"\033[0m"` → `terminal::color("\033[0m")`.
- both `std::getline(std::cin, password_)` prompts → `password_ = terminal::read_password("Enter password: ");`
- in `srp_register()`, follow the first prompt with a confirmation:

```cpp
        password_ = terminal::read_password("Enter password: ");
        const auto confirm = terminal::read_password("Confirm password: ");
        if (password_ != confirm)
            throw std::runtime_error("Passwords do not match");
```

- `std::put_time(std::localtime(&time_t), ...)` in `render_ui` → `std::localtime` is not
  thread-safe; use `localtime_r` on POSIX and `localtime_s` on Windows, matching the pattern in
  `log.hpp`.

- [ ] **Step 7: Delete the blocking protocol helpers**

In `include/chat/common/protocol.hpp`, remove `send_packet` and `receive_packet`. Run
`grep -rn "ProtocolHelpers::send_packet\|ProtocolHelpers::receive_packet" src/ tests/` and confirm
no hits remain.

- [ ] **Step 8: Build and test**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: everything compiles and all suites pass.

- [ ] **Step 9: Verify the password is not echoed**

Run `./build/debug/chat_client localhost 8888 alice` against a running server and type at the
password prompt.
Expected: nothing appears on screen while typing, and a newline follows Enter. Then run
`NO_COLOR=1 ./build/debug/chat_client ... | cat` and confirm no escape sequences appear in the piped
output.

- [ ] **Step 10: Commit**

```bash
git add include src CMakeLists.txt
git commit -m "refactor(client): async receive loop and terminal handling"
```

---

## Task 11: Flag-based configuration

**Files:**
- Create: `include/chat/common/cli.hpp`, `src/common/cli.cpp`
- Modify: `src/server/main.cpp`, `src/client/main.cpp`, `include/chat/client/client.hpp`, `src/client/client.cpp`, `CMakeLists.txt`
- Create: `tests/cli_tests.cpp`

**Interfaces:**
- Produces `class chat::Cli`:
  - `Cli(int argc, char* argv[])` — parses `--flag value`, `--flag=value`, and bare `--flag` booleans. Throws `std::runtime_error` on an unknown flag or a missing value.
  - `bool has(const std::string& name) const`
  - `std::string get(const std::string& name, const std::string& fallback) const`
  - `int get_int(const std::string& name, int fallback) const` — throws on a non-numeric value.
  - `void expect_known(std::initializer_list<const char*> names) const` — throws naming the first unrecognised flag.
- `Client` constructor becomes `Client(ClientConfig config)` with `struct ClientConfig { std::string host = "localhost"; uint16_t port = 8888; std::string username; bool register_first = false; };`

- [ ] **Step 1: Write the failing test file `tests/cli_tests.cpp`**

```cpp
#include "chat/common/cli.hpp"

#include <gtest/gtest.h>
#include <vector>

namespace chat
{
    namespace
    {
        Cli parse(std::vector<const char*> args)
        {
            args.insert(args.begin(), "prog");
            return Cli(static_cast<int>(args.size()), const_cast<char**>(args.data()));
        }
    }

    TEST(CliTest, ParsesSeparatedValues)
    {
        const auto cli = parse({"--host", "example.com", "--port", "9000"});
        EXPECT_EQ(cli.get("host", "localhost"), "example.com");
        EXPECT_EQ(cli.get_int("port", 8888), 9000);
    }

    TEST(CliTest, ParsesEqualsForm)
    {
        const auto cli = parse({"--host=example.com", "--port=9000"});
        EXPECT_EQ(cli.get("host", "localhost"), "example.com");
        EXPECT_EQ(cli.get_int("port", 8888), 9000);
    }

    TEST(CliTest, BareFlagIsBoolean)
    {
        const auto cli = parse({"--register"});
        EXPECT_TRUE(cli.has("register"));
        EXPECT_FALSE(cli.has("help"));
    }

    TEST(CliTest, FallsBackWhenAbsent)
    {
        const auto cli = parse({});
        EXPECT_EQ(cli.get("host", "localhost"), "localhost");
        EXPECT_EQ(cli.get_int("port", 8888), 8888);
    }

    TEST(CliTest, RejectsNonNumericInt)
    {
        const auto cli = parse({"--port", "eight"});
        EXPECT_THROW((void)cli.get_int("port", 8888), std::runtime_error);
    }

    TEST(CliTest, RejectsPositionalArguments)
    {
        EXPECT_THROW((void)parse({"stray"}), std::runtime_error);
    }

    TEST(CliTest, ExpectKnownNamesTheOffendingFlag)
    {
        const auto cli = parse({"--hsot", "example.com"});
        EXPECT_THROW(cli.expect_known({"host", "port"}), std::runtime_error);
        EXPECT_NO_THROW(parse({"--host", "x"}).expect_known({"host", "port"}));
    }
} // namespace chat
```

- [ ] **Step 2: Register the target**

Add `src/common/cli.cpp` to `chat_common`, then:

```cmake
    add_executable(cli_tests
            tests/cli_tests.cpp
    )
    target_link_libraries(cli_tests
            PRIVATE
            chat_common
            GTest::gtest_main
    )
```

plus `gtest_discover_tests(cli_tests)`.

- [ ] **Step 3: Run the build to verify it fails**

Run: `cmake --build --preset debug 2>&1 | tail -20`
Expected: `chat/common/cli.hpp: No such file or directory`.

- [ ] **Step 4: Write `include/chat/common/cli.hpp`**

```cpp
#pragma once

#include <initializer_list>
#include <map>
#include <string>

namespace chat
{
    /**
     * Minimal long-flag parser: --flag value, --flag=value, and bare --flag.
     * Deliberately not a general argument library — two binaries with a handful
     * of options each do not justify a dependency.
     */
    class Cli
    {
    public:
        Cli(int argc, char* argv[]);

        [[nodiscard]] bool has(const std::string& name) const;
        [[nodiscard]] std::string get(const std::string& name, const std::string& fallback) const;
        [[nodiscard]] int get_int(const std::string& name, int fallback) const;

        // Throws naming the first flag that is not in `names`.
        void expect_known(std::initializer_list<const char*> names) const;

    private:
        std::map<std::string, std::string> values_;
    };
} // namespace chat
```

- [ ] **Step 5: Write `src/common/cli.cpp`**

```cpp
#include "chat/common/cli.hpp"

#include <algorithm>
#include <stdexcept>

namespace chat
{
    Cli::Cli(const int argc, char* argv[])
    {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];

            if (!arg.starts_with("--"))
                throw std::runtime_error("Unexpected argument '" + arg + "' (options start with --)");

            arg.erase(0, 2);

            if (const auto eq = arg.find('='); eq != std::string::npos) {
                values_[arg.substr(0, eq)] = arg.substr(eq + 1);
                continue;
            }

            // A following token that is not itself a flag is this flag's value.
            if (i + 1 < argc && !std::string(argv[i + 1]).starts_with("--")) {
                values_[arg] = argv[++i];
                continue;
            }

            values_[arg] = ""; // bare boolean flag
        }
    }

    bool Cli::has(const std::string& name) const
    {
        return values_.contains(name);
    }

    std::string Cli::get(const std::string& name, const std::string& fallback) const
    {
        const auto it = values_.find(name);
        if (it == values_.end() || it->second.empty())
            return fallback;
        return it->second;
    }

    int Cli::get_int(const std::string& name, const int fallback) const
    {
        const auto it = values_.find(name);
        if (it == values_.end() || it->second.empty())
            return fallback;

        try {
            size_t consumed = 0;
            const int value = std::stoi(it->second, &consumed);
            if (consumed != it->second.size())
                throw std::invalid_argument("trailing characters");
            return value;
        }
        catch (const std::exception&) {
            throw std::runtime_error("Option --" + name + " expects a number, got '" + it->second + "'");
        }
    }

    void Cli::expect_known(std::initializer_list<const char*> names) const
    {
        for (const auto& [name, value] : values_) {
            const bool known = std::ranges::any_of(names, [&name](const char* candidate) {
                return name == candidate;
            });

            if (!known)
                throw std::runtime_error("Unknown option --" + name);
        }
    }
} // namespace chat
```

- [ ] **Step 6: Rewrite `src/server/main.cpp`**

```cpp
#include "chat/common/cli.hpp"
#include "chat/common/log.hpp"
#include "chat/server/server.hpp"

#include <cstdio>
#include <cstdlib>

namespace
{
    void print_usage(const char* program)
    {
        std::printf(
            "Usage: %s [options]\n"
            "\n"
            "  --port <n>               Listen port (default 8888, range 1024-65535)\n"
            "  --users-db <path>        Credential database (default users.db)\n"
            "  --max-connections <n>    Concurrent connection cap (default 256)\n"
            "  --handshake-timeout <s>  Seconds to complete authentication (default 30)\n"
            "  --idle-timeout <s>       Seconds of silence before disconnect (default 120)\n"
            "  --help                   Show this message\n",
            program);
    }
}

int main(const int argc, char* argv[])
{
    try {
        const chat::Cli cli(argc, argv);
        cli.expect_known({"port", "users-db", "max-connections",
                          "handshake-timeout", "idle-timeout", "help"});

        if (cli.has("help")) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }

        chat::server::ServerConfig config;

        const int port = cli.get_int("port", 8888);
        if (port < 1024 || port > 65535)
            throw std::runtime_error("--port must be between 1024 and 65535");
        config.port = static_cast<uint16_t>(port);

        config.users_db = cli.get("users-db", "users.db");

        const int max_connections = cli.get_int("max-connections", 256);
        if (max_connections < 1)
            throw std::runtime_error("--max-connections must be at least 1");
        config.max_connections = static_cast<size_t>(max_connections);

        const int handshake = cli.get_int("handshake-timeout", 30);
        const int idle      = cli.get_int("idle-timeout", 120);
        if (handshake < 1 || idle < 1)
            throw std::runtime_error("timeouts must be at least 1 second");
        config.handshake_timeout = std::chrono::seconds(handshake);
        config.idle_timeout      = std::chrono::seconds(idle);

        chat::server::Server server(config);
        server.run();
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        chat::log::error(e.what());
        std::fprintf(stderr, "Try '%s --help'\n", argv[0]);
        return EXIT_FAILURE;
    }
}
```

- [ ] **Step 7: Rewrite `src/client/main.cpp`**

```cpp
#include "chat/client/client.hpp"
#include "chat/common/cli.hpp"
#include "chat/common/log.hpp"

#include <cstdio>
#include <cstdlib>

namespace
{
    void print_usage(const char* program)
    {
        std::printf(
            "Usage: %s --user <name> [options]\n"
            "\n"
            "  --user <name>   Username, 1-32 chars of [A-Za-z0-9_-] (required)\n"
            "  --host <host>   Server host (default localhost)\n"
            "  --port <n>      Server port (default 8888)\n"
            "  --register      Create the account before logging in\n"
            "  --help          Show this message\n",
            program);
    }
}

int main(const int argc, char* argv[])
{
    try {
        const chat::Cli cli(argc, argv);
        cli.expect_known({"user", "host", "port", "register", "help"});

        if (cli.has("help")) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }

        chat::client::ClientConfig config;
        config.host           = cli.get("host", "localhost");
        config.username       = cli.get("user", "");
        config.register_first = cli.has("register");

        if (config.username.empty())
            throw std::runtime_error("--user is required");

        const int port = cli.get_int("port", 8888);
        if (port < 1024 || port > 65535)
            throw std::runtime_error("--port must be between 1024 and 65535");
        config.port = static_cast<uint16_t>(port);

        chat::client::Client client(std::move(config));
        client.run();
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        chat::log::error(e.what());
        std::fprintf(stderr, "Try '%s --help'\n", argv[0]);
        return EXIT_FAILURE;
    }
}
```

- [ ] **Step 8: Adopt `ClientConfig` in the client**

In `include/chat/client/client.hpp`, add the struct above the class and replace the constructor:

```cpp
    struct ClientConfig
    {
        std::string host     = "localhost";
        uint16_t port        = 8888;
        std::string username;
        bool register_first  = false;
    };
```

```cpp
        explicit Client(ClientConfig config);
```

Replace the `host_`, `port_`, `username_`, and `register_first_` members with a single
`ClientConfig config_;` and update every use (`host_` → `config_.host`, and so on). The constructor
body becomes `: socket_(io_context_), config_(std::move(config)), running_(false), connected_(false) {}`.

- [ ] **Step 9: Run the tests**

Run: `cmake --build --preset debug && ctest --preset debug`
Expected: all seven `CliTest` cases pass along with every other suite.

- [ ] **Step 10: Full manual end-to-end run**

```bash
./build/debug/chat_server --port 8888 &
./build/debug/chat_client --user alice --register
```
Expected: prompts for a password twice, registers, authenticates, and shows the banner. In a second
terminal, `./build/debug/chat_client --user bob --register`, then send messages both ways.
Expected: each client sees the other's messages with correct timestamps; a third client joining with
`--user carol --register` receives the prior history. Then check the failure modes:

```bash
./build/debug/chat_client --help
./build/debug/chat_client --user alice --port 99999
./build/debug/chat_client --hsot localhost --user alice
./build/debug/chat_client --user alice   # wrong password at the prompt
```
Expected, in order: usage text and exit 0; `--port must be between 1024 and 65535`;
`Unknown option --hsot`; and a generic `Authentication failed` that does not reveal whether the
account exists.

- [ ] **Step 11: Commit**

```bash
git add include src tests/cli_tests.cpp CMakeLists.txt
git commit -m "feat(cli): flag-based configuration for server and client"
```

---

## Task 12: Extend AES coverage

**Files:**
- Modify: `tests/aes_tests.cpp`

**Interfaces:**
- Consumes: `crypto::AESEngine`. No production code changes — this task exists to prove the AEAD
  fails closed, since every confidentiality guarantee in the system now rests on it.

- [ ] **Step 1: Read the existing file**

Run: `grep -n "TEST" tests/aes_tests.cpp`
Skip any case below that already exists under a different name rather than duplicating it.

- [ ] **Step 2: Add the tamper-detection tests**

```cpp
    TEST(AesTest, WrongKeyFailsToDecrypt)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x11);
        const std::vector<uint8_t> other(crypto::AESEngine::KEY_SIZE, 0x22);

        const auto sealed = crypto::AESEngine::encrypt_string("secret", key);
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(sealed, other), std::runtime_error);
    }

    TEST(AesTest, FlippedTagBitIsRejected)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x33);
        auto sealed = crypto::AESEngine::encrypt_string("secret", key);

        sealed.back() ^= 0x01; // last byte is inside the GCM tag
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(sealed, key), std::runtime_error);
    }

    TEST(AesTest, FlippedCiphertextBitIsRejected)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x44);
        auto sealed = crypto::AESEngine::encrypt_string("a much longer secret message", key);

        sealed[crypto::AESEngine::IV_SIZE + 2] ^= 0x01;
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(sealed, key), std::runtime_error);
    }

    TEST(AesTest, TruncatedPayloadIsRejected)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x55);
        auto sealed = crypto::AESEngine::encrypt_string("secret", key);

        sealed.resize(sealed.size() - 4);
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(sealed, key), std::runtime_error);

        const std::vector<uint8_t> far_too_short(4, 0x00);
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(far_too_short, key), std::runtime_error);
    }

    TEST(AesTest, RepeatedEncryptionUsesAFreshIv)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x66);

        const auto first  = crypto::AESEngine::encrypt_string("same text", key);
        const auto second = crypto::AESEngine::encrypt_string("same text", key);

        // GCM is catastrophically broken by IV reuse; identical plaintext must
        // still produce different bytes.
        EXPECT_NE(first, second);
        EXPECT_NE(std::vector<uint8_t>(first.begin(), first.begin() + crypto::AESEngine::IV_SIZE),
                  std::vector<uint8_t>(second.begin(), second.begin() + crypto::AESEngine::IV_SIZE));
    }

    TEST(AesTest, MismatchedAadIsRejected)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x77);
        const std::vector<uint8_t> aad{'c', 't', 'x', '1'};
        const std::vector<uint8_t> other_aad{'c', 't', 'x', '2'};

        const auto sealed = crypto::AESEngine::encrypt_string("secret", key, aad);
        EXPECT_EQ(crypto::AESEngine::decrypt_string(sealed, key, aad), "secret");
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(sealed, key, other_aad), std::runtime_error);
    }

    TEST(AesTest, WrongKeySizeIsRejected)
    {
        const std::vector<uint8_t> short_key(16, 0x88);
        EXPECT_THROW((void)crypto::AESEngine::encrypt_string("secret", short_key), std::runtime_error);
    }

    TEST(AesTest, HkdfIsDeterministicAndSaltDependent)
    {
        const std::vector<uint8_t> ikm(32, 0x99);
        const std::vector<uint8_t> salt_a(16, 0x01);
        const std::vector<uint8_t> salt_b(16, 0x02);
        const std::string info = "srp-chat/aes-256-gcm/v1";

        const auto key_a1 = crypto::AESEngine::derive_key(ikm, salt_a, info);
        const auto key_a2 = crypto::AESEngine::derive_key(ikm, salt_a, info);
        const auto key_b  = crypto::AESEngine::derive_key(ikm, salt_b, info);

        EXPECT_EQ(key_a1.size(), crypto::AESEngine::KEY_SIZE);
        EXPECT_EQ(key_a1, key_a2);
        EXPECT_NE(key_a1, key_b);
        EXPECT_NE(key_a1, crypto::AESEngine::derive_key(ikm, salt_a, "different-info"));
    }
```

- [ ] **Step 3: Run the tests**

Run: `cmake --build --preset debug && ctest --preset debug -R AesTest`
Expected: every case passes. If `MismatchedAadIsRejected` fails, that is a real defect in
`AESEngine::decrypt` — the AAD is fed in before the tag is set, which is correct, so investigate
rather than deleting the test.

- [ ] **Step 4: Run the full suite under the sanitizer**

Run: `cmake --build --preset asan && ctest --preset asan`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add tests/aes_tests.cpp
git commit -m "test: cover aead tamper detection and key derivation"
```

---

## Task 13: README

**Files:**
- Create: `README.md`

**Interfaces:** none. Documentation only.

- [ ] **Step 1: Gather the facts the README must state correctly**

Run these and use the real output rather than writing from memory:

```bash
./build/debug/chat_server --help
./build/debug/chat_client --help
ctest --preset debug -N | tail -3
```

- [ ] **Step 2: Write `README.md`**

Cover these sections in this order. Prose should be plain and short; no marketing language.

1. **Title and one-line description.** An SRP-6a authenticated chat server and client in C++20, with AES-256-GCM message encryption.

2. **Threat model** — the most important section, stated plainly:
   - The password never leaves the client. The server stores only a salt and a verifier, so a stolen database does not directly yield passwords, though it is offline-attackable against weak ones.
   - Authentication is mutual: the client proves knowledge of the password with `M`, the server proves it with `H_AMK`. An attacker who intercepts the handshake learns neither.
   - The AES key is derived independently on both sides from the SRP shared secret and is never transmitted.
   - **This is not end-to-end encryption.** The server decrypts each message and re-encrypts it per recipient. A compromised server sees all plaintext. Say so explicitly.
   - Not covered: transport metadata (who talks to whom, when, how much), denial of service beyond the built-in caps, and a malicious server.

3. **Requirements** — a C++20 compiler (GCC 13+, Clang 16+, MSVC 19.3+), CMake ≥3.25, Ninja, and vcpkg with `VCPKG_ROOT` set.

4. **Build** — the preset commands verbatim:
   ```bash
   cmake --preset release
   cmake --build --preset release
   ```
   and for development, the `debug` preset plus `ctest --preset debug`, and the `asan` preset.

5. **Run** — start the server, register two users, chat. Use the real flags from Step 1.

6. **Flag reference** — two tables, server and client, copied from `--help`.

7. **Protocol** — the handshake as a message sequence, showing that `SRP_SUCCESS` carries only `H_AMK_b64`, and the derivation on both sides:
   ```
   K   = SHA256(S)
   key = HKDF-SHA256(K, salt = room_salt, info = "srp-chat/aes-256-gcm/v1", 32 bytes)
   ```
   Also document the frame layout: 2-byte little-endian type, 4-byte little-endian length, then payload; and the limits table from the Global Constraints section of this plan.

8. **Credential storage** — the `users.db` format, `0600` permissions, atomic replace via `.tmp` and rename, and that the file is gitignored.

9. **Testing** — the suite names and how to run one (`ctest --preset debug -R SrpTest`).

10. **Limitations** — copy the Non-goals list from the spec: no TLS, no Docker or CI, flat-file database, no client reconnect, no per-IP registration rate limiting, not end-to-end encrypted.

11. **Layout** — a short tree of `include/chat/{common,auth,crypto,server,client}` and `src/` with one line per component.

- [ ] **Step 3: Verify every command in the README actually runs**

Execute each command block from a clean checkout in a scratch directory. Any command that fails or
whose output contradicts the README is a documentation bug — fix the README, not the reader's
expectations.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add readme"
```

---

## Final verification

- [ ] Run `cmake --preset release && cmake --build --preset release` from a clean `build/` — both binaries link with tests disabled.
- [ ] Run `cmake --preset debug && cmake --build --preset debug && ctest --preset debug` — every suite passes.
- [ ] Run `cmake --preset asan && cmake --build --preset asan && ctest --preset asan` — clean.
- [ ] Run `grep -rn "session_key_b64\|SRP_USER_NOT_FOUND\|ConnectionManager\|system(\"cl" include/ src/` — no hits.
- [ ] Run `git log --oneline -13` — thirteen commits, none with a `Co-Authored-By` or "Generated with" trailer.
- [ ] Run `git status` — clean tree, and `users.db` is absent from `git ls-files`.
- [ ] Confirm nothing was pushed: `git status -sb` shows the branch ahead of its remote, or no remote at all.

