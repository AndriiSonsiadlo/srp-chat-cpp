# SRP Chat — Production Hardening Design

**Date:** 2026-08-07
**Status:** Approved
**Scope:** Security correctness, reliability, build/packaging, documentation. No new subsystems.

## Problem

The repository implements an SRP-6a authenticated chat over TCP with AES-256-GCM message
encryption. The cryptography is currently non-functional in the security sense: the AES key is
generated randomly by the server and transmitted to the client in cleartext, so a passive network
observer can decrypt every message. Several supporting defects (missing SRP safety checks,
plaintext message history, username enumeration, data races, unbounded thread and session growth)
make the system unsuitable for deployment.

This document specifies the changes that make the system correct, bounded, and operable.

## Goals

1. The AES key is never transmitted. Both peers derive it from the SRP shared secret.
2. No plaintext chat content crosses the wire or reaches server logs.
3. The SRP implementation performs the safety checks required by RFC 5054 / SRP-6a.
4. Every resource the server allocates on behalf of a client is bounded and reclaimed.
5. The wire format is deterministic across platforms and rejects malformed input.
6. Both binaries are configurable by flags, build from a vcpkg manifest, and are documented.

## Non-goals

Explicitly out of scope for this pass, each a clean follow-up:

- TLS transport (SRP is already MITM-resistant; payloads are AES-GCM; TLS would protect metadata).
- Docker images and CI workflows.
- Replacing the flat-file user database with a real database.
- Protocol magic bytes for wrong-port detection.
- Client reconnect with backoff.
- Per-IP registration rate limiting.
- End-to-end encryption in which the server never sees plaintext.

---

## 1. Key agreement

### Current behavior (defect)

`SRPServer::verify_authentication` (`src/auth/srp_server.cpp:214`) generates
`SRPUtils::random_bytes(32)`, base64-encodes it, and returns it as `VerifyResponse::session_key`.
`Server::handle_srp_authentication` (`src/server/server.cpp:127`) sends it to the client inside
`SRP_SUCCESS`. The SRP shared secret `K` is computed and discarded. The transmitted key is the
AES-256-GCM key used for all subsequent messages.

Both sides then run the transmitted value through a nonsensical double decode — bytes to
`std::string` to `base64_to_bytes` (`src/server/server.cpp:137`, `src/client/client.cpp:383`) —
which happens to work only because the server sent base64 text as raw bytes.

### Required behavior

`SrpSuccessMsg` carries only `H_AMK_b64`. `VerifyResponse` carries only `H_AMK`. Both peers derive
the key independently:

```
K   = SHA256(S)                                              // already computed on both sides
key = HKDF-SHA256(ikm = K,
                  salt = room_salt,
                  info = "srp-chat/aes-256-gcm/v1",
                  len  = 32)
```

`room_salt` is generated once per server process, is already sent to the client in `SRP_CHALLENGE`,
and is currently discarded by the client at `src/client/client.cpp:382`. It becomes the HKDF salt.
Because `K` differs per user, each connection derives a distinct key; the server continues to
decrypt on receive and re-encrypt per recipient on broadcast.

`AESEngine::derive_key` already implements this HKDF and is currently unreferenced. It is reused
as-is. No new cryptographic primitive is written.

Both decode hacks are deleted.

### Key material lifetime

Derived keys and the password buffer are wiped with `OPENSSL_cleanse` when their owner is
destroyed. `SRPClient` takes the password by value rather than holding a raw `std::string*`
(`include/chat/auth/srp_client.hpp`), removing a dangling-pointer hazard.

---

## 2. Protocol

The changes below are breaking. A version gate makes the break explicit rather than silent.

### Version negotiation

`SrpInitMsg` gains a leading `uint16_t protocol_version`. The server compares it against
`kProtocolVersion` and, on mismatch, replies with `ERROR_MSG` naming both versions and closes.

### Encrypted, timestamped history

`Message::as_tuple` (`include/chat/common/types.hpp:61`) omits `timestamp`, so history timestamps
are meaningless after a client joins. `InitMsg` (`include/chat/common/messages.hpp:26`) serializes
`Message` directly, so history text crosses the wire as plaintext.

Both are fixed by one change: the wire representation of a history entry becomes

```
HistoryEntry { std::string username; std::string ciphertext_b64; int64_t timestamp_ms; }
```

encrypted with the receiving client's derived key at the moment `INIT` is built. This mirrors
`BroadcastMsg`. The in-memory `Message` type keeps its `time_point` and is no longer serialized
directly.

### Username enumeration

`SRP_USER_NOT_FOUND` is removed from `MessageType`. When `init_authentication` is called for an
unknown username, the server returns a challenge built from a deterministic fake credential:

```
fake_salt     = HMAC-SHA256(server_secret, "salt:"     || username)[0..16]
fake_verifier = HMAC-SHA256(server_secret, "verifier:" || username)  interpreted as a BigNum mod N
```

`server_secret` is 32 random bytes generated at process start and never persisted or transmitted.
The handshake then proceeds normally and fails at `M` verification, matching the shape and
approximate timing of a wrong-password attempt. Determinism matters: repeated probes for the same
unknown username must yield the same salt, exactly as a real account would.

### Explicit registration

The client no longer prompts `"User not found. Register? (y/n)"` in the middle of a handshake
(`src/client/client.cpp:301`). Registration is requested up front with `chat_client --register`,
which sends `SRP_REGISTER`, awaits `SRP_REGISTER_ACK`, and then authenticates normally. Without the
flag, an unknown username produces an authentication failure.

Registration remains inherently enumerating: `SRP_REGISTER` for a taken username must be refused,
which confirms the username exists. This is accepted. The point of the fake-challenge change is
that the *authentication* path, which is unauthenticated and unlimited, stops being an oracle.

### Deterministic encoding

`MsgHeader` is currently `memcpy`-ed as a packed struct (`include/chat/common/types.hpp:10`,
`include/chat/common/protocol.hpp:125`), and `BufferWriter::write<T>` `memcpy`-s host-order
integers (`include/chat/common/buffer.hpp:17`). The wire format is therefore host-endianness
dependent.

All integers are encoded explicitly little-endian, byte by byte, on both read and write.
`MsgHeader` is serialized field by field rather than as a struct image. The `#pragma pack` block is
removed. Field order and sizes are unchanged, so the format is identical on the little-endian
platforms in use today; the change removes the latent portability defect.

### Input limits

Enforced during deserialization, before any allocation:

| Limit | Value |
| --- | --- |
| Payload size | 1 MiB (existing `kMaxPayloadSize`) |
| String field length | 64 KiB |
| Vector element count | 1024 |
| Message text | 4 KiB |
| Username | 32 chars, `[A-Za-z0-9_-]` |

The vector-count limit closes a concrete defect: `Protocol::read_field` for `std::vector<T>`
(`include/chat/common/protocol.hpp:72`) calls `result.reserve(count)` with an attacker-supplied
`uint32_t`, allowing a ~4-billion-element reservation from a 4-byte input.

---

## 3. Server concurrency

### Current behavior (defect)

`Server::start_accept` (`src/server/server.cpp:239`) spawns a detached `std::thread` per accepted
connection with no cap, no timeout, and no shutdown join. `ConnectionManager::broadcast` and
`send_to` (`src/server/connection_manager.cpp:79`, `:93`) perform blocking socket writes while
holding `mutex_`, so a single slow reader stalls every other client.

### Required design

Boost.Asio C++20 coroutines (`awaitable`, `co_spawn`, `use_awaitable`) replace the thread model.

**`chat::server::Session`** — one per connection, `enable_shared_from_this`. Owns the socket and a
write queue serialized on a strand, so broadcasts never block the caller and concurrent writers
never interleave frames. Exposes `send(packet)` (enqueue, return immediately). The handshake and
the message loop are coroutines.

**`chat::server::Room`** — replaces `ConnectionManager`. Owns the session table, the per-user
derived keys, and history in a `std::deque` (replacing `message_history_.erase(begin())`, which is
O(n) on a `std::vector` at `src/server/server.cpp:326`). `broadcast` enqueues to each session under
the lock and returns; no socket I/O occurs under a mutex.

**`chat::server::Server`** — acceptor coroutine plus an `io_context` run by a thread pool sized to
`std::thread::hardware_concurrency()`. Shutdown is driven by `boost::asio::signal_set`, which
delivers the signal on the io_context rather than in a signal handler: the current
`src/server/main.cpp:14` calls `exit(0)` from a handler, which is not async-signal-safe and skips
`~Server`, so `save_users` never runs on Ctrl-C. The new path stops the acceptor, closes sessions,
saves the user database, and returns from `main`.

### Bounds

| Bound | Default | Flag |
| --- | --- | --- |
| Max concurrent connections | 256 | `--max-connections` |
| Handshake timeout | 30 s | `--handshake-timeout` |
| Idle read watchdog | 120 s | `--idle-timeout` |
| Auth attempts per connection | 3 | fixed |

Each bound is enforced by a `steady_timer` raced against the corresponding coroutine. Exceeding the
connection cap closes the new socket immediately with an `ERROR_MSG`.

---

## 4. SRP hardening

### Safety checks

| Check | Side | Action on failure |
| --- | --- | --- |
| `A mod N == 0` | Server | Abort handshake |
| `B mod N == 0` | Client | Abort handshake |
| `u == 0` | Both | Abort handshake |

None of these exist today. Their absence permits an attacker to force a predictable shared secret.

### Session identity

`SRPSession` (`include/chat/auth/srp_types.hpp:30`) gains a `username` field, populated in
`init_authentication`. This deletes the lookup at `src/auth/srp_server.cpp:183`, which recovers the
username by scanning every stored credential for a matching salt — wrong under salt collision and
linear in user count on every authentication.

### Other defects

- `generate_user_id` (`src/auth/srp_server.cpp:248`) uses `std::mt19937` seeded from
  `std::random_device` and emits 8 hex nibbles: 32 bits, predictable, collision-prone, and used as
  the session key in `sessions_`. Replaced with 16 bytes from `RAND_bytes`, hex-encoded.
- `init_authentication` returns `sessions_[user_id].B` (`src/auth/srp_server.cpp:142`) after
  releasing `sessions_mutex_` — a data race, and a second unsynchronized map lookup. The local
  `session.B` is used instead.
- Proof comparisons in `SRPServer::verify_authentication` and `SRPClient::verify_server` use
  hand-rolled XOR loops. Replaced with `CRYPTO_memcmp`.
- `BN_CTX` is allocated and freed manually on every error path across `src/auth/srp_utils.cpp`
  (roughly 30 lines of duplicated cleanup). An RAII wrapper replaces it.
- `clear_expired_sessions` (`src/auth/srp_server.cpp:242`) is an empty stub with an unused
  parameter. Sessions gain a creation timestamp, are swept by a periodic timer, and are cleared on
  disconnect — `clear_session` is currently never called from anywhere.

### Error disclosure

`src/server/server.cpp:120` sends `"Authentication failed: " + e.what()` to the client, leaking
internal state. Clients receive fixed generic strings; detail goes to the server log only.

---

## 5. `UserStore`

`SRPServer` currently owns both credential persistence and live protocol state. Persistence moves
to a `chat::auth::UserStore` with a narrow interface: `load`, `save`, `find`, `insert`, `contains`.

- Saves atomically: write to `<path>.tmp`, `fsync`, `rename` over the target. The current
  `save_users` (`src/auth/srp_server.cpp:79`) truncates the live file before writing, so a crash
  mid-write destroys the database.
- Creates the file with mode `0600`.
- Skips malformed lines rather than silently producing partial credentials.
- Rejects usernames containing `:` or a newline at registration — the flat format is
  colon-delimited, so such a username corrupts the file and can forge another user's record.
- Path configurable via `--users-db`, defaulting to `users.db`.

The flat `username:salt_hex:verifier_hex` format is retained. It works, it is greppable, and
replacing it is a non-goal.

---

## 6. Client

- Password read with terminal echo disabled (`termios` on POSIX, `SetConsoleMode` on Windows),
  confirmed on registration, cleansed after use. Currently `std::getline` echoes the password
  (`src/client/client.cpp:346`, `:420`).
- Flags with defaults replace positional `argc == 4`: `--host` (default `localhost`), `--port`
  (default `8888`), `--user`, `--register`, `--help`. The server likewise gains `--port`,
  `--users-db`, `--max-connections`, and the timeout flags in place of positional `argc == 2`.
- `system("clear")` (`src/client/client.cpp:498`) is replaced with ANSI escapes; the fixed
  80-column blanking (`std::string(80, ' ')`, `src/client/client.cpp:203` and elsewhere) becomes
  `\033[2K`. Colour is suppressed when `NO_COLOR` is set or stdout is not a TTY.
- Receiving becomes an `awaitable` coroutine on the `io_context`. Stdin remains a blocking read on
  its own thread that posts work into the `io_context`. This fixes the race in which `disconnect()`
  (`src/client/client.cpp:107`) closes the socket while the receive thread is blocked reading it.
  Fully asynchronous stdin is not worth the complexity and is not attempted.

## 7. Logging

A small `chat::log` header — timestamped `info` / `warn` / `error` to stderr. No new dependency.

The server currently prints every decrypted message to stdout (`src/server/server.cpp:317`),
writing the plaintext it was entrusted with to the operator's terminal and any capturing log
system. It logs username and ciphertext length instead.

## 8. Build and packaging

`vcpkg.json` manifest declaring `boost-asio`, `boost-system`, and `openssl`, with `gtest` behind a
`tests` feature so a plain release build does not fetch it. Pinned with a `builtin-baseline`.

`CMakePresets.json` wiring the vcpkg toolchain, with `debug`, `release`, and `asan` presets. The
`debug` and `asan` presets enable the `tests` feature and `BUILD_TESTS`; `release` does not, and is
the configuration used to ship binaries.

`CMakeLists.txt`:

- `cmake_minimum_required` 4.0.0 → 3.25 (presets v6; 4.0.0 needlessly excludes current toolchains).
- Global `include_directories` → per-target `target_include_directories`.
- `-Wshadow` added to the existing `-Wall -Wextra -Wpedantic`.
- `-Werror` behind a `CHAT_WERROR` option, off by default.
- `users.db` and `users.db.tmp` added to `.gitignore`.

## 9. Tests

New:

- `srp_tests` — full in-process client/server handshake; wrong password rejected; `A ≡ 0` rejected;
  `B ≡ 0` rejected; both sides derive byte-identical keys; `H_AMK` verifies; unknown username
  yields a challenge and fails at `M` (no distinguishable enumeration signal).
- `wire_tests` — little-endian round-trip for every field type; truncated payload rejected;
  oversized string length rejected; oversized vector count rejected without a large allocation.
- `user_store_tests` — save/load round-trip; malformed line skipped; atomic replace leaves the
  original intact on failure; username containing `:` rejected.

Extended:

- `aes_tests` — wrong key, truncated ciphertext, and flipped authentication tag all fail closed.

Updated:

- `protocol_tests`, `types_tests`, and `connection_manager_tests` follow the new `Room` API and the
  new history entry type.

## 10. README

`README.md` covering: what the project is and its threat model (including the explicit statement
that the server sees plaintext and this is not end-to-end encryption); build via vcpkg and presets;
running server and client; the flag reference; the protocol and handshake described as a message
sequence; the on-disk credential format; running the tests; and the known limitations listed under
Non-goals.

## 11. Delivery

Thirteen commits, none pushed, messages concise, no co-author or generation trailers:

1. `build: add vcpkg manifest and cmake presets`
2. `refactor(wire): explicit little-endian framing and payload limits`
3. `fix(auth): derive session key from SRP shared secret`
4. `fix(auth): add SRP-6a safety checks and constant-time compares`
5. `refactor(auth): extract user store with atomic writes`
6. `fix(auth): remove username enumeration oracle`
7. `refactor(server): async coroutine session and room`
8. `feat(server): connection limits, timeouts, graceful shutdown`
9. `fix(protocol): encrypt message history and preserve timestamps`
10. `refactor(client): async receive loop and terminal handling`
11. `feat(cli): flag-based configuration`
12. `test: cover srp handshake, wire framing, user store`
13. `docs: add readme`

Each commit builds and leaves the test suite green.

## Success criteria

1. No key material appears in any packet. Verifiable by inspecting `SrpSuccessMsg`, which carries
   only `H_AMK_b64`.
2. `srp_tests` asserts that client and server derive byte-identical keys without exchanging them.
3. No plaintext message content appears in any packet or in server logs.
4. The three SRP safety checks are covered by tests that fail without them.
5. A malformed or hostile packet closes one connection and leaves the server serving others.
6. `SIGINT` saves the user database and exits cleanly with no leaked sessions.
7. From a clean clone with only vcpkg and a C++20 compiler present,
   `cmake --preset release && cmake --build --preset release` produces both binaries, and
   `cmake --preset debug && cmake --build --preset debug && ctest --preset debug` passes.
8. The `asan` preset runs the suite clean.
