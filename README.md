# srp-chat-cpp

An SRP-6a authenticated chat server and client in C++20, with AES-256-GCM message encryption.

## Threat model

- **The password never leaves the client.** The server stores only a salt and a
  verifier per user (`v = g^x mod N`, where `x` is derived from the salt and
  password). A stolen database does not directly yield passwords, though the
  verifiers are offline-attackable against weak passwords — SRP does not
  change that.
- **Authentication is mutual.** The client proves knowledge of the password
  with `M`; the server proves it holds the matching verifier with `H_AMK`. An
  attacker who intercepts the handshake learns neither the password nor the
  session key.
- **The AES-256-GCM session key is derived independently on both sides** from
  the SRP shared secret `S` and is never transmitted on the wire.
- **This is not end-to-end encryption.** The server decrypts each message and
  re-encrypts it per recipient with that recipient's session key. A
  compromised server sees all plaintext.
- **Not covered:** transport metadata (who talks to whom, when, how much),
  denial of service beyond the built-in caps (connection limits, message
  size, handshake/idle timeouts, auth-attempt budget), and a malicious
  server.

## Requirements

- A C++20 compiler (GCC 13+, Clang 16+, MSVC 19.3+)
- CMake >= 3.25
- Ninja
- vcpkg, with `VCPKG_ROOT` set in the environment

## Build

```bash
cmake --preset release
cmake --build --preset release
```

For development, use the `debug` preset (builds the test suite) and run it
with ctest:

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

There is also an `asan` preset (debug + AddressSanitizer/UBSan) for catching
memory and undefined-behavior bugs:

```bash
cmake --preset asan
cmake --build --preset asan
ctest --preset asan
```

## Run

Start the server:

```bash
./build/release/chat_server --port 8888
```

Register and log in as a first user (client prompts for a password twice on
`--register`, then authenticates and joins):

```bash
./build/release/chat_client --user alice --register --host localhost --port 8888
```

In a second terminal, register a second user and chat:

```bash
./build/release/chat_client --user bob --register --host localhost --port 8888
```

Once logged in, type a line and press Enter to broadcast it to the room. Type
`/help` inside the client for available commands.

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

## Flag reference

### `chat_server`

```
Usage: chat_server [options]

  --port <n>               Listen port (default 8888, range 1024-65535)
  --users-db <path>        Credential database (default users.db)
  --max-connections <n>    Concurrent connection cap (default 256)
  --max-rooms <n>          Room cap, lobby included (default 64)
  --max-room-members <n>   Members per room (default 64)
  --handshake-timeout <s>  Seconds to complete authentication (default 30)
  --idle-timeout <s>       Seconds of silence before disconnect (default 120)
  --help                   Show this message
```

### `chat_client`

```
Usage: chat_client --user <name> [options]

  --user <name>   Username, 1-32 chars of [A-Za-z0-9_-] (required)
  --host <host>   Server host (default localhost)
  --port <n>      Server port (default 8888)
  --register      Create the account before logging in
  --help          Show this message
```

## Protocol

The handshake, as a message sequence (client `C`, server `S`):

```
Registration (only with --register):
  C -> S   SRP_REGISTER      { username, salt_b64, verifier_b64 }
  S -> C   SRP_REGISTER_ACK  (or ERROR_MSG on failure, e.g. duplicate user)

Authentication:
  C -> S   SRP_INIT          { protocol_version, username, A_b64 }
  S -> C   SRP_CHALLENGE     { user_id, B_b64, salt_b64, room_salt_b64 }
  C -> S   SRP_RESPONSE      { user_id, M_b64 }
  S -> C   SRP_SUCCESS       { H_AMK_b64 }      -- and nothing else
  S -> C   INIT              { room, messages, users }
```

`SRP_SUCCESS` deliberately carries only `H_AMK_b64` — the server's proof that
it holds the matching verifier — never a session key or any other secret.
Each side derives the AES-256-GCM key independently:

```
K   = SHA256(S)                                             -- S = SRP shared secret
key = HKDF-SHA256(K, salt = room_salt, info = "srp-chat/aes-256-gcm/v1", 32 bytes)
```

The server retries a rejected proof up to 3 times per connection (a fresh
server ephemeral `B` each attempt), sending `ERROR_MSG` and a new
`SRP_CHALLENGE` on each rejection. The current client does not use that
budget: on the first `ERROR_MSG` in place of `SRP_SUCCESS` it throws and
disconnects rather than retrying the handshake.

### Frame layout

Every message on the wire is a 6-byte header followed by a payload, all
integers little-endian:

| Field  | Size    | Meaning                    |
|--------|---------|-----------------------------|
| type   | 2 bytes | `MessageType`               |
| size   | 4 bytes | payload length in bytes     |
| payload| `size` bytes | message-specific fields |

### Limits

| Limit                     | Value          |
|----------------------------|---------------|
| Max payload size            | 1 MiB (1,048,576 bytes) |
| Max string length (decode)  | 65,536 bytes  |
| Max vector element count (decode) | 1,024   |
| Max username length         | 32 characters |
| Username charset            | `[A-Za-z0-9_-]` |
| Max chat message length     | 4,096 characters |

## Credential storage

Credentials live in a flat text file (`users.db` by default, set with
`--users-db`), one line per user:

```
# SRP User Database
# Format: username:salt_hex:verifier_hex
alice:c201b2d282c53cc94acd45402d485d37:a18ce928e6...
```

No passwords are ever written — only the random salt and the SRP verifier,
both hex-encoded. Writes are atomic: the server writes to `users.db.tmp`,
`chmod`s it `0600` (owner read/write only, POSIX only), then renames it over
`users.db`, so a crash mid-write cannot corrupt the existing database.
`users.db` and `users.db.tmp` are gitignored.

## Testing

Test suites (run with `ctest --preset debug`, 129 tests total):

- `AesTest`, `AESEngineTest` — AES-256-GCM encryption and HKDF key derivation
- `CliTest` — command-line flag parsing
- `OnlineUsersTest` — server-wide username claim/release tracking
- `ProtocolTest` — message encode/decode
- `RoomTest` — chat room membership and broadcast
- `RoomManagerTest` — room creation, joining, capacity/name limits, lobby lifecycle
- `RoomNameTest` — room name validation and case-insensitive key normalization
- `SrpTest` — SRP-6a client/server key exchange
- `TypesTest` — core message/user structs
- `UserStoreTest` — credential storage, atomic save, malformed-input handling
- `WireTest` — low-level buffer read/write, header framing, decode limits

Run a single suite:

```bash
ctest --preset debug -R SrpTest
```

## Limitations

- No TLS. The connection is plaintext at the transport layer; only the SRP
  handshake and per-message AES-GCM payloads are protected.
- No Docker image or CI pipeline.
- Flat-file database (`users.db`); no concurrent-writer safety beyond the
  process-local mutex, no replication, no external DB.
- No client reconnect: a dropped connection ends the session.
- No per-IP registration rate limiting.
- Not end-to-end encrypted — see Threat model above.
- **Protocol version 2.** A version-1 client is rejected at the handshake with a
  clear message rather than failing obscurely later.
- `room_salt` (used to derive the AES room key via HKDF) is sent unauthenticated
  in the `SRP_CHALLENGE`; an active on-path attacker (already a conceded
  capability given no TLS) can tamper with it to desync the client's and
  server's independently-derived keys. This causes decrypt failures, not a
  confidentiality break — the attacker gains no key material. Not defended
  against in this version.
- Registering with an already-taken username reveals that the account exists
  (the server must say so to refuse the registration). This is inherent to
  self-service registration and not separately mitigated (no rate limiting,
  as noted above).

## Layout

```
include/chat/
  common/   wire format (buffer.hpp, protocol.hpp), message structs, CLI parsing, logging
  auth/     SRP-6a client/server state machines, user credential store, base64/hex utils
  crypto/   AES-256-GCM engine and HKDF-SHA256 key derivation
  server/   connection session, room (broadcast/membership), room manager, online users tracking (online_users.hpp), server entry point
  client/   client state machine, terminal UI helpers
src/
  common/   buffer.cpp, cli.cpp
  auth/     srp_client.cpp, srp_server.cpp, srp_utils.cpp, user_store.cpp
  crypto/   aes_engine.cpp
  server/   server.cpp, session.cpp, session_rooms.cpp, room.cpp, room_manager.cpp, main.cpp
  client/   client.cpp, terminal.cpp, main.cpp
```
