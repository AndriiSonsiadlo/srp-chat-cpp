# SRP Chat — Multi-Room Chat Design

**Date:** 2026-08-10
**Status:** Approved
**Scope:** Server-side room subsystem, protocol extension, minimal client command surface. No UI rewrite.

## Problem

The server owns a single `Room`. Every authenticated user is placed in it at the end of the
handshake and there is no way to be anywhere else — the protocol has no concept of a room, so
there is nothing for a client to name, list, or join. `SrpChallengeMsg::room_salt_b64` is a
misnomer: it salts the per-user session key derivation and has nothing to do with rooms.

This document specifies multiple named rooms, optionally password-protected, created on demand by
any authenticated user.

## Goals

1. Any authenticated user can create a room, join a room, and list the rooms that exist.
2. A room may be public or password-protected. The room password never crosses the wire in
   the clear.
3. A user is in exactly one room at a time; message traffic and presence events are scoped to
   that room.
4. Room state is bounded: a room dies when its last member leaves, and both the room count and
   per-room membership are capped.
5. An account still cannot be logged in twice, which today is an accidental property of the
   single room.

## Non-goals

Each a clean follow-up, deliberately excluded:

- **The curses/PDCurses TUI.** It is the next spec and depends on this one for the data it
  renders (room list, per-room roster). Filtering, themes, and layout belong there.
- Simultaneous membership in several rooms (IRC-style).
- Room persistence across server restart. Rooms are in-memory and ephemeral.
- Room ownership, moderation, kick/ban, invitations.
- End-to-end encryption within a room. The server continues to decrypt and re-encrypt per
  recipient, as documented in the README threat model.
- Rate limiting on room operations. See "Accepted risks".

---

## Architecture

### Component changes

**`RoomManager` — new** (`include/chat/server/room_manager.hpp`, `src/server/room_manager.cpp`).
Owns `std::unordered_map<std::string, std::shared_ptr<Room>>` keyed by the lowercased room name,
guarded by one mutex. Responsible for lifecycle only:

```
std::shared_ptr<Room> find(name) const;
JoinResult  join(name, password, user_id, username, sink, key);
JoinResult  create_and_join(name, password, user_id, username, sink, key);
std::vector<RoomInfo> list() const;
void        drop_if_empty(name);
```

`JoinResult` carries a status enum (`Ok`, `NoSuchRoom`, `WrongPassword`, `PasswordRequired`,
`RoomFull`, `NameTaken`, `TooManyRooms`) and, on success, the room.

The manager pins `lobby` at construction: it always exists, is always passwordless, and
`drop_if_empty` never removes it. Login joins it, `/leave` returns to it.

**`Room` — modified.** Gains its display name (the creator's casing), a 16-byte random salt, and
the HMAC of its password, plus `has_password()`, `verify_password()`, and `name()`. It **loses**
the duplicate-username check inside `try_join`, which becomes a plain `join`. The member cap is
not a `Room` concern: the manager owns the limit and compares it against the existing `size()`
inside the same critical section as the join. Members, the history deque, per-recipient sealing, `broadcast_packet`, and
`init_packet_for` are unchanged.

**`OnlineUsers` — new**, a small standalone class (`unordered_set<std::string>` + mutex,
`try_claim` / `release`). This is where `Room`'s duplicate-username check goes. With many rooms
that check is meaningless inside a room — alice in `lobby` and alice in `dev` would both succeed —
so it moves up to a server-wide registry claimed in `finish_login` and released in the disconnect
cleanup path. It is a separate class rather than members on `Server` because `Server` requires an
`io_context` and a bound acceptor to construct, which would make the logic untestable.

**`Server` — modified.** Holds a `RoomManager` and an `OnlineUsers` in place of the single
`room()` accessor. Carries the two new caps from the CLI.

**`Session` — modified.** Gains `std::shared_ptr<Room> room_` and a stored `key_`. Today the
session key is derived twice — once in `finish_login`, once at the top of `message_loop`. Joining
a room needs it again, so it is derived once at login and kept. Adds handlers for the four new
message types. `session.cpp` is 412 lines; if the room handlers push it past ~500, they move to
`src/server/session_rooms.cpp`.

### Rejected alternatives

**Partitioning inside the existing single `Room`** (a room field on each member and history item,
filtered on fan-out). Same amount of work, worse boundaries: every method grows a filter argument,
one history deque needs per-room trimming, and the class acquires a second responsibility.

**A strand per room, no mutex.** The right answer at thousands of rooms. Here it buys nothing over
a mutex held for microseconds and complicates object lifetime.

---

## Protocol

`kProtocolVersion` goes to 2. Old clients get the existing clean version-mismatch rejection.

Four message types appended to `MessageType` (existing values keep their numbers):

| Type | Direction | Payload |
|---|---|---|
| `ROOM_LIST_REQ` | client → server | empty |
| `ROOM_LIST` | server → client | `RoomListMsg { vector<RoomInfo> rooms }` |
| `ROOM_CREATE` | client → server | `RoomCreateMsg { string name; string password_ct_b64; }` |
| `ROOM_JOIN` | client → server | `RoomJoinMsg { string name; string password_ct_b64; }` |

```cpp
// include/chat/common/messages.hpp, alongside the other wire structs
struct RoomInfo {
    std::string name;       // creator's casing
    uint32_t    user_count;
    uint8_t     has_password;
};
```

A vector of structs already round-trips through `Protocol::write_field` / `read_field`; no
serializer work is required.

`InitMsg` gains a leading `std::string room` field. Two omissions are deliberate:

- **No `ROOM_LEAVE`.** `/leave` is client-side sugar for `ROOM_JOIN{"lobby", ""}`.
- **No `ROOM_JOINED`.** The existing INIT packet — history sealed per recipient, plus the roster —
  already answers both create and join, and now names the room.

An empty `password_ct_b64` means a public room (on create) or no password supplied (on join).

### Room password on the wire

There is no encrypted tunnel: protocol frames are plaintext TCP, and only `TextMsg::ciphertext_b64`
is sealed. The room password is therefore sealed exactly the way message text is — AES-256-GCM
under the joiner's SRP session key — with **AAD set to the room name**. The AAD binds a sealed
password blob to the room it was minted for, so a `ROOM_JOIN` captured on the wire cannot be
replayed against a different room. The AAD is the name **exactly as it appears in the same
message's `name` field**, not the room's stored display casing — the client cannot know the latter,
and any mismatch would fail the GCM tag. `ROOM_CREATE` seals the password it is setting the same
way.

The server verifies against a salted `HMAC-SHA256(room_salt, password)` compared with
`CRYPTO_memcmp`. PBKDF2 is deliberately **not** used here. Its value is resistance to offline
attack on a hash at rest, and this hash is never at rest: it lives in process memory, in a room
that ceases to exist when empty. An attacker who can read it already holds the session keys and
plaintext messages beside it. The additional cost would be real — verification happens under the
manager mutex, and 100k PBKDF2 rounds would hold the global room lock for ~50 ms per join, stalling
every other room operation. Account verifiers in `users.db` do hit disk and keep their full
treatment; this is the one difference between the two.

---

## Data flow

### Join

The client already knows `has_password` from the cached room list, so it prompts for the password
before sending. The server-side error is the fallback path.

1. `ROOM_JOIN{name, ct}` arrives. Validate the name; reject if it names the current room.
2. If `ct` is non-empty, decrypt under the session key with the room name as AAD, then validate
   the plaintext.
3. `RoomManager::join(...)` performs find, password check, capacity check, and `Room::join`
   **inside a single manager-mutex critical section**, returning a status and the room.
4. Outside the lock, the session then: broadcasts `USER_LEFT` to the old room, sends
   `init_packet_for(user_id)` to itself, broadcasts `USER_JOINED` to the new room, and calls
   `drop_if_empty(old_name)`.

Step 3 is one critical section on purpose. Splitting it into a `find()` followed by a `join()`
opens a window in which the room empties and is dropped between the two calls: the caller's
`shared_ptr` keeps the object alive, so the join succeeds into a room that is no longer in the map
and that nobody else can ever discover or join.

`ROOM_CREATE` follows the same flow through `create_and_join`, failing with `NameTaken` if the
lowercased name exists or `TooManyRooms` at the cap. Creation implies joining; requiring a
separate join would cost a round trip and could land the creator in someone else's room of the
same name.

### Lock ordering

The manager mutex may be acquired before a room mutex, never after. `Room` methods only enqueue on
sinks and perform no socket I/O, so the nested hold is microseconds.

### Messages and presence

`MessageType::MESSAGE` is handled against `room_` rather than the former single server room.
`USER_JOINED` and `USER_LEFT` fan out only within the room concerned.

### Disconnect

The existing cleanup block in `Session::run` extends to: leave the current room, broadcast
`USER_LEFT` to that room only, `drop_if_empty` on it, and `release_username`. It remains wrapped
in its try/catch — this coroutine is detached and an escaping exception would terminate the
process.

---

## Validation and limits

`is_valid_room_name`, mirroring `UserStore::is_valid_username`:

- 1–32 characters, `[A-Za-z0-9_-]` only.
- Uniqueness is case-insensitive: the manager keys on the lowercased name while `Room` retains the
  creator's casing for display. `Dev` and `dev` are the same room.

Room password, after decryption: 1–128 bytes, no control characters — the same `c < 0x20` rule
messages already get. The sealed blob is length-capped before decryption is attempted.

New CLI flags on `chat_server`, in the existing style and range-validated:

- `--max-rooms <n>` (default 64) — `ROOM_CREATE` fails with `TooManyRooms` at the cap.
- `--max-room-members <n>` (default 64) — join fails with `RoomFull`.

A session gets 5 wrong room-password attempts before it is closed, mirroring `kMaxAuthAttempts`.
Only `WrongPassword` spends from that budget. `PasswordRequired` — a join sent with no password to
a locked room — does not, since that is the ordinary first step when a client's cached room list is
stale.

---

## Error handling

Room errors do **not** close the connection. Today's `fail()` helper is paired with `co_return` on
the handshake path, where any failure is terminal. Unknown room, wrong password, password required,
room full, name taken, and "already in that room" instead send `ERROR_MSG` with a fixed string,
log the detail server-side, and leave the message loop running so the client can re-prompt.

Only two conditions still close a session: the exhausted room-password budget, and a malformed
frame (unchanged behavior).

Client-facing strings stay fixed and detail-free, as they are today; the reason lands in the log.

## Accepted risks

- **Room names and occupancy are visible to every logged-in user**, including for
  password-protected rooms, which are listed with their `has_password` flag set. Discovery is the
  point of the list, and every user is already an authenticated account holder.
- **No rate limiting** on `ROOM_LIST_REQ` or on room create/join churn. An authenticated client can
  already flood `MESSAGE` today; limiting one message type and not the others would be theater.
  The existing idle timeout, connection cap, and room caps bound the damage.
- **A room password is known to the server** in the instant it is verified. This is consistent with
  the documented threat model — the server decrypts every message anyway — but users should not
  reuse their account password as a room password. Worth a line in the README.

---

## Client changes

The client keeps its line-based stdout UI in this spec. The curses rewrite is the next one, and it
consumes what is built here.

- `/rooms [filter]` — sends `ROOM_LIST_REQ` and prints the cached result. The filter is a
  client-side case-insensitive substring match on the name; no protocol involvement.
- `/join <name>` — prompts via `terminal::read_password` when the cached list marks the room
  locked, seals the password under the session key with the room name as AAD, sends `ROOM_JOIN`.
- `/create <name>` — creates a public room. `/create <name> --locked` prompts for the password via
  `terminal::read_password` and seals it the same way. The password is deliberately not an inline
  argument: typed inline it would land in the terminal scrollback and, under a shell-driven client,
  in shell history.
- `/leave` — `ROOM_JOIN{"lobby", ""}`.
- The current room name appears in the prompt.
- `/help` gains the new commands.

Handling `INIT` clears the local message and user vectors before repopulating them: a join replaces
the visible history and roster rather than appending to the previous room's.

---

## Testing

`room_tests.cpp` extends with: password accepted, rejected, and absent-when-required; room name
validation; per-room history isolation; the member cap.

`room_manager_tests.cpp` (new): create; duplicate name; case-insensitive collision; list contents
and counts; drop-when-empty; `lobby` pinned against `drop_if_empty`; the max-rooms cap; join into a
room concurrently emptied (asserting the caller either lands in a discoverable room or gets a clean
failure).

`online_users_tests.cpp` (new): claim, duplicate claim refused, release then re-claim.

`wire_tests.cpp` extends with round trips for the four new messages, `RoomInfo` vectors, and
`InitMsg` with its `room` field.

`cli_tests.cpp` extends with `--max-rooms` and `--max-room-members` parsing and range validation.

Each new test executable is registered in `CMakeLists.txt` alongside the existing ones and
discovered via `gtest_discover_tests`.

**Known gap:** there is no end-to-end server↔client harness in this repository, so the join round
trip is covered only at the unit level. Building one is out of scope here.

---

## Documentation

The README gains a rooms section covering the commands, the room-password mechanism, and the
warning against reusing an account password as a room password. The flag reference gains the two
new server flags. The threat model section notes that room names and occupancy are visible to all
authenticated users.
