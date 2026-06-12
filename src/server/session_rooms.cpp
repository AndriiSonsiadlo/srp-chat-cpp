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
