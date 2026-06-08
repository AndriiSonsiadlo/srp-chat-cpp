#include "chat/server/session.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

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
        remote_             = ec ? std::string("unknown") : endpoint.address().to_string();
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
            if (self->closing_)
                return;
            self->write_queue_.push_back(std::move(packet));
            self->write_signal_.cancel_one();
        });
    }

    void Session::close()
    {
        auto self = shared_from_this();
        boost::asio::post(strand_, [self] {
            self->closing_ = true;
            if (self->write_queue_.empty())
                self->hard_close();
            else
                self->write_signal_.cancel(); // wake the writer to drain, then it closes
        });
    }

    void Session::hard_close()
    {
        boost::system::error_code ec;
        socket_.close(ec);
        write_signal_.cancel();
        deadline_timer_.cancel();
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
                if (closing_) {
                    hard_close();
                    co_return;
                }

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
                hard_close();
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
                hard_close();
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
