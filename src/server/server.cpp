#include "chat/server/server.hpp"

#include <iostream>
#include <thread>
#include <iomanip>
#include <sstream>

#include "chat/crypto/aes_engine.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"

namespace chat::server
{
    namespace
    {
        constexpr size_t kMaxMessageHistory = 100;
    }

    Server::Server(const int port)
        : acceptor_(
              io_context_,
              boost::asio::ip::tcp::endpoint(
                  boost::asio::ip::tcp::v4(),
                  static_cast<boost::asio::ip::port_type>(port)
              )
          ),
          srp_server_(std::make_unique<auth::SRPServer>()),
          connection_manager_(std::make_unique<ConnectionManager>()),
          next_user_id_(1),
          running_(false),
          port_(port)
    {
        srp_server_->load_users("users.db");
    }

    Server::~Server()
    {
        if (srp_server_)
            srp_server_->save_users("users.db");
        stop();
    }

    std::optional<std::string> Server::handle_srp_authentication(const std::shared_ptr<Connection>& conn)
    {
        try {
            auth::SRPServer::ChallengeResponse challenge;
            std::string username;

            while (true) {
                // wait for SRP_INIT or SRP_REGISTER
                auto [type, msg] = conn->receive_packet();

                if (type == MessageType::SRP_REGISTER) {
                    handle_srp_register(conn, msg);
                    continue;
                }

                if (type != MessageType::SRP_INIT) {
                    conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Expected SRP_INIT"}));
                    return std::nullopt;
                }

                // parse SRP_INIT
                auto [init_username, A_b64] = Protocol::decode<SrpInitMsg>(msg);
                if (init_username.empty() || A_b64.empty()) {
                    conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Invalid SRP_INIT"}));
                    return std::nullopt;
                }

                // decode A
                auto A = auth::SRPUtils::base64_to_bytes(A_b64);

                // initialize SRP authentication
                try {
                    challenge = srp_server_->init_authentication(init_username, A);
                    username  = std::move(init_username);
                    break;
                }
                catch (const std::exception&) {
                    conn->send_packet(Protocol::encode(MessageType::SRP_USER_NOT_FOUND));
                }
            }

            // send SRP_CHALLENGE
            conn->send_packet(Protocol::encode(MessageType::SRP_CHALLENGE, SrpChallengeMsg{
                                                   challenge.user_id,
                                                   auth::SRPUtils::bytes_to_base64(challenge.B),
                                                   auth::SRPUtils::bytes_to_base64(challenge.salt),
                                                   auth::SRPUtils::bytes_to_base64(challenge.room_salt)
                                               }));

            // wait for SRP_RESPONSE
            auto [response_type, response_payload] = conn->receive_packet();
            if (response_type != MessageType::SRP_RESPONSE) {
                conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Expected SRP_RESPONSE"}));
                return std::nullopt;
            }

            // parse SRP_RESPONSE
            auto [response_user_id, response_M_b64] = Protocol::decode<SrpResponseMsg>(response_payload);
            if (response_user_id != challenge.user_id) {
                conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Invalid user_id"}));
                return std::nullopt;
            }

            if (connection_manager_->username_exists(username)) {
                conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"User already logged in"}));
                return std::nullopt;
            }

            // decode M and verify
            auto M = auth::SRPUtils::base64_to_bytes(response_M_b64);
            auth::SRPServer::VerifyResponse verify;
            try {
                verify = srp_server_->verify_authentication(response_user_id, M);
            }
            catch (const std::exception& e) {
                conn->send_packet(
                    Protocol::encode(
                        MessageType::ERROR_MSG, ErrorMsg{"Authentication failed: " + std::string(e.what())}
                    )
                );
                return std::nullopt;
            }

            // send SRP_SUCCESS
            conn->send_packet(
                Protocol::encode(
                    MessageType::SRP_SUCCESS,
                    SrpSuccessMsg{
                        auth::SRPUtils::bytes_to_base64(verify.H_AMK),
                        auth::SRPUtils::bytes_to_base64(verify.session_key)
                    }
                ));

            std::string user_id = response_user_id;
            auto session_key    = auth::SRPUtils::base64_to_bytes(
                std::string(verify.session_key.begin(), verify.session_key.end()));
            if (session_key.size() != crypto::AESEngine::KEY_SIZE) {
                conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Invalid session key size"}));
                return std::nullopt;
            }

            connection_manager_->add(user_id, username, conn);
            {
                std::lock_guard<std::mutex> lock(user_keys_mutex_);
                user_keys_[user_id] = std::move(session_key);
            }

            std::cout << "User '" << username << "' (ID: " << user_id << ") authenticated successfully" << std::endl;

            {
                std::lock_guard<std::mutex> lock(message_mutex_);
                auto users = connection_manager_->get_active_users();
                conn->send_packet(Protocol::encode(
                    MessageType::INIT,
                    InitMsg{message_history_, std::move(users)}));
            }

            connection_manager_->broadcast(
                Protocol::encode(
                    MessageType::USER_JOINED,
                    UserJoinedMsg{username, user_id}
                ), user_id); // exclude the new user from broadcast

            return user_id;
        }
        catch (const std::exception& e) {
            std::cerr << "SRP authentication error: " << e.what() << std::endl;
            conn->send_packet(Protocol::encode(MessageType::ERROR_MSG,
                                               ErrorMsg{"Authentication error: " + std::string(e.what())}));
            return std::nullopt;
        }
    }

    void Server::handle_srp_register(
        const std::shared_ptr<Connection>& conn,
        const std::vector<uint8_t>& payload)
    {
        auto [username, salt_b64, verifier_b64] = Protocol::decode<SrpRegisterMsg>(payload);
        if (username.empty() || salt_b64.empty() || verifier_b64.empty()) {
            conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Invalid registration data"}));
            return;
        }

        if (srp_server_->user_exists(username)) {
            conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Username already exists"}));
            return;
        }

        // decode and store credentials
        const auth::UserCredentials creds{
            .username = username,
            .salt = auth::SRPUtils::base64_to_bytes(salt_b64),
            .verifier = auth::SRPUtils::base64_to_bytes(verifier_b64)
        };

        if (srp_server_->register_user(username, creds)) {
            std::cout << "User '" << username << "' registered successfully" << std::endl;

            conn->send_packet(Protocol::encode(MessageType::SRP_REGISTER_ACK));

            // save the database immediately
            srp_server_->save_users("users.db");
        }
        else {
            conn->send_packet(Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Registration failed"}));
        }
    }

    void Server::run()
    {
        std::cout << "Server starting on port " << port_ << "..." << std::endl;
        running_ = true;

        start_accept();

        std::cout << "Server listening on port " << port_ << std::endl;
        std::cout << "Waiting for connections..." << std::endl;

        io_context_.run();
    }

    void Server::stop()
    {
        if (running_.exchange(false)) {
            io_context_.stop();
        }
    }

    void Server::start_accept()
    {
        auto conn   = std::make_shared<Connection>(io_context_);
        auto lambda = [this, conn](const boost::system::error_code& error) {
            if (!error) {
                std::cout << "New connection from " << conn->socket().remote_endpoint() << std::endl;

                // handle client in a separate thread
                std::thread([this, conn]() {
                    const auto user_id = this->handle_srp_authentication(conn);
                    if (user_id.has_value())
                        this->handle_client(conn, user_id.value());
                }).detach();
            }
            else
                std::cerr << "Accept error: " << error.message() << std::endl;

            if (running_)
                this->start_accept();
        };

        acceptor_.async_accept(conn->socket(), lambda);
    }

    void Server::handle_client(const std::shared_ptr<Connection>& conn, const std::string& user_id)
    {
        const std::string username = connection_manager_->get_username_by_user_id(user_id);
        try {
            // message loop
            while (conn->is_open() && running_) {
                switch (auto [type, payload] = conn->receive_packet(); type) {
                    case MessageType::MESSAGE: {
                        const auto& [ciphertext_b64] = Protocol::decode<TextMsg>(payload);

                        std::vector<uint8_t> key;
                        {
                            std::lock_guard<std::mutex> lock(user_keys_mutex_);
                            if (const auto it = user_keys_.find(user_id); it != user_keys_.end())
                                key = it->second;
                        }

                        if (key.empty()) {
                            conn->send_packet(
                                Protocol::encode(MessageType::ERROR_MSG, ErrorMsg{"Missing session key"}));
                            break;
                        }

                        const auto encrypted = auth::SRPUtils::base64_to_bytes(ciphertext_b64);
                        const auto text      = crypto::AESEngine::decrypt_string(encrypted, key);
                        handle_message(username, text);
                        break;
                    }
                    case MessageType::DISCONNECT:
                        conn->close();
                        break;
                    default:
                        std::cerr << "Unknown message type from " << username << std::endl;
                        break;
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Client error: " << e.what() << std::endl;
        }

        if (!user_id.empty()) {
            handle_disconnect(user_id);
            std::cout << "User '" << username << "' disconnected" << std::endl;
        }

        conn->close();
    }

    void Server::handle_message(const std::string& username, const std::string& text)
    {
        if (username.empty())
            return;

        const auto now             = std::chrono::system_clock::now();
        const auto duration        = now.time_since_epoch();
        const int64_t timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

        const auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");

        std::cout << "[" << oss.str() << "] " << username << ": " << text << std::endl;

        // store message in history
        {
            std::lock_guard<std::mutex> lock(message_mutex_);
            message_history_.emplace_back(username, text, now);

            // keep only last kMaxMessageHistory messages
            if (message_history_.size() > kMaxMessageHistory)
                message_history_.erase(message_history_.begin());
        }

        // encrypt and broadcast to each active user with their session key
        for (const auto& user : connection_manager_->get_active_users()) {
            std::vector<uint8_t> key;
            {
                std::lock_guard<std::mutex> lock(user_keys_mutex_);
                if (const auto it = user_keys_.find(user.user_id); it != user_keys_.end())
                    key = it->second;
            }

            if (key.empty())
                continue;

            try {
                const auto encrypted = crypto::AESEngine::encrypt_string(text, key);
                connection_manager_->send_to(
                    user.user_id,
                    Protocol::encode(
                        MessageType::BROADCAST,
                        BroadcastMsg{
                            username,
                            auth::SRPUtils::bytes_to_base64(encrypted),
                            timestamp_ms
                        }
                    )
                );
            }
            catch (const std::exception& e) {
                std::cerr << "Encryption/broadcast error for " << user.user_id << ": " << e.what() << std::endl;
            }
        }
    }

    void Server::handle_disconnect(const std::string& user_id)
    {
        // get username before removing
        const std::string username = connection_manager_->get_username_by_user_id(user_id);
        {
            std::lock_guard<std::mutex> lock(user_keys_mutex_);
            user_keys_.erase(user_id);
        }
        connection_manager_->remove(user_id);

        if (!username.empty())
            // notify other users
            connection_manager_->broadcast(Protocol::encode(MessageType::USER_LEFT, UserLeftMsg{username}));
    }
} // namespace chat::server
