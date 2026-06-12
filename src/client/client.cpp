#include "chat/client/client.hpp"

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <utility>
#include <chrono>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_future.hpp>

#include "chat/client/terminal.hpp"
#include "chat/crypto/aes_engine.hpp"
#include "chat/common/log.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"
#include "chat/auth/srp_utils.hpp"

namespace chat::client
{
    namespace
    {
        constexpr size_t kMaxStoredMessages    = 50;
        constexpr size_t kRenderedMessageCount = 20;

        // std::localtime/std::gmtime share a static tm; the receive coroutine and
        // the render path can both be here, so use the reentrant variants.
        std::string format_time(const std::chrono::system_clock::time_point tp, const char* fmt, const bool utc)
        {
            const auto as_time = std::chrono::system_clock::to_time_t(tp);

            std::tm out{};
#ifdef _WIN32
            if (utc) gmtime_s(&out, &as_time);
            else localtime_s(&out, &as_time);
#else
            if (utc) gmtime_r(&as_time, &out);
            else localtime_r(&as_time, &out);
#endif

            std::ostringstream oss;
            oss << std::put_time(&out, fmt);
            return oss.str();
        }
    }

    Client::Client(ClientConfig config)
        : socket_(io_context_)
          , config_(std::move(config))
          , running_(false)
          , connected_(false)
    {
    }

    Client::~Client()
    {
        stop();
    }

    void Client::run()
    {
        try
        {
            connect();

            auto login = boost::asio::co_spawn(
                io_context_,
                [this]() -> boost::asio::awaitable<void>
                {
                    if (config_.register_first)
                        co_await srp_register();

                    co_await srp_authenticate();
                },
                boost::asio::use_future);

            work_guard_.emplace(boost::asio::make_work_guard(io_context_));
            io_thread_ = std::thread([this] { io_context_.run(); });

            login.get(); // rethrows any handshake exception on this thread

            running_ = true;
            boost::asio::co_spawn(io_context_, [this] { return receive_loop(); }, boost::asio::detached);

            render_ui();
            input_loop();
        }
        catch (const std::exception& e)
        {
            log::error(std::string("client error: ") + e.what());
        }

        stop();
    }

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
                {
                    std::lock_guard<std::mutex> lock(ui_mutex_);
                    password = terminal::read_password("Room password: ");
                }
            }
            else
            {
                // Case-insensitive substring match, entirely client-side.
                const auto lower = [](std::string s) {
                    std::ranges::transform(s, s.begin(), [](const unsigned char c) {
                        return static_cast<char>(std::tolower(c));
                    });
                    return s;
                };

                bool locked = false;
                {
                    std::lock_guard<std::mutex> lock(rooms_mutex_);
                    for (const auto& room : rooms_)
                        if (lower(room.name) == lower(name) && room.has_password)
                            locked = true;
                }
                if (locked)
                {
                    std::lock_guard<std::mutex> lock(ui_mutex_);
                    password = terminal::read_password("Room password: ");
                }
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

    void Client::stop()
    {
        running_ = false;

        if (io_thread_.joinable())
        {
            // disconnect() runs on the io_context thread, so it never closes the
            // socket underneath an in-flight read.
            boost::asio::post(io_context_, [this] { disconnect(); });
            work_guard_.reset();
            io_thread_.join();
        }
        else if (socket_.is_open())
            disconnect();

        terminal::wipe(password_);
    }

    void Client::connect()
    {
        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cout << "Connecting to " << config_.host << ":" << config_.port << "..." << std::endl;
        }

        boost::asio::ip::tcp::resolver resolver(io_context_);
        auto endpoints = resolver.resolve(config_.host, std::to_string(config_.port));
        boost::asio::connect(socket_, endpoints);
    }

    void Client::disconnect()
    {
        if (socket_.is_open())
        {
            boost::system::error_code ec;
            const auto packet = Protocol::encode(MessageType::DISCONNECT);
            boost::asio::write(socket_, boost::asio::buffer(packet), ec);
            socket_.close(ec);
        }
        connected_ = false;
    }

    boost::asio::awaitable<void> Client::send_message(std::string text)
    {
        if (!connected_)
            co_return;

        try
        {
            const auto encrypted = crypto::AESEngine::encrypt_string(text, room_key_);
            co_await ProtocolHelpers::async_send_packet(socket_, Protocol::encode(
                MessageType::MESSAGE,
                TextMsg{auth::SRPUtils::bytes_to_base64(encrypted)}
            ));
        }
        catch (const std::exception& e)
        {
            log::error(std::string("failed to send message: ") + e.what());
            connected_ = false;
        }
    }

    boost::asio::awaitable<void> Client::receive_loop()
    {
        try
        {
            while (running_ && connected_)
            {
                auto [type, payload] = co_await ProtocolHelpers::async_receive_packet(socket_);
                handle_packet(type, payload);
            }
        }
        catch (const std::exception& e)
        {
            if (running_)
            {
                std::lock_guard<std::mutex> lock(ui_mutex_);
                std::cerr << "\nConnection lost: " << e.what() << std::endl;
            }
            connected_ = false;
        }
    }

    void Client::handle_packet(MessageType type, const std::vector<uint8_t>& payload)
    {
        switch (type)
        {
            case MessageType::INIT: {
                auto msg = Protocol::decode<InitMsg>(payload);

                std::vector<Message> decrypted;
                decrypted.reserve(msg.messages.size());
                size_t skipped = 0;
                for (const auto& entry : msg.messages)
                {
                    try
                    {
                        const std::vector<uint8_t> aad(entry.username.begin(), entry.username.end());
                        auto text = crypto::AESEngine::decrypt_string(
                            auth::SRPUtils::base64_to_bytes(entry.ciphertext_b64), room_key_, aad);
                        decrypted.emplace_back(
                            entry.username, std::move(text),
                            std::chrono::system_clock::time_point(
                                std::chrono::milliseconds(entry.timestamp_ms)));
                    }
                    catch (const std::exception&)
                    {
                        ++skipped; // skip an entry we cannot read rather than aborting the join
                    }
                }

                // Count only — never the exception text or any ciphertext, which
                // would leak length/content of what we failed to open.
                if (skipped > 0 && skipped == msg.messages.size())
                    // Every entry failed: far more likely a desynced room key
                    // (e.g. a tampered, unauthenticated room_salt in the SRP
                    // challenge — see README Limitations) than scattered
                    // corruption, so this deserves a louder signal.
                    log::error("failed to decrypt all " + std::to_string(skipped)
                               + " history entries; room key may be desynced");
                else if (skipped > 0)
                    log::warn("skipped " + std::to_string(skipped) + " unreadable history entries");

                {
                    std::lock_guard<std::mutex> lock(messages_mutex_);
                    messages_ = std::move(decrypted);
                }
                {
                    std::lock_guard<std::mutex> lock(users_mutex_);
                    users_ = std::move(msg.users);
                }

                {
                    std::lock_guard<std::mutex> lock(ui_mutex_);
                    current_room_ = msg.room;
                }
                render_ui();

                break;
            }
            case MessageType::BROADCAST: {
                handle_broadcast(payload);
                break;
            }
            case MessageType::USER_JOINED: {
                auto msg = Protocol::decode<UserJoinedMsg>(payload);

                {
                    std::lock_guard<std::mutex> lock(users_mutex_);
                    users_.emplace_back(msg.username, msg.user_id);
                }
                {
                    std::lock_guard<std::mutex> lock(ui_mutex_);
                    terminal::clear_line();
                    std::cout << terminal::color("\033[33m") << "*** " << msg.username << " joined the chat ***"
                        << terminal::color("\033[0m") << std::endl;
                    std::cout << "[" << current_room_ << "] > " << std::flush;
                }

                break;
            }
            case MessageType::USER_LEFT: {
                auto msg = Protocol::decode<UserLeftMsg>(payload);

                {
                    std::lock_guard<std::mutex> lock(users_mutex_);
                    std::erase_if(users_, [&msg](const User& u) { return u.username == msg.username; });
                }
                {
                    std::lock_guard<std::mutex> lock(ui_mutex_);
                    terminal::clear_line();
                    std::cout << terminal::color("\033[31m") << "*** " << msg.username << " left the chat ***"
                        << terminal::color("\033[0m") << std::endl;
                    std::cout << "[" << current_room_ << "] > " << std::flush;
                }

                break;
            }
            case MessageType::ROOM_LIST: {
                auto msg = Protocol::decode<RoomListMsg>(payload);
                {
                    std::lock_guard<std::mutex> lock(rooms_mutex_);
                    rooms_ = std::move(msg.rooms);
                }
                print_rooms();
                break;
            }
            case MessageType::ERROR_MSG: {
                auto msg = Protocol::decode<ErrorMsg>(payload);
                std::lock_guard<std::mutex> lock(ui_mutex_);
                terminal::clear_line();
                std::cout << terminal::color("\033[31m") << "*** " << msg.error_msg << " ***"
                    << terminal::color("\033[0m") << std::endl;
                std::cout << "[" << current_room_ << "] > " << std::flush;
                break;
            }
            default: {
                log::warn("unknown message type " + std::to_string(static_cast<int>(type)));
                break;
            }
        }
    }

    void Client::handle_broadcast(const std::vector<uint8_t>& payload)
    {
        auto [username, encrypted_text_b64, timestamp_ms] = Protocol::decode<BroadcastMsg>(payload);
        std::string text;
        try
        {
            const auto encrypted = auth::SRPUtils::base64_to_bytes(encrypted_text_b64);
            const std::vector<uint8_t> aad(username.begin(), username.end());
            text                 = crypto::AESEngine::decrypt_string(encrypted, room_key_, aad);
        }
        catch (const std::exception& e)
        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cerr << "\nFailed to decrypt message from " << username << ": " << e.what() << std::endl;
            std::cout << "[" << current_room_ << "] > " << std::flush;
            return;
        }

        auto timestamp = std::chrono::system_clock::time_point(
            std::chrono::milliseconds(timestamp_ms));

        {
            std::lock_guard<std::mutex> lock(messages_mutex_);
            messages_.emplace_back(username, text, timestamp);

            if (messages_.size() > kMaxStoredMessages) // keep last messages
                messages_.erase(messages_.begin());
        }

        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            terminal::clear_line();

            const char* name_color = username == config_.username
                                         ? terminal::color("\033[32m")
                                         : terminal::color("\033[36m");

            std::cout << "[" << format_time(timestamp, "%Y-%m-%dT%H:%M:%S", true) << "] "
                << name_color << username << terminal::color("\033[0m") << ": " << text << std::endl;

            std::cout << "[" << current_room_ << "] > " << std::flush;
        }
    }

    boost::asio::awaitable<void> Client::srp_authenticate()
    {
        // srp_register() (when register_first is set) already prompted for and
        // captured the password immediately before this call — don't ask twice.
        if (password_.empty())
            password_ = terminal::read_password("Enter password: ");

        srp_client_ = std::make_unique<auth::SRPClient>(config_.username, password_);

        // step 1: generate A and send SRP_INIT
        auto A = srp_client_->generate_A();
        co_await ProtocolHelpers::async_send_packet(socket_, Protocol::encode(
            MessageType::SRP_INIT,
            SrpInitMsg{kProtocolVersion, config_.username, auth::SRPUtils::bytes_to_base64(A)}));

        // step 2: receive response (could be SRP_CHALLENGE or ERROR_MSG)
        auto [type, payload] = co_await ProtocolHelpers::async_receive_packet(socket_);

        if (type == MessageType::ERROR_MSG)
        {
            auto msg = Protocol::decode<ErrorMsg>(payload);
            throw std::runtime_error("Authentication error: " + msg.error_msg);
        }

        if (type != MessageType::SRP_CHALLENGE)
            throw std::runtime_error(
                "Expected SRP_CHALLENGE, got message type " + std::to_string(static_cast<int>(type)));

        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cout << "Authenticating..." << std::endl;
        }

        auto srpChallengeMsg = Protocol::decode<SrpChallengeMsg>(payload);
        user_id_             = srpChallengeMsg.user_id;
        auto B               = auth::SRPUtils::base64_to_bytes(srpChallengeMsg.B_b64);
        auto salt            = auth::SRPUtils::base64_to_bytes(srpChallengeMsg.salt_b64);
        auto room_salt       = auth::SRPUtils::base64_to_bytes(srpChallengeMsg.room_salt_b64);

        // step 3: process challenge and send response
        auto M = srp_client_->process_challenge(B, salt);
        co_await ProtocolHelpers::async_send_packet(socket_, Protocol::encode(
            MessageType::SRP_RESPONSE, SrpResponseMsg{user_id_, auth::SRPUtils::bytes_to_base64(M)}));

        // step 4: receive SRP_SUCCESS
        auto [success_type, success_payload] = co_await ProtocolHelpers::async_receive_packet(socket_);

        if (success_type == MessageType::ERROR_MSG)
        {
            auto msg = Protocol::decode<ErrorMsg>(success_payload);
            throw std::runtime_error("Authentication failed: " + msg.error_msg);
        }

        if (success_type != MessageType::SRP_SUCCESS)
            throw std::runtime_error("Expected SRP_SUCCESS");

        auto srpSuccessMsg = Protocol::decode<SrpSuccessMsg>(success_payload);
        auto H_AMK         = auth::SRPUtils::base64_to_bytes(srpSuccessMsg.H_AMK_b64);

        // verify server
        if (!srp_client_->verify_server(H_AMK))
            throw std::runtime_error("Server verification failed");

        room_key_ = srp_client_->derive_session_key(room_salt);
        if (room_key_.size() != crypto::AESEngine::KEY_SIZE)
            throw std::runtime_error("Invalid AES room key size");

        // step 5: receive INIT to get messages and users
        auto [init_type, init_payload] = co_await ProtocolHelpers::async_receive_packet(socket_);

        if (init_type == MessageType::ERROR_MSG)
        {
            auto msg = Protocol::decode<ErrorMsg>(init_payload);
            throw std::runtime_error("Init error: " + msg.error_msg);
        }

        if (init_type != MessageType::INIT)
            throw std::runtime_error("Expected INIT");

        handle_packet(init_type, init_payload);
        connected_ = true;

        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cout << "Authentication successful! Joined the chat" << std::endl;
            std::cout << "\nType /help for commands\n" << std::endl;
        }
    }

    boost::asio::awaitable<void> Client::srp_register()
    {
        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cout << "Registering new user '" << config_.username << "'..." << std::endl;
        }

        password_    = terminal::read_password("Enter password: ");
        auto confirm = terminal::read_password("Confirm password: ");
        const bool mismatch = password_ != confirm;
        terminal::wipe(confirm);
        if (mismatch)
            throw std::runtime_error("Passwords do not match");

        // generate credentials
        auto creds = auth::SRPClient::register_user(config_.username, password_);

        // send SRP_REGISTER
        co_await ProtocolHelpers::async_send_packet(socket_, Protocol::encode(
            MessageType::SRP_REGISTER,
            SrpRegisterMsg{
                .username = config_.username,
                .salt_b64 = auth::SRPUtils::bytes_to_base64(creds.salt),
                .verifier_b64 = auth::SRPUtils::bytes_to_base64(creds.verifier)
            }));

        // wait for response
        auto [type, payload] = co_await ProtocolHelpers::async_receive_packet(socket_);

        if (type == MessageType::ERROR_MSG)
        {
            auto msg = Protocol::decode<ErrorMsg>(payload);
            throw std::runtime_error("Registration failed: " + msg.error_msg);
        }

        if (type != MessageType::SRP_REGISTER_ACK)
            throw std::runtime_error("Expected SRP_REGISTER_ACK");

        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cout << "Registration successful!" << std::endl;
        }
    }

    void Client::render_ui()
    {
        // Task 8 made this reachable from the io thread (every room switch
        // triggers an INIT -> render_ui()), not just the main thread as
        // before. cout is not thread-safe, so the whole render must be one
        // critical section under ui_mutex_ -- the container-specific mutexes
        // below only protect the containers themselves, not the printing.
        std::lock_guard<std::mutex> ui_lock(ui_mutex_);

        terminal::clear_screen();
        print_banner();

        {
            std::lock_guard<std::mutex> lock(users_mutex_);
            std::cout << "Room: " << current_room_ << "\n";
            std::cout << "Online users: ";
            for (size_t i = 0; i < users_.size(); ++i)
            {
                if (i > 0) std::cout << ", ";
                std::cout << users_[i].username;
            }
            std::cout << std::endl;
        }

        std::cout << std::string(70, '-') << std::endl;

        {
            std::lock_guard<std::mutex> lock(messages_mutex_);

            size_t start = messages_.size() > kRenderedMessageCount ? messages_.size() - kRenderedMessageCount : 0;
            for (size_t i = start; i < messages_.size(); ++i)
            {
                auto& msg = messages_[i];
                std::cout << "[" << format_time(msg.timestamp, "%H:%M:%S", false) << "] ";

                if (msg.username == config_.username)
                    std::cout << terminal::color("\033[32m") << msg.username << terminal::color("\033[0m");
                else
                    std::cout << terminal::color("\033[36m") << msg.username << terminal::color("\033[0m");

                std::cout << ": " << msg.text << std::endl;
            }
        }

        std::cout << std::string(70, '-') << std::endl;
    }

    void Client::print_banner()
    {
        std::cout << R"(
██████╗  ██████╗  ██████╗      ██████╗██╗  ██╗ █████╗ ████████╗
██╔════╝ ██╔══██╗ ██╔══██╗    ██╔════╝██║  ██║██╔══██╗╚══██╔══╝
██████╗  ██████╔╝ ██████╔╝    ██║     ███████║███████║   ██║
╚════██╗ ██╔══██╗ ██╔════╝    ██║     ██╔══██║██╔══██║   ██║
██████╔╝ ██║  ██║ ██║         ╚██████╗██║  ██║██║  ██║   ██║
╚═════╝  ╚═╝  ╚═╝ ╚═╝          ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
)" << std::endl;
    }
} // namespace chat::client
