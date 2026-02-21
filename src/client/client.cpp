#include "chat/client/client.hpp"
#include <iostream>
#include <iomanip>
#include <utility>
#include <chrono>

#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"

namespace chat::client
{
    Client::Client(std::string host, const int port, std::string username)
        : socket_(io_context_)
          , host_(std::move(host))
          , port_(port)
          , username_(std::move(username))
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

            // start receive thread
            running_        = true;
            receive_thread_ = std::thread([this]() { receive_loop(); });

            // initial render
            render_ui();

            // input loop
            std::string line;
            while (running_ && connected_)
            {
                std::cout << "> ";
                std::getline(std::cin, line);

                if (!line.empty())
                {
                    if (line == "/quit" || line == "/q")
                        break;

                    if (line == "/clear")
                    {
                        std::unique_lock<std::mutex> lock(messages_mutex_);
                        messages_.clear();
                        lock.unlock();

                        render_ui();
                    }
                    else if (line == "/help")
                    {
                        std::lock_guard<std::mutex> lock(ui_mutex_);
                        std::cout << "\nCommands:\n";
                        std::cout << "  /quit, /q  - Quit the chat\n";
                        std::cout << "  /clear     - Clear message history\n";
                        std::cout << "  /help      - Show this help\n\n";
                    }
                    else
                        send_message(line);
                }
            }

            disconnect();
        }
        catch (const std::exception& e)
        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cerr << "Error: " << e.what() << std::endl;
        }

        stop();
    }

    void Client::stop()
    {
        if (running_.exchange(false))
        {
            disconnect();

            if (receive_thread_.joinable())
                receive_thread_.join();
        }
    }

    void Client::connect()
    {
        std::unique_lock<std::mutex> ui_lock(ui_mutex_);
        std::cout << "Connecting to " << host_ << ":" << port_ << "..." << std::endl;
        ui_lock.unlock();

        boost::asio::ip::tcp::resolver resolver(io_context_);
        const auto endpoints = resolver.resolve(host_, std::to_string(port_));
        boost::asio::connect(socket_, endpoints);

        ui_lock.lock();
        std::cout << "Authenticating as '" << username_ << "'..." << std::endl;
        ui_lock.unlock();

        // send CONNECT message
        auto connect_packet = Protocol::encode(MessageType::CONNECT, ConnectMsg{username_});
        send_packet(connect_packet);

        // wait for CONNECT_ACK
        auto [ack_type, ack_payload] = receive_packet();
        if (ack_type != MessageType::CONNECT_ACK && ack_type != MessageType::ERROR_MSG)
            throw std::runtime_error("Expected CONNECT_ACK");
        handle_packet(ack_type, ack_payload);

        // wait for INIT
        auto [init_type, init_payload] = receive_packet();
        if (init_type != MessageType::INIT && init_type != MessageType::ERROR_MSG)
            throw std::runtime_error("Expected INIT");
        handle_packet(init_type, init_payload);
        connected_ = true;

        ui_lock.lock();
        std::cout << "Successfully joined the chat!" << std::endl;
        std::cout << "\nType /help for commands\n" << std::endl;
        ui_lock.unlock();
    }

    void Client::disconnect()
    {
        if (socket_.is_open())
            try
            {
                send_packet(Protocol::encode(MessageType::DISCONNECT));
                socket_.close();
            }
            catch (...)
            {
                // ignore errors on disconnect
            }
        connected_ = false;
    }

    void Client::send_message(const std::string& text)
    {
        if (!connected_)
            return;

        try
        {
            send_packet(Protocol::encode(MessageType::MESSAGE, TextMsg{text}));
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error sending message: " << e.what() << std::endl;
            connected_ = false;
        }
    }

    void Client::send_packet(const std::vector<uint8_t>& packet)
    {
        boost::asio::write(socket_, boost::asio::buffer(packet));
    }

    std::pair<MessageType, std::vector<uint8_t>> Client::receive_packet()
    {
        // read header
        MsgHeader header{};
        boost::asio::read(socket_, boost::asio::buffer(&header, sizeof(MsgHeader)));

        // read payload
        std::vector<uint8_t> payload(header.size);
        if (header.size > 0)
        {
            boost::asio::read(socket_, boost::asio::buffer(payload));
        }

        return {static_cast<MessageType>(header.type), std::move(payload)};
    }

    void Client::receive_loop()
    {
        try
        {
            while (running_ && connected_)
            {
                auto [type, payload] = receive_packet();
                handle_packet(type, payload);
            }
        }
        catch (const std::exception& e)
        {
            if (running_)
            {
                std::lock_guard<std::mutex> lock(ui_mutex_);
                std::cerr << "\nConnection lost: " << e.what() << std::endl;
                connected_ = false;
            }
        }
    }

    void Client::handle_packet(MessageType type, const std::vector<uint8_t>& payload)
    {
        std::unique_lock<std::mutex> lock;
        switch (type)
        {
            case MessageType::CONNECT_ACK:
                {
                    auto msg = Protocol::decode<ConnectAckMsg>(payload);
                    user_id_ = msg.user_id;
                    std::cout << "Connected with ID: " << user_id_ << std::endl;
                    break;
                }
            case MessageType::INIT:
                {
                    auto msg = Protocol::decode<InitMsg>(payload);

                    lock      = std::unique_lock<std::mutex>(messages_mutex_);
                    messages_ = std::move(msg.messages);
                    lock.unlock();

                    lock   = std::unique_lock<std::mutex>(users_mutex_);
                    users_ = std::move(msg.users);
                    lock.unlock();

                    break;
                }
            case MessageType::BROADCAST:
                {
                    handle_broadcast(payload);
                    break;
                }
            case MessageType::USER_JOINED:
                {
                    auto msg = Protocol::decode<UserJoinedMsg>(payload);

                    lock = std::unique_lock<std::mutex>(users_mutex_);
                    users_.emplace_back(msg.username, msg.user_id);
                    lock.unlock();

                    lock = std::unique_lock<std::mutex>(ui_mutex_);
                    std::cout << "\r" << std::string(80, ' ') << "\r";
                    std::cout << "\033[33m*** " << msg.username << " joined the chat ***\033[0m" << std::endl;
                    std::cout << "> " << std::flush;
                    lock.unlock();

                    break;
                }
            case MessageType::USER_LEFT:
                {
                    auto msg = Protocol::decode<UserLeftMsg>(payload);

                    lock = std::unique_lock<std::mutex>(users_mutex_);
                    std::erase_if(users_, [&msg](const User& u) { return u.username == msg.username; });
                    lock.unlock();

                    lock = std::unique_lock<std::mutex>(ui_mutex_);
                    std::cout << "\r" << std::string(80, ' ') << "\r";
                    std::cout << "\033[31m*** " << msg.username << " left the chat ***\033[0m" << std::endl;
                    std::cout << "> " << std::flush;
                    lock.unlock();

                    break;
                }
            case MessageType::ERROR_MSG:
                {
                    auto msg = Protocol::decode<ErrorMsg>(payload);
                    std::cerr << "Error from server: " << msg.error_msg << std::endl;
                    connected_ = false;
                    break;
                }
            default:
                {
                    lock = std::unique_lock<std::mutex>(ui_mutex_);
                    std::cerr << "Unknown message type" << std::endl;
                    lock.unlock();
                }
        }
    }

    void Client::handle_broadcast(const std::vector<uint8_t>& payload)
    {
        auto [username, text, timestamp_ms] = Protocol::decode<BroadcastMsg>(payload);

        auto timestamp = std::chrono::system_clock::time_point(
            std::chrono::milliseconds(timestamp_ms));

        {
            std::lock_guard<std::mutex> lock(messages_mutex_);
            messages_.emplace_back(username, text, timestamp);

            if (messages_.size() > 50) // keep only last 50 messages
                messages_.erase(messages_.begin());
        }

        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cout << "\r" << std::string(80, ' ') << "\r"; // Clear current line

            auto time_t = std::chrono::system_clock::to_time_t(timestamp);
            std::ostringstream oss;
            oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");

            if (username == username_)
                std::cout << "[" << oss.str() << "] \033[32m" << username << "\033[0m: " << text << std::endl;
            else
                std::cout << "[" << oss.str() << "] \033[36m" << username << "\033[0m: " << text << std::endl;

            std::cout << "> " << std::flush;
        }
    }

    void Client::render_ui()
    {
        std::unique_lock<std::mutex> ui_lock(ui_mutex_);
        clear_screen();
        print_banner();
        ui_lock.unlock();

        {
            std::lock_guard<std::mutex> lock(users_mutex_);
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

            size_t start = messages_.size() > 20 ? messages_.size() - 20 : 0;
            for (size_t i = start; i < messages_.size(); ++i)
            {
                auto& msg   = messages_[i];
                auto time_t = std::chrono::system_clock::to_time_t(msg.timestamp);
                std::cout << "[" << std::put_time(std::localtime(&time_t), "%H:%M:%S") << "] ";

                if (msg.username == username_)
                    std::cout << "\033[32m" << msg.username << "\033[0m";
                else
                    std::cout << "\033[36m" << msg.username << "\033[0m";

                std::cout << ": " << msg.text << std::endl;
            }
        }

        std::cout << std::string(70, '-') << std::endl;
    }

    void Client::clear_screen()
    {
#ifdef _WIN32
        system("cls");
#else
        system("clear");
#endif
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
