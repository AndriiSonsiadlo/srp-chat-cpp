#include "chat/client/client.hpp"
#include "chat/common/protocol.hpp"
#include <iostream>
#include <iomanip>
#include <utility>

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
                        std::lock_guard<std::mutex> lock(messages_mutex_);
                        messages_.clear();
                        render_ui();
                    }
                    else if (line == "/help")
                    {
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
        std::cout << "Connecting to " << host_ << ":" << port_ << "..." << std::endl;

        boost::asio::ip::tcp::resolver resolver(io_context_);
        const auto endpoints = resolver.resolve(host_, std::to_string(port_));

        boost::asio::connect(socket_, endpoints);

        std::cout << "Connected! Authenticating as '" << username_ << "'..." << std::endl;

        // send CONNECT message
        std::string connect_msg = Protocol::encode_connect(username_);
        boost::asio::write(socket_, boost::asio::buffer(connect_msg));

        // wait for CONNECT_ACK
        std::string line;
        boost::asio::read_until(socket_, buffer_, '\n');
        std::istream is(&buffer_);
        std::getline(is, line);
        line += "\n";

        handle_connect_ack(line);

        // wait for INIT
        boost::asio::read_until(socket_, buffer_, '\n');
        std::getline(is, line);
        line += "\n";

        handle_init(line);

        connected_ = true;
        std::cout << "Successfully joined the chat!" << std::endl;
        std::cout << "\nType /help for commands\n" << std::endl;
    }

    void Client::disconnect()
    {
        if (socket_.is_open())
            try
            {
                std::string disconnect_msg = Protocol::encode_disconnect();
                boost::asio::write(socket_, boost::asio::buffer(disconnect_msg));
                socket_.close();
            }
            catch (...)
            {
                // Ignore errors on disconnect
            }
        connected_ = false;
    }

    void Client::send_message(const std::string& text)
    {
        if (!connected_)
            return;

        try
        {
            std::string msg = Protocol::encode_message(text);
            boost::asio::write(socket_, boost::asio::buffer(msg));
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error sending message: " << e.what() << std::endl;
            connected_ = false;
        }
    }

    void Client::receive_loop()
    {
        try
        {
            while (running_ && connected_)
            {
                std::string line;
                boost::asio::read_until(socket_, buffer_, '\n');
                std::istream is(&buffer_);
                std::getline(is, line);
                line += "\n";

                const MessageType type = Protocol::parse_type(line);
                switch (type)
                {
                    case MessageType::BROADCAST:
                        handle_broadcast(line);
                        break;
                    case MessageType::USER_JOINED:
                        handle_user_joined(line);
                        break;
                    case MessageType::USER_LEFT:
                        handle_user_left(line);
                        break;
                    case MessageType::ERROR_MSG:
                        handle_error(line);
                        break;
                    default:
                        std::cerr << "Unknown message type" << std::endl;
                }
            }
        }
        catch (const std::exception& e)
        {
            if (running_)
            {
                std::cerr << "\nConnection lost: " << e.what() << std::endl;
                connected_ = false;
            }
        }
    }

    void Client::handle_connect_ack(const std::string& message)
    {
        user_id_ = Protocol::parse_field(message, "user_id");
    }

    void Client::handle_init(const std::string& message)
    {
        const std::string messages_str = Protocol::parse_field(message, "messages");
        const std::string users_str    = Protocol::parse_field(message, "users");

        {
            std::lock_guard<std::mutex> lock(messages_mutex_);
            messages_ = Protocol::parse_messages(messages_str);
        }

        {
            std::lock_guard<std::mutex> lock(users_mutex_);
            users_ = Protocol::parse_users(users_str);
        }
    }

    void Client::handle_broadcast(const std::string& message)
    {
        const std::string username  = Protocol::parse_field(message, "username");
        const std::string text      = Protocol::parse_field(message, "text");
        const std::string timestamp = Protocol::parse_field(message, "timestamp");

        {
            std::lock_guard<std::mutex> lock(messages_mutex_);
            Message msg{
                .username = username,
                .text = text,
                .timestamp = std::chrono::system_clock::now()
            };
            messages_.push_back(std::move(msg));

            // keep only last 50 messages
            if (messages_.size() > 50)
                messages_.erase(messages_.begin());
        }

        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cout << "\r" << std::string(80, ' ') << "\r"; // Clear current line

            if (username == username_)
                std::cout << "[" << timestamp << "] \033[32m" << username << "\033[0m: " << text << std::endl;
            else
                std::cout << "[" << timestamp << "] \033[36m" << username << "\033[0m: " << text << std::endl;

            std::cout << "> " << std::flush;
        }
    }

    void Client::handle_user_joined(const std::string& message)
    {
        const std::string username = Protocol::parse_field(message, "username");
        const std::string user_id  = Protocol::parse_field(message, "user_id");

        {
            std::lock_guard<std::mutex> lock(users_mutex_);
            users_.push_back({username, user_id});
        }

        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cout << "\r" << std::string(80, ' ') << "\r";
            std::cout << "\033[33m*** " << username << " joined the chat ***\033[0m" << std::endl;
            std::cout << "> " << std::flush;
        }
    }

    void Client::handle_user_left(const std::string& message)
    {
        std::string username = Protocol::parse_field(message, "username");

        {
            std::lock_guard<std::mutex> lock(users_mutex_);
            std::erase_if(users_, [&username](const User& u) { return u.username == username; });
        }

        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            std::cout << "\r" << std::string(80, ' ') << "\r";
            std::cout << "\033[31m*** " << username << " left the chat ***\033[0m" << std::endl;
            std::cout << "> " << std::flush;
        }
    }

    void Client::handle_error(const std::string& message)
    {
        const std::string error_msg = Protocol::parse_field(message, "message");
        std::cerr << "Error from server: " << error_msg << std::endl;
        connected_ = false;
    }

    void Client::render_ui()
    {
        clear_screen();
        print_banner();

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
