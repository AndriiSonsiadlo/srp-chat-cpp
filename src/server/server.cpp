#include "chat/server/server.hpp"

#include <iostream>
#include <thread>
#include <iomanip>
#include <sstream>

#include "chat/common/protocol.hpp"

namespace chat::server
{
    Server::Server(const int port)
        : acceptor_(
              io_context_,
              boost::asio::ip::tcp::endpoint(
                  boost::asio::ip::tcp::v4(),
                  static_cast<boost::asio::ip::port_type>(port)
              )
          ),
          connection_manager_(std::make_unique<ConnectionManager>()),
          next_user_id_(1),
          running_(false),
          port_(port)
    {
    }

    Server::~Server()
    {
        stop();
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
        if (running_.exchange(false))
        {
            io_context_.stop();
        }
    }

    void Server::start_accept()
    {
        auto conn   = std::make_shared<Connection>(io_context_);
        auto lambda = [this, conn](const boost::system::error_code& error)
        {
            if (!error)
            {
                std::cout << "New connection from " << conn->socket().remote_endpoint() << std::endl;

                // handle client in a separate thread
                std::thread([this, conn]()
                {
                    const auto user_id = this->handle_connect(conn);
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
        try
        {
            // message loop
            while (conn->is_open() && running_)
            {
                std::string message = conn->receive_line();
                MessageType type    = Protocol::parse_type(message);

                if (type == MessageType::MESSAGE)
                    handle_message(conn, username, message);
                else if (type == MessageType::DISCONNECT)
                    break;
                else
                    std::cerr << "Unknown message type from " << username << std::endl;
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "Client error: " << e.what() << std::endl;
        }

        if (!user_id.empty())
        {
            handle_disconnect(user_id);
            std::cout << "User '" << username << "' disconnected" << std::endl;
        }

        conn->close();
    }

    std::optional<std::string> Server::handle_connect(const std::shared_ptr<Connection>& conn)
    {
        // wait for CONNECT message
        const std::string connect_msg = conn->receive_line();
        if (const MessageType type = Protocol::parse_type(connect_msg); type != MessageType::CONNECT)
        {
            conn->send(Protocol::encode_error("Expected CONNECT message"));
            conn->close();
            return std::nullopt;
        }

        const std::string username = Protocol::parse_field(connect_msg, "username");
        if (username.empty())
        {
            conn->send(Protocol::encode_error("Username cannot be empty"));
            conn->close();
            return std::nullopt;
        }

        if (connection_manager_->username_exists(username))
        {
            conn->send(Protocol::encode_error("Username already exists"));
            conn->close();
            return std::nullopt;
        }

        // generate user ID and add connection
        const std::string user_id = generate_user_id();
        connection_manager_->add(user_id, conn);
        connection_manager_->set_username(user_id, username);

        std::cout << "User '" << username << "' (ID: " << user_id << ") connected" << std::endl;

        // send CONNECT_ACK
        conn->send(Protocol::encode_connect_ack(user_id));

        // send INIT with message history and active users
        {
            std::lock_guard<std::mutex> lock(message_mutex_);
            const auto users = connection_manager_->get_active_users();
            conn->send(Protocol::encode_init(message_history_, users));
        }

        // notify other users
        const std::string join_msg = Protocol::encode_user_joined(username, user_id);
        connection_manager_->broadcast(join_msg, user_id);

        return user_id;
    }

    void Server::handle_message(const std::shared_ptr<Connection>& conn,
                                const std::string& username,
                                const std::string& message)
    {
        if (username.empty())
            return;

        const std::string text = Protocol::parse_field(message, "text");
        const std::string timestamp = get_timestamp();
        std::cout << "[" << timestamp << "] " << username << ": " << text << std::endl;

        // store message in history
        {
            std::lock_guard<std::mutex> lock(message_mutex_);
            Message msg{
                .username = username,
                .text = text,
                .timestamp = std::chrono::system_clock::now()
            };
            message_history_.push_back(std::move(msg));

            // keep only last 100 messages
            if (message_history_.size() > 100)
                message_history_.erase(message_history_.begin());
        }

        // broadcast to all users
        const std::string broadcast_msg = Protocol::encode_broadcast(username, text, timestamp);
        connection_manager_->broadcast(broadcast_msg);
    }

    void Server::handle_disconnect(const std::string& user_id) const
    {
        // get username before removing
        const std::string username = connection_manager_->get_username_by_user_id(user_id);
        connection_manager_->remove(user_id);

        if (!username.empty())
        {
            // notify other users
            const std::string left_msg = Protocol::encode_user_left(username);
            connection_manager_->broadcast(left_msg);
        }
    }

    std::string Server::generate_user_id()
    {
        const int id = next_user_id_++;
        return "user_" + std::to_string(id);
    }

    std::string Server::get_timestamp()
    {
        const auto now    = std::chrono::system_clock::now();
        const auto time_t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
        return oss.str();
    }
} // namespace chat::server
