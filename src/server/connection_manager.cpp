#include "chat/server/connection_manager.hpp"
#include <iostream>
#include <utility>

namespace chat::server
{
    Connection::Connection(boost::asio::io_context& io_context)
        : socket_(io_context)
    {
    }

    Connection::socket_type& Connection::socket()
    {
        return socket_;
    }

    void Connection::send(const std::string& message)
    {
        try
        {
            boost::asio::write(socket_, boost::asio::buffer(message));
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error sending message: " << e.what() << std::endl;
        }
    }

    std::string Connection::receive_line()
    {
        try
        {
            std::string line;
            boost::asio::read_until(socket_, buffer_, '\n');
            std::istream is(&buffer_);
            std::getline(is, line);
            return line + "\n";
        }
        catch (const std::exception&)
        {
            throw std::runtime_error("Connection closed");
        }
    }

    void Connection::close()
    {
        try
        {
            socket_.close();
        }
        catch (...)
        {
            // ignore errors on close
        }
    }

    bool Connection::is_open() const
    {
        return socket_.is_open();
    }

    void ConnectionManager::add(const std::string& user_id, std::shared_ptr<Connection> conn)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        connections_[user_id] = std::move(conn);
    }

    void ConnectionManager::set_username(const std::string& user_id, const std::string& username)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        user_id_to_username_[user_id] = username;
    }

    void ConnectionManager::remove(const std::string& user_id)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = user_id_to_username_.find(user_id);
        if (it != user_id_to_username_.end())
            user_id_to_username_.erase(it);

        auto conn_it = connections_.find(user_id);
        if (conn_it != connections_.end())
        {
            conn_it->second->close();
            connections_.erase(conn_it);
        }
    }

    void ConnectionManager::broadcast(const std::string& message, const std::string& exclude_user)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto& [user_id, conn] : connections_)
            if (user_id != exclude_user && conn->is_open())
                try
                {
                    conn->send(message);
                }
                catch (const std::exception& e)
                {
                    std::cerr << "Error broadcasting to " << user_id << ": " << e.what() << std::endl;
                }
    }

    bool ConnectionManager::send_to(const std::string& user_id, const std::string& message)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = connections_.find(user_id);
        if (it != connections_.end() && it->second->is_open())
            try
            {
                it->second->send(message);
                return true;
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error sending to " << user_id << ": " << e.what() << std::endl;
                return false;
            }
        return false;
    }

    std::vector<User> ConnectionManager::get_active_users() const
    {
        std::lock_guard<std::mutex> lock(mutex_);

        std::vector<User> users;
        for (const auto& [user_id, username] : user_id_to_username_)
            users.push_back({username, user_id});
        return users;
    }

    bool ConnectionManager::username_exists(const std::string& username) const
    {
        std::lock_guard<std::mutex> lock(mutex_);

        return std::any_of(user_id_to_username_.begin(), user_id_to_username_.end(), [&](const auto& pair)
        {
            return pair.second == username;
        });
    }

    std::string ConnectionManager::get_user_id_by_username(const std::string& username) const
    {
        std::lock_guard<std::mutex> lock(mutex_);

        for (const auto& [user_id, uname] : user_id_to_username_)
            if (uname == username)
                return user_id;
        return "";
    }

    std::string ConnectionManager::get_username_by_user_id(const std::string& user_id) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (auto it = user_id_to_username_.find(user_id); it != user_id_to_username_.end())
            return it->second;
        return "";
    }
} // namespace chat::server
