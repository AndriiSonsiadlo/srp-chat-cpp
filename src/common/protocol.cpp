#include <algorithm>
#include <iomanip>
#include <sstream>
#include "chat/common/protocol.hpp"


namespace chat
{
    using Str = std::string;

    std::string Protocol::escape(const std::string& str)
    {
        std::string result;
        for (const char c : str)
        {
            if (c == '|' || c == ':' || c == '\n' || c == '\\')
                result += '\\';
            result += c;
        }
        return result;
    }

    std::string Protocol::unescape(const std::string& str)
    {
        std::string result;
        bool escaped = false;
        for (const char c : str)
        {
            if (escaped)
            {
                result  += c;
                escaped = false;
            }
            else if (c == '\\')
            {
                escaped = true;
            }
            else
            {
                result += c;
            }
        }
        return result;
    }

    std::string Protocol::encode_connect(const std::string& username)
    {
        return "CONNECT|username:" + escape(username) + "\n";
    }

    std::string Protocol::encode_connect_ack(const std::string& user_id)
    {
        return "CONNECT_ACK|user_id:" + escape(user_id) + "\n";
    }

    std::string Protocol::encode_init(
        const std::vector<Message>& messages,
        const std::vector<User>& users)
    {
        std::ostringstream oss;
        oss << "INIT|";

        // encode messages
        oss << "messages:";
        for (size_t i = 0; i < messages.size(); ++i)
        {
            if (i > 0) oss << ";";

            auto time_t = std::chrono::system_clock::to_time_t(messages[i].timestamp);
            std::ostringstream time_oss;
            time_oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");

            oss << escape(messages[i].username) << ","
                << escape(messages[i].text) << ","
                << time_oss.str();
        }

        // encode users
        oss << "|users:";
        for (size_t i = 0; i < users.size(); ++i)
        {
            if (i > 0) oss << ";";
            oss << escape(users[i].username) << "," << escape(users[i].user_id);
        }

        oss << "\n";
        return oss.str();
    }

    std::string Protocol::encode_message(const std::string& text)
    {
        return "MESSAGE|text:" + escape(text) + "\n";
    }

    std::string Protocol::encode_broadcast(
        const std::string& username,
        const std::string& text,
        const std::string& timestamp)
    {
        return "BROADCAST|username:" + escape(username) +
            "|text:" + escape(text) +
            "|timestamp:" + timestamp + "\n";
    }

    std::string Protocol::encode_user_joined(
        const std::string& username,
        const std::string& user_id)
    {
        return "USER_JOINED|username:" + escape(username) +
            "|user_id:" + escape(user_id) + "\n";
    }

    std::string Protocol::encode_user_left(const std::string& username)
    {
        return "USER_LEFT|username:" + escape(username) + "\n";
    }

    std::string Protocol::encode_disconnect()
    {
        return "DISCONNECT\n";
    }

    std::string Protocol::encode_error(const std::string& error_msg)
    {
        return "ERROR|message:" + escape(error_msg) + "\n";
    }

    MessageType Protocol::parse_type(const std::string& message)
    {
        size_t pos = message.find('|');
        if (pos == std::string::npos)
            pos = message.find('\n');

        const std::string type_str = message.substr(0, pos);
        return string_to_message_type(type_str);
    }

    std::string Protocol::parse_field(const std::string& message, const std::string& field_name)
    {
        std::string search = "|" + field_name + ":";
        size_t start       = message.find(search);

        if (start == std::string::npos)
            return "";

        start      += search.length();
        size_t end = message.find('|', start);
        if (end == std::string::npos)
            end = message.find('\n', start);
        if (end == std::string::npos)
            return unescape(message.substr(start));

        return unescape(message.substr(start, end - start));
    }

    std::vector<Message> Protocol::parse_messages(const std::string& messages_str)
    {
        std::vector<Message> messages;

        if (messages_str.empty())
            return messages;

        std::istringstream iss(messages_str);
        std::string msg_token;

        while (std::getline(iss, msg_token, ';'))
        {
            std::istringstream msg_iss(msg_token);
            std::string username, text, timestamp;

            std::getline(msg_iss, username, ',');
            std::getline(msg_iss, text, ',');
            std::getline(msg_iss, timestamp, ',');

            Message msg{
                .username = unescape(username),
                .text = unescape(text),
                .timestamp = std::chrono::system_clock::now()
            };

            messages.push_back(msg);
        }

        return messages;
    }

    std::vector<User> Protocol::parse_users(const std::string& users_str)
    {
        std::vector<User> users;

        if (users_str.empty())
        {
            return users;
        }

        std::istringstream iss(users_str);
        std::string user_token;

        while (std::getline(iss, user_token, ';'))
        {
            std::istringstream user_iss(user_token);
            std::string username, user_id;

            std::getline(user_iss, username, ',');
            std::getline(user_iss, user_id, ',');

            User user;
            user.username = unescape(username);
            user.user_id  = unescape(user_id);

            users.push_back(user);
        }

        return users;
    }
} // namespace chat
