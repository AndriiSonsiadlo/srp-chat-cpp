#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "chat/common/types.hpp"
#include "chat/server/sink.hpp"

namespace chat::server
{
    class Server;

    /**
     * One client connection, driven by coroutines.
     *
     * Reads happen in run(); writes are queued and drained by a single writer
     * coroutine on the session's strand, so concurrent broadcasts never
     * interleave frames and never block the broadcaster.
     */
    class Session final : public Sink, public std::enable_shared_from_this<Session>
    {
    public:
        Session(boost::asio::ip::tcp::socket socket, Server& server);

        void start();

        void send(std::vector<uint8_t> packet) override;

        // Flushes whatever is already queued (so a final ERROR_MSG reaches the
        // client) and then shuts the socket down. The watchdog still bounds the
        // flush, so a client that stops reading cannot pin the session open.
        void close() override;

    private:
        boost::asio::awaitable<void> run();
        boost::asio::awaitable<void> writer();
        boost::asio::awaitable<void> watchdog();

        // Returns the authenticated user id, or nullopt if the handshake failed.
        boost::asio::awaitable<std::optional<std::string>> handshake();
        // Post-verification work: duplicate-login check, key derivation, room join,
        // INIT, and the USER_JOINED broadcast. Returns nullopt on duplicate login or
        // a malformed derived key, in which case the caller must not retry.
        boost::asio::awaitable<std::optional<std::string>> finish_login(
            const std::string& username, const std::string& user_id);
        boost::asio::awaitable<void> message_loop(const std::string& user_id);
        boost::asio::awaitable<bool> handle_register(const std::vector<uint8_t>& payload);

        void fail(const std::string& client_message, const std::string& log_message);
        void extend_deadline();

        // Both must run on the strand.
        void hard_close();

        boost::asio::ip::tcp::socket socket_;
        boost::asio::strand<boost::asio::any_io_executor> strand_;
        Server& server_;

        std::deque<std::vector<uint8_t>> write_queue_;
        boost::asio::steady_timer write_signal_;
        bool closing_ = false;

        boost::asio::steady_timer deadline_timer_;
        std::chrono::steady_clock::time_point deadline_;

        std::string username_;
        std::string remote_;
        int auth_attempts_ = 0;
    };
} // namespace chat::server
