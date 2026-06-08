#include "chat/server/server.hpp"

#include <algorithm>
#include <thread>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>

#include "chat/common/log.hpp"
#include "chat/common/messages.hpp"
#include "chat/common/protocol.hpp"
#include "chat/server/session.hpp"

namespace chat::server
{
    using boost::asio::awaitable;
    using boost::asio::co_spawn;
    using boost::asio::detached;
    using boost::asio::use_awaitable;

    Server::Server(ServerConfig config)
        : config_(std::move(config))
          , acceptor_(io_context_,
                      boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), config_.port))
          , srp_server_(std::make_unique<auth::SRPServer>(config_.users_db))
    {
        srp_server_->load();
    }

    Server::~Server()
    {
        stop();
    }

    void Server::run()
    {
        log::info("listening on port " + std::to_string(config_.port)
                  + " (max " + std::to_string(config_.max_connections) + " connections)");

        co_spawn(io_context_, [this] { return accept_loop(); }, detached);
        co_spawn(io_context_, [this] { return session_sweeper(); }, detached);

        // Signals are delivered on the io_context, not in a signal handler, so
        // shutdown can do real work: close the acceptor and persist the database.
        boost::asio::signal_set signals(io_context_, SIGINT, SIGTERM);
        signals.async_wait([this](const boost::system::error_code&, int) {
            log::info("shutting down");
            stop();
        });

        const auto threads = std::max(1u, std::thread::hardware_concurrency());
        std::vector<std::thread> pool;
        pool.reserve(threads - 1);
        for (unsigned i = 1; i < threads; ++i)
            pool.emplace_back([this] { io_context_.run(); });

        io_context_.run();

        for (auto& thread : pool)
            thread.join();

        try {
            srp_server_->save();
            log::info("user database saved");
        }
        catch (const std::exception& e) {
            log::error(std::string("failed to save user database: ") + e.what());
        }
    }

    void Server::stop()
    {
        boost::system::error_code ec;
        acceptor_.close(ec);
        io_context_.stop();
    }

    awaitable<void> Server::accept_loop()
    {
        while (acceptor_.is_open()) {
            boost::system::error_code ec;
            auto socket = co_await acceptor_.async_accept(
                boost::asio::redirect_error(use_awaitable, ec));

            if (ec) {
                if (acceptor_.is_open())
                    log::warn("accept failed: " + ec.message());
                co_return;
            }

            if (open_connections_.load() >= config_.max_connections) {
                log::warn("connection refused: limit of "
                          + std::to_string(config_.max_connections) + " reached");
                boost::system::error_code close_ec;
                socket.close(close_ec);
                continue;
            }

            ++open_connections_;
            std::make_shared<Session>(std::move(socket), *this)->start();
        }
    }

    awaitable<void> Server::session_sweeper()
    {
        boost::asio::steady_timer timer(io_context_);

        while (!io_context_.stopped()) {
            timer.expires_after(std::chrono::seconds(60));

            boost::system::error_code ec;
            co_await timer.async_wait(boost::asio::redirect_error(use_awaitable, ec));
            if (ec)
                co_return;

            srp_server_->clear_expired_sessions(3600);
        }
    }
} // namespace chat::server
