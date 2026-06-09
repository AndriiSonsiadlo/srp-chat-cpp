#include "chat/common/cli.hpp"
#include "chat/common/log.hpp"
#include "chat/server/server.hpp"

#include <cstdio>
#include <cstdlib>

namespace
{
    void print_usage(const char* program)
    {
        std::printf(
            "Usage: %s [options]\n"
            "\n"
            "  --port <n>               Listen port (default 8888, range 1024-65535)\n"
            "  --users-db <path>        Credential database (default users.db)\n"
            "  --max-connections <n>    Concurrent connection cap (default 256)\n"
            "  --handshake-timeout <s>  Seconds to complete authentication (default 30)\n"
            "  --idle-timeout <s>       Seconds of silence before disconnect (default 120)\n"
            "  --help                   Show this message\n",
            program);
    }
}

int main(const int argc, char* argv[])
{
    try {
        const chat::Cli cli(argc, argv);
        cli.expect_known({"port", "users-db", "max-connections",
                          "handshake-timeout", "idle-timeout", "help"});

        if (cli.has("help")) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }

        chat::server::ServerConfig config;

        const int port = cli.get_int("port", 8888);
        if (port < 1024 || port > 65535)
            throw std::runtime_error("--port must be between 1024 and 65535");
        config.port = static_cast<uint16_t>(port);

        config.users_db = cli.get("users-db", "users.db");

        const int max_connections = cli.get_int("max-connections", 256);
        if (max_connections < 1)
            throw std::runtime_error("--max-connections must be at least 1");
        config.max_connections = static_cast<size_t>(max_connections);

        const int handshake = cli.get_int("handshake-timeout", 30);
        const int idle      = cli.get_int("idle-timeout", 120);
        if (handshake < 1 || idle < 1)
            throw std::runtime_error("timeouts must be at least 1 second");
        config.handshake_timeout = std::chrono::seconds(handshake);
        config.idle_timeout      = std::chrono::seconds(idle);

        chat::server::Server server(config);
        server.run();
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        chat::log::error(e.what());
        std::fprintf(stderr, "Try '%s --help'\n", argv[0]);
        return EXIT_FAILURE;
    }
}
