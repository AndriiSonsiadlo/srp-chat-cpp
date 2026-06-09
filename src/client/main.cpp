#include "chat/client/client.hpp"
#include "chat/common/cli.hpp"
#include "chat/common/log.hpp"

#include <cstdio>
#include <cstdlib>

namespace
{
    void print_usage(const char* program)
    {
        std::printf(
            "Usage: %s --user <name> [options]\n"
            "\n"
            "  --user <name>   Username, 1-32 chars of [A-Za-z0-9_-] (required)\n"
            "  --host <host>   Server host (default localhost)\n"
            "  --port <n>      Server port (default 8888)\n"
            "  --register      Create the account before logging in\n"
            "  --help          Show this message\n",
            program);
    }
}

int main(const int argc, char* argv[])
{
    try {
        const chat::Cli cli(argc, argv);
        cli.expect_known({"user", "host", "port", "register", "help"});

        if (cli.has("help")) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }

        chat::client::ClientConfig config;
        config.host           = cli.get("host", "localhost");
        config.username       = cli.get("user", "");
        config.register_first = cli.has("register");

        if (config.username.empty())
            throw std::runtime_error("--user is required");

        const int port = cli.get_int("port", 8888);
        if (port < 1024 || port > 65535)
            throw std::runtime_error("--port must be between 1024 and 65535");
        config.port = static_cast<uint16_t>(port);

        chat::client::Client client(std::move(config));
        client.run();
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        chat::log::error(e.what());
        std::fprintf(stderr, "Try '%s --help'\n", argv[0]);
        return EXIT_FAILURE;
    }
}
