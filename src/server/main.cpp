#include "chat/common/log.hpp"
#include "chat/server/server.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

int main(const int argc, char* argv[])
{
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    try {
        const int port = std::stoi(argv[1]);
        if (port < 1024 || port > 65535) {
            std::fprintf(stderr, "Port must be between 1024 and 65535\n");
            return EXIT_FAILURE;
        }

        chat::server::ServerConfig config;
        config.port = static_cast<uint16_t>(port);

        chat::server::Server server(config);
        server.run();
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        chat::log::error(std::string("fatal: ") + e.what());
        return EXIT_FAILURE;
    }
}
