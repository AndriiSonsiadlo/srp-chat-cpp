#include "chat/server/server.hpp"
#include <iostream>
#include <csignal>
#include <cstdlib>

std::unique_ptr<chat::server::Server> g_server;

void signal_handler(const int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutting down server..." << std::endl;
        if (g_server) {
            g_server->stop();
        }
        exit(0);
    }
}

int main(const int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        std::cerr << "Example: " << argv[0] << " 8888" << std::endl;
        return EXIT_FAILURE;
    }

    try {
        int port = std::stoi(argv[1]);

        if (port < 1024 || port > 65535) {
            std::cerr << "Port must be between 1024 and 65535" << std::endl;
            return EXIT_FAILURE;
        }

        // set up signal handlers
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        g_server = std::make_unique<chat::server::Server>(port);
        g_server->run();

        return EXIT_SUCCESS;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}