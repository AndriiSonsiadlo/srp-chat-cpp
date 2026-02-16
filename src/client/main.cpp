#include "chat/client/client.hpp"
#include <iostream>
#include <cstdlib>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <host> <port> <username>" << std::endl;
        std::cerr << "Example: " << argv[0] << " localhost 8888 alice" << std::endl;
        return EXIT_FAILURE;
    }

    try {
        std::string host = argv[1];
        int port = std::stoi(argv[2]);
        std::string username = argv[3];

        if (username.empty()) {
            std::cerr << "Username cannot be empty" << std::endl;
            return EXIT_FAILURE;
        }

        if (port < 1024 || port > 65535) {
            std::cerr << "Port must be between 1024 and 65535" << std::endl;
            return EXIT_FAILURE;
        }

        chat::client::Client client(host, port, username);
        client.run();

        return EXIT_SUCCESS;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}