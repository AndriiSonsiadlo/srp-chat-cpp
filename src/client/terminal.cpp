#include "chat/client/terminal.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>

#include <openssl/crypto.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace chat::client::terminal
{
    namespace
    {
        bool stdin_is_tty()
        {
#ifdef _WIN32
            return _isatty(_fileno(stdin)) != 0;
#else
            return ::isatty(STDIN_FILENO) != 0;
#endif
        }

        bool stdout_is_tty()
        {
#ifdef _WIN32
            return _isatty(_fileno(stdout)) != 0;
#else
            return ::isatty(STDOUT_FILENO) != 0;
#endif
        }

        // RAII echo suppression: restores the original mode even if the read throws.
        class EchoOff
        {
        public:
            EchoOff()
            {
#ifdef _WIN32
                handle_ = GetStdHandle(STD_INPUT_HANDLE);
                if (GetConsoleMode(handle_, &original_)) {
                    active_ = true;
                    SetConsoleMode(handle_, original_ & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
                }
#else
                if (tcgetattr(STDIN_FILENO, &original_) == 0) {
                    active_       = true;
                    termios quiet = original_;
                    quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
                    tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
                }
#endif
            }

            ~EchoOff()
            {
                if (!active_) return;
#ifdef _WIN32
                SetConsoleMode(handle_, original_);
#else
                tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
#endif
            }

            EchoOff(const EchoOff&)            = delete;
            EchoOff& operator=(const EchoOff&) = delete;

        private:
            bool active_ = false;
#ifdef _WIN32
            HANDLE handle_{};
            DWORD original_{};
#else
            termios original_{};
#endif
        };
    }

    std::string read_password(const std::string& prompt)
    {
        std::cout << prompt << std::flush;

        std::string password;
        if (stdin_is_tty()) {
            const EchoOff guard;
            std::getline(std::cin, password);
            std::cout << std::endl; // the user's Enter was not echoed
        }
        else {
            std::getline(std::cin, password);
        }

        return password;
    }

    bool colors_enabled()
    {
        static const bool enabled = (std::getenv("NO_COLOR") == nullptr) && stdout_is_tty();
        return enabled;
    }

    const char* color(const char* ansi)
    {
        return colors_enabled() ? ansi : "";
    }

    void clear_screen()
    {
        if (colors_enabled())
            std::cout << "\033[2J\033[H" << std::flush; // clear, cursor home
    }

    void clear_line()
    {
        if (colors_enabled())
            std::cout << "\r\033[2K" << std::flush; // carriage return, erase line
        else
            std::cout << "\n";
    }

    void wipe(std::string& secret)
    {
        if (!secret.empty())
            OPENSSL_cleanse(secret.data(), secret.size());
        secret.clear();
    }
} // namespace chat::client::terminal
