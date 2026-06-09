#pragma once

#include <string>

namespace chat::client::terminal
{
    // Reads a line with terminal echo disabled. Falls back to a plain read when
    // stdin is not a terminal (a pipe in a test or a script).
    std::string read_password(const std::string& prompt);

    // False when NO_COLOR is set or stdout is not a TTY.
    bool colors_enabled();

    // Returns the escape sequence, or "" when colours are disabled.
    const char* color(const char* ansi);

    void clear_screen();
    void clear_line();

    // Overwrites the contents before clearing, so the password does not linger.
    void wipe(std::string& secret);
} // namespace chat::client::terminal
