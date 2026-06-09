#include "chat/common/cli.hpp"

#include <algorithm>
#include <stdexcept>

namespace chat
{
    Cli::Cli(const int argc, char* argv[])
    {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];

            if (!arg.starts_with("--"))
                throw std::runtime_error("Unexpected argument '" + arg + "' (options start with --)");

            arg.erase(0, 2);

            if (const auto eq = arg.find('='); eq != std::string::npos) {
                values_[arg.substr(0, eq)] = arg.substr(eq + 1);
                continue;
            }

            // A following token that is not itself a flag is this flag's value.
            if (i + 1 < argc && !std::string(argv[i + 1]).starts_with("--")) {
                values_[arg] = argv[++i];
                continue;
            }

            values_[arg] = ""; // bare boolean flag
        }
    }

    bool Cli::has(const std::string& name) const
    {
        return values_.contains(name);
    }

    std::string Cli::get(const std::string& name, const std::string& fallback) const
    {
        const auto it = values_.find(name);
        if (it == values_.end() || it->second.empty())
            return fallback;
        return it->second;
    }

    int Cli::get_int(const std::string& name, const int fallback) const
    {
        const auto it = values_.find(name);
        if (it == values_.end() || it->second.empty())
            return fallback;

        try {
            size_t consumed = 0;
            const int value = std::stoi(it->second, &consumed);
            if (consumed != it->second.size())
                throw std::invalid_argument("trailing characters");
            return value;
        }
        catch (const std::exception&) {
            throw std::runtime_error("Option --" + name + " expects a number, got '" + it->second + "'");
        }
    }

    void Cli::expect_known(std::initializer_list<const char*> names) const
    {
        for (const auto& [name, value] : values_) {
            const bool known = std::ranges::any_of(names, [&name](const char* candidate) {
                return name == candidate;
            });

            if (!known)
                throw std::runtime_error("Unknown option --" + name);
        }
    }
} // namespace chat
