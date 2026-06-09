#pragma once

#include <initializer_list>
#include <map>
#include <string>

namespace chat
{
    /**
     * Minimal long-flag parser: --flag value, --flag=value, and bare --flag.
     * Deliberately not a general argument library — two binaries with a handful
     * of options each do not justify a dependency.
     */
    class Cli
    {
    public:
        Cli(int argc, char* argv[]);

        [[nodiscard]] bool has(const std::string& name) const;
        [[nodiscard]] std::string get(const std::string& name, const std::string& fallback) const;
        [[nodiscard]] int get_int(const std::string& name, int fallback) const;

        // Throws naming the first flag that is not in `names`.
        void expect_known(std::initializer_list<const char*> names) const;

    private:
        std::map<std::string, std::string> values_;
    };
} // namespace chat
