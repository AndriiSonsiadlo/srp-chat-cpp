#pragma once

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace chat::log
{
    namespace detail
    {
        inline std::mutex& mutex()
        {
            static std::mutex m;
            return m;
        }

        inline void write(const char* level, const std::string& message)
        {
            const auto now    = std::chrono::system_clock::now();
            const auto as_time = std::chrono::system_clock::to_time_t(now);

            std::tm utc{};
#ifdef _WIN32
            gmtime_s(&utc, &as_time);
#else
            gmtime_r(&as_time, &utc);
#endif

            std::ostringstream line;
            line << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ") << " [" << level << "] " << message;

            std::lock_guard<std::mutex> lock(mutex());
            std::cerr << line.str() << std::endl;
        }
    }

    inline void info(const std::string& message) { detail::write("info", message); }
    inline void warn(const std::string& message) { detail::write("warn", message); }
    inline void error(const std::string& message) { detail::write("error", message); }
} // namespace chat::log
