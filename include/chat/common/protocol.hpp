#pragma once

#include <string>
#include <vector>
#include "chat/common/types.hpp"

namespace chat
{
    class Protocol
    {
    private:
        static std::string escape(const std::string& str);
        static std::string unescape(const std::string& str);
    };
} // namespace chat
