#include <algorithm>
#include <iomanip>
#include <sstream>
#include "chat/common/protocol.hpp"


namespace chat
{
    std::string Protocol::escape(const std::string& str)
    {
        std::string result;
        for (const char c : str)
        {
            if (c == '|' || c == ':' || c == '\n' || c == '\\')
            {
                result += '\\';
            }
            result += c;
        }
        return result;
    }

    std::string Protocol::unescape(const std::string& str)
    {
        std::string result;
        bool escaped = false;
        for (const char c : str)
        {
            if (escaped)
            {
                result  += c;
                escaped = false;
            }
            else if (c == '\\')
            {
                escaped = true;
            }
            else
            {
                result += c;
            }
        }
        return result;
    }
} // namespace chat
