#pragma once

#include <cstdint>
#include <vector>

namespace chat::server
{
    /**
     * Somewhere a packet can be delivered. Session implements it over a socket;
     * tests implement it over a vector. Room depends only on this, which is why
     * Room needs no io_context to be tested.
     */
    class Sink
    {
    public:
        virtual ~Sink() = default;

        // Must not block: implementations enqueue and return.
        virtual void send(std::vector<uint8_t> packet) = 0;
        virtual void close()                           = 0;
    };
} // namespace chat::server
