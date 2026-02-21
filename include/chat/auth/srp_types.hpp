#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <array>

namespace chat::auth
{
    // SRP-6a parameters (RFC 5054)
    constexpr size_t SRP_HASH_SIZE = 32; // SHA-256
    constexpr size_t SRP_KEY_SIZE  = 32; // 256-bit key
    constexpr size_t SRP_SALT_SIZE = 16; // 128-bit salt

    // using 2048-bit safe prime from RFC 5054 (Group 14)
    // this is a well-known safe prime for SRP
    constexpr const char* SRP_N_HEX_2048 =
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
        "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
        "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
        "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
        "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
        "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
        "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
        "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

    constexpr const char* SRP_G_HEX = "02"; // generator g = 2

    // SRP session state
    struct SRPSession
    {
        std::string user_id;
        std::vector<uint8_t> A;        // client's public ephemeral key
        std::vector<uint8_t> b;        // server's private ephemeral key
        std::vector<uint8_t> B;        // server's public ephemeral key
        std::vector<uint8_t> salt;     // user's salt
        std::vector<uint8_t> verifier; // user's verifier (v = g^x)
        std::vector<uint8_t> K;        // shared session key
        bool authenticated{false};
    };

    // user credentials stored on server
    struct UserCredentials
    {
        std::string username;
        std::vector<uint8_t> salt;     // random salt
        std::vector<uint8_t> verifier; // v = g^x mod N, where x = H(salt, password)
    };
} // namespace chat::auth
