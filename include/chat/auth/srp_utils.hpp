#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <openssl/bn.h>

namespace chat::auth
{
    /**
     * SRP utility functions for cryptographic operations
     * Implements SRP-6a protocol (RFC 5054)
     */
    class SRPUtils
    {
    public:
        // BigNum wrapper for RAII
        class BigNum
        {
        private:
            BIGNUM* bn_;

        public:
            BigNum();
            explicit BigNum(const std::vector<uint8_t>& bytes);
            explicit BigNum(const std::string& hex);
            ~BigNum();

            // no copy
            BigNum(const BigNum&)            = delete;
            BigNum& operator=(const BigNum&) = delete;

            // move
            BigNum(BigNum&& other) noexcept;
            BigNum& operator=(BigNum&& other) noexcept;

            BIGNUM* get() { return bn_; }
            const BIGNUM* get() const { return bn_; }

            std::vector<uint8_t> to_bytes() const;
            std::string to_hex() const;
        };

        // Hash functions
        static std::vector<uint8_t> hash_sha256(const std::vector<uint8_t>& data);
        static std::vector<uint8_t> hash_sha256(const std::string& data);

        // Hash multiple values
        static std::vector<uint8_t> hash_multiple(
            const std::vector<std::vector<uint8_t>>& values);

        // Random number generation
        static std::vector<uint8_t> random_bytes(size_t length);

        // SRP-specific calculations
        // k = H(N, g)
        static BigNum calculate_k(const BigNum& N, const BigNum& g);

        // u = H(A, B)
        static BigNum calculate_u(const BigNum& A, const BigNum& B);

        // x = H(salt, H(username, ":", password))
        static BigNum calculate_x(
            const std::vector<uint8_t>& salt,
            const std::string& username,
            const std::string& password);

        // v = g^x mod N
        static BigNum calculate_verifier(
            const BigNum& g,
            const BigNum& x,
            const BigNum& N);

        // Server: B = kv + g^b mod N
        static BigNum calculate_B(
            const BigNum& k,
            const BigNum& v,
            const BigNum& g,
            const BigNum& b,
            const BigNum& N);

        // Client: S = (B - kg^x)^(a + ux) mod N
        static BigNum calculate_S_client(
            const BigNum& N,
            const BigNum& B,
            const BigNum& k,
            const BigNum& g,
            const BigNum& x,
            const BigNum& a,
            const BigNum& u);

        // Server: S = (Av^u)^b mod N
        static BigNum calculate_S_server(
            const BigNum& A,
            const BigNum& v,
            const BigNum& u,
            const BigNum& b,
            const BigNum& N);

        // K = H(S)
        static std::vector<uint8_t> calculate_K(const BigNum& S);

        // M = H(H(N) XOR H(g), H(username), salt, A, B, K)
        static std::vector<uint8_t> calculate_M(
            const BigNum& N,
            const BigNum& g,
            const std::string& username,
            const std::vector<uint8_t>& salt,
            const BigNum& A,
            const BigNum& B,
            const std::vector<uint8_t>& K);

        // H_AMK = H(A, M, K) - Server proof
        static std::vector<uint8_t> calculate_H_AMK(
            const BigNum& A,
            const std::vector<uint8_t>& M,
            const std::vector<uint8_t>& K);

        // Convert bytes to/from hex
        static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
        static std::vector<uint8_t> hex_to_bytes(const std::string& hex);

        // Convert bytes to/from base64
        static std::string bytes_to_base64(const std::vector<uint8_t>& bytes);
        static std::vector<uint8_t> base64_to_bytes(const std::string& base64);

    private:
        // XOR two byte arrays
        static std::vector<uint8_t> xor_bytes(
            const std::vector<uint8_t>& a,
            const std::vector<uint8_t>& b);
    };
} // namespace chat::auth
