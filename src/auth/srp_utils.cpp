#include "chat/auth/srp_utils.hpp"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace chat::auth
{
    // BigNum implementation
    SRPUtils::BigNum::BigNum() : bn_(BN_new())
    {
        if (!bn_) throw std::runtime_error("Failed to create BIGNUM");
    }

    SRPUtils::BigNum::BigNum(const std::vector<uint8_t>& bytes) : bn_(BN_new())
    {
        if (!bn_) throw std::runtime_error("Failed to create BIGNUM");
        if (!BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), bn_))
            throw std::runtime_error("Failed to convert bytes to BIGNUM");
    }

    SRPUtils::BigNum::BigNum(const std::string& hex) : bn_(BN_new())
    {
        if (!bn_) throw std::runtime_error("Failed to create BIGNUM");
        if (!BN_hex2bn(&bn_, hex.c_str()))
            throw std::runtime_error("Failed to convert hex to BIGNUM");
    }

    SRPUtils::BigNum::~BigNum()
    {
        if (bn_) BN_free(bn_);
    }

    SRPUtils::BigNum::BigNum(BigNum&& other) noexcept : bn_(other.bn_)
    {
        other.bn_ = nullptr;
    }

    SRPUtils::BigNum& SRPUtils::BigNum::operator=(BigNum&& other) noexcept
    {
        if (this != &other)
        {
            if (bn_) BN_free(bn_);
            bn_       = other.bn_;
            other.bn_ = nullptr;
        }
        return *this;
    }

    std::vector<uint8_t> SRPUtils::BigNum::to_bytes() const
    {
        int len = BN_num_bytes(bn_);
        std::vector<uint8_t> bytes(len);
        BN_bn2bin(bn_, bytes.data());
        return bytes;
    }

    std::string SRPUtils::BigNum::to_hex() const
    {
        char* hex = BN_bn2hex(bn_);
        if (!hex) throw std::runtime_error("Failed to convert BIGNUM to hex");
        std::string result(hex);
        OPENSSL_free(hex);
        return result;
    }

    // Hash functions
    std::vector<uint8_t> SRPUtils::hash_sha256(const std::vector<uint8_t>& data)
    {
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }

    std::vector<uint8_t> SRPUtils::hash_sha256(const std::string& data)
    {
        return hash_sha256(std::vector<uint8_t>(data.begin(), data.end()));
    }

    std::vector<uint8_t> SRPUtils::hash_multiple(
        const std::vector<std::vector<uint8_t>>& values)
    {
        std::vector<uint8_t> combined;
        for (const auto& v : values)
            combined.insert(combined.end(), v.begin(), v.end());
        return hash_sha256(combined);
    }

    std::vector<uint8_t> SRPUtils::random_bytes(size_t length)
    {
        std::vector<uint8_t> bytes(length);
        if (RAND_bytes(bytes.data(), static_cast<int>(length)) != 1)
            throw std::runtime_error("Failed to generate random bytes");
        return bytes;
    }

    // SRP calculations
    SRPUtils::BigNum SRPUtils::calculate_k(const BigNum& N, const BigNum& g)
    {
        // k = H(N, g)
        auto N_bytes = N.to_bytes();
        auto g_bytes = g.to_bytes();
        auto hash    = hash_multiple({N_bytes, g_bytes});
        return BigNum(hash);
    }

    SRPUtils::BigNum SRPUtils::calculate_u(const BigNum& A, const BigNum& B)
    {
        // u = H(A, B)
        auto A_bytes = A.to_bytes();
        auto B_bytes = B.to_bytes();
        auto hash    = hash_multiple({A_bytes, B_bytes});
        return BigNum(hash);
    }

    SRPUtils::BigNum SRPUtils::calculate_x(
        const std::vector<uint8_t>& salt,
        const std::string& username,
        const std::string& password)
    {
        // x = H(salt, H(username, ":", password))
        std::string identity = username + ":" + password;
        auto inner_hash      = hash_sha256(identity);
        auto combined        = salt;
        combined.insert(combined.end(), inner_hash.begin(), inner_hash.end());
        auto x_hash = hash_sha256(combined);
        return BigNum(x_hash);
    }

    SRPUtils::BigNum SRPUtils::calculate_verifier(
        const BigNum& g,
        const BigNum& x,
        const BigNum& N)
    {
        // v = g^x mod N
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create BN_CTX");

        BigNum v;
        if (!BN_mod_exp(v.get(), g.get(), x.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate verifier");
        }

        BN_CTX_free(ctx);
        return v;
    }

    SRPUtils::BigNum SRPUtils::calculate_B(
        const BigNum& k,
        const BigNum& v,
        const BigNum& g,
        const BigNum& b,
        const BigNum& N)
    {
        // B = kv + g^b mod N
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create BN_CTX");

        BigNum kv, gb, B;

        // kv = k * v mod N
        if (!BN_mod_mul(kv.get(), k.get(), v.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate kv");
        }

        // gb = g^b mod N
        if (!BN_mod_exp(gb.get(), g.get(), b.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate g^b");
        }

        // B = kv + gb mod N
        if (!BN_mod_add(B.get(), kv.get(), gb.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate B");
        }

        BN_CTX_free(ctx);
        return B;
    }

    SRPUtils::BigNum SRPUtils::calculate_S_client(
        const BigNum& N,
        const BigNum& B,
        const BigNum& k,
        const BigNum& g,
        const BigNum& x,
        const BigNum& a,
        const BigNum& u)
    {
        // S = (B - kg^x)^(a + ux) mod N
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create BN_CTX");

        BigNum gx, kgx, base, ux, exp, S;

        // gx = g^x mod N
        if (!BN_mod_exp(gx.get(), g.get(), x.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate g^x");
        }

        // kgx = k * gx mod N
        if (!BN_mod_mul(kgx.get(), k.get(), gx.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate k*g^x");
        }

        // base = B - kgx mod N
        if (!BN_mod_sub(base.get(), B.get(), kgx.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate B - kg^x");
        }

        // ux = u * x
        if (!BN_mul(ux.get(), u.get(), x.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate ux");
        }

        // exp = a + ux
        if (!BN_add(exp.get(), a.get(), ux.get()))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate a + ux");
        }

        // S = base^exp mod N
        if (!BN_mod_exp(S.get(), base.get(), exp.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate S");
        }

        BN_CTX_free(ctx);
        return S;
    }

    SRPUtils::BigNum SRPUtils::calculate_S_server(
        const BigNum& A,
        const BigNum& v,
        const BigNum& u,
        const BigNum& b,
        const BigNum& N)
    {
        // S = (A * v^u)^b mod N
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create BN_CTX");

        BigNum vu, base, S;

        // vu = v^u mod N
        if (!BN_mod_exp(vu.get(), v.get(), u.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate v^u");
        }

        // base = A * vu mod N
        if (!BN_mod_mul(base.get(), A.get(), vu.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate A * v^u");
        }

        // S = base^b mod N
        if (!BN_mod_exp(S.get(), base.get(), b.get(), N.get(), ctx))
        {
            BN_CTX_free(ctx);
            throw std::runtime_error("Failed to calculate S");
        }

        BN_CTX_free(ctx);
        return S;
    }

    std::vector<uint8_t> SRPUtils::calculate_K(const BigNum& S)
    {
        // K = H(S)
        return hash_sha256(S.to_bytes());
    }

    std::vector<uint8_t> SRPUtils::calculate_M(
        const BigNum& N,
        const BigNum& g,
        const std::string& username,
        const std::vector<uint8_t>& salt,
        const BigNum& A,
        const BigNum& B,
        const std::vector<uint8_t>& K)
    {
        // M = H(H(N) XOR H(g), H(username), salt, A, B, K)
        auto H_N         = hash_sha256(N.to_bytes());
        auto H_g         = hash_sha256(g.to_bytes());
        auto H_N_xor_H_g = xor_bytes(H_N, H_g);
        auto H_username  = hash_sha256(username);

        return hash_multiple({
            H_N_xor_H_g,
            H_username,
            salt,
            A.to_bytes(),
            B.to_bytes(),
            K
        });
    }

    std::vector<uint8_t> SRPUtils::calculate_H_AMK(
        const BigNum& A,
        const std::vector<uint8_t>& M,
        const std::vector<uint8_t>& K)
    {
        // H_AMK = H(A, M, K)
        return hash_multiple({A.to_bytes(), M, K});
    }

    std::vector<uint8_t> SRPUtils::xor_bytes(
        const std::vector<uint8_t>& a,
        const std::vector<uint8_t>& b)
    {
        if (a.size() != b.size())
            throw std::runtime_error("XOR operands must be same size");

        std::vector<uint8_t> result(a.size());
        for (size_t i = 0; i < a.size(); ++i)
            result[i] = a[i] ^ b[i];
        return result;
    }

    // Encoding functions
    std::string SRPUtils::bytes_to_hex(const std::vector<uint8_t>& bytes)
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t b : bytes)
            oss << std::setw(2) << static_cast<int>(b);
        return oss.str();
    }

    std::vector<uint8_t> SRPUtils::hex_to_bytes(const std::string& hex)
    {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2)
        {
            std::string byte_str = hex.substr(i, 2);
            uint8_t byte         = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    std::string SRPUtils::bytes_to_base64(const std::vector<uint8_t>& bytes)
    {
        BIO* b64  = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new(BIO_s_mem());
        b64       = BIO_push(b64, bmem);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

        BIO_write(b64, bytes.data(), static_cast<int>(bytes.size()));
        BIO_flush(b64);

        BUF_MEM* bptr;
        BIO_get_mem_ptr(b64, &bptr);

        std::string result(bptr->data, bptr->length);
        BIO_free_all(b64);

        return result;
    }

    std::vector<uint8_t> SRPUtils::base64_to_bytes(const std::string& base64)
    {
        BIO* b64  = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new_mem_buf(base64.data(), static_cast<int>(base64.size()));
        bmem      = BIO_push(b64, bmem);
        BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

        std::vector<uint8_t> result(base64.size());
        int decoded_size = BIO_read(bmem, result.data(), static_cast<int>(result.size()));

        BIO_free_all(bmem);

        if (decoded_size < 0)
            throw std::runtime_error("Base64 decode failed");

        result.resize(decoded_size);
        return result;
    }
} // namespace chat::auth
