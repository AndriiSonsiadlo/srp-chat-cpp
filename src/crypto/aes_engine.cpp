#include "chat/crypto/aes_engine.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <stdexcept>
#include <cstring>

namespace chat::crypto
{
    AESEngine::CipherContext::CipherContext()
        : ctx_(EVP_CIPHER_CTX_new())
    {
        if (!ctx_)
            throw std::runtime_error("Failed to create cipher context");
    }

    AESEngine::CipherContext::~CipherContext()
    {
        if (ctx_)
            EVP_CIPHER_CTX_free(ctx_);
    }

    std::vector<uint8_t> AESEngine::encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& aad)
    {
        if (key.size() != KEY_SIZE)
            throw std::runtime_error("Invalid key size");

        std::vector<uint8_t> iv(IV_SIZE);
        if (RAND_bytes(iv.data(), IV_SIZE) != 1)
            throw std::runtime_error("Failed to generate IV");

        CipherContext ctx;

        // initialize encryption
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                              key.data(), iv.data()) != 1)
            throw std::runtime_error("Failed to initialize encryption");

        // set AAD if provided
        int len = 0;
        if (!aad.empty())
        {
            if (EVP_EncryptUpdate(ctx.get(), nullptr, &len,
                                 aad.data(), static_cast<int>(aad.size())) != 1)
                throw std::runtime_error("Failed to set AAD");
        }

        // encrypt plaintext
        std::vector<uint8_t> ciphertext(plaintext.size());
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                             plaintext.data(), static_cast<int>(plaintext.size())) != 1)
            throw std::runtime_error("Failed to encrypt");

        int ciphertext_len = len;

        // finalize encryption
        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1)
            throw std::runtime_error("Failed to finalize encryption");

        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        // get authentication tag
        std::vector<uint8_t> tag(TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1)
            throw std::runtime_error("Failed to get authentication tag");

        // return IV || ciphertext || tag
        std::vector<uint8_t> result;
        result.reserve(IV_SIZE + ciphertext.size() + TAG_SIZE);
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        result.insert(result.end(), tag.begin(), tag.end());

        return result;
    }

    // decryption
    std::vector<uint8_t> AESEngine::decrypt(
        const std::vector<uint8_t>& encrypted_data,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& aad)
    {
        if (key.size() != KEY_SIZE)
            throw std::runtime_error("Invalid key size");

        if (encrypted_data.size() < IV_SIZE + TAG_SIZE)
            throw std::runtime_error("Invalid encrypted data size");

        // extract IV, ciphertext, and tag
        std::vector<uint8_t> iv(encrypted_data.begin(),
                               encrypted_data.begin() + IV_SIZE);

        size_t ciphertext_len = encrypted_data.size() - IV_SIZE - TAG_SIZE;
        std::vector<uint8_t> ciphertext(
            encrypted_data.begin() + IV_SIZE,
            encrypted_data.begin() + IV_SIZE + ciphertext_len);

        std::vector<uint8_t> tag(
            encrypted_data.end() - TAG_SIZE,
            encrypted_data.end());

        CipherContext ctx;

        // initialize decryption
        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                              key.data(), iv.data()) != 1)
            throw std::runtime_error("Failed to initialize decryption");

        // set AAD if provided
        int len = 0;
        if (!aad.empty())
        {
            if (EVP_DecryptUpdate(ctx.get(), nullptr, &len,
                                 aad.data(), static_cast<int>(aad.size())) != 1)
                throw std::runtime_error("Failed to set AAD");
        }

        // decrypt ciphertext
        std::vector<uint8_t> plaintext(ciphertext.size());
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                             ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
            throw std::runtime_error("Failed to decrypt");

        int plaintext_len = len;

        // set expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                               const_cast<uint8_t*>(tag.data())) != 1)
            throw std::runtime_error("Failed to set authentication tag");

        // finalize decryption (verifies tag)
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1)
            throw std::runtime_error("Authentication failed - message tampered or corrupted");

        plaintext_len += len;
        plaintext.resize(plaintext_len);

        return plaintext;
    }

    // string encryption
    std::vector<uint8_t> AESEngine::encrypt_string(
        const std::string& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& aad)
    {
        std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
        return encrypt(plaintext_bytes, key, aad);
    }

    // string decryption
    std::string AESEngine::decrypt_string(
        const std::vector<uint8_t>& encrypted_data,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& aad)
    {
        auto plaintext_bytes = decrypt(encrypted_data, key, aad);
        return std::string(plaintext_bytes.begin(), plaintext_bytes.end());
    }

    // key derivation using HKDF
    std::vector<uint8_t> AESEngine::derive_key(
        const std::vector<uint8_t>& password,
        const std::vector<uint8_t>& salt,
        const std::string& info)
    {
        std::vector<uint8_t> key(KEY_SIZE);

        EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
        if (!kdf)
            throw std::runtime_error("Failed to fetch HKDF");

        EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);

        if (!kctx)
            throw std::runtime_error("Failed to create KDF context");

        // set HKDF parameters
        OSSL_PARAM params[5];
        const char* digest = "SHA256";

        params[0] = OSSL_PARAM_construct_utf8_string("digest",
                                                     const_cast<char*>(digest), 0);
        params[1] = OSSL_PARAM_construct_octet_string("key",
                                                      const_cast<uint8_t*>(password.data()),
                                                      password.size());
        params[2] = OSSL_PARAM_construct_octet_string("salt",
                                                      const_cast<uint8_t*>(salt.data()),
                                                      salt.size());
        params[3] = OSSL_PARAM_construct_octet_string("info",
                                                      const_cast<char*>(info.data()),
                                                      info.size());
        params[4] = OSSL_PARAM_construct_end();

        if (EVP_KDF_derive(kctx, key.data(), key.size(), params) != 1)
        {
            EVP_KDF_CTX_free(kctx);
            throw std::runtime_error("HKDF key derivation failed");
        }

        EVP_KDF_CTX_free(kctx);
        return key;
    }

} // namespace chat::crypto