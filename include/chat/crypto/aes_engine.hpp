#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <openssl/evp.h>

namespace chat::crypto
{
    /**
     * AES-256-GCM Encryption Engine
     * Provides authenticated encryption for messages
     */
    class AESEngine
    {
    public:
        // AES-GCM parameters
        static constexpr size_t KEY_SIZE = 32;  // 256 bits
        static constexpr size_t IV_SIZE = 12;   // 96 bits (recommended for GCM)
        static constexpr size_t TAG_SIZE = 16;  // 128 bits authentication tag

        /**
         * Encrypt data using AES-256-GCM
         * @param plaintext Data to encrypt
         * @param key 256-bit encryption key
         * @param aad Additional authenticated data (optional)
         * @return Encrypted data (IV || ciphertext || tag)
         */
        static std::vector<uint8_t> encrypt(
            const std::vector<uint8_t>& plaintext,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& aad = {});

        /**
         * Decrypt data using AES-256-GCM
         * @param encrypted_data Encrypted data (IV || ciphertext || tag)
         * @param key 256-bit encryption key
         * @param aad Additional authenticated data (optional)
         * @return Decrypted plaintext
         * @throws std::runtime_error if authentication fails
         */
        static std::vector<uint8_t> decrypt(
            const std::vector<uint8_t>& encrypted_data,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& aad = {});

        /**
         * Encrypt a string message
         */
        static std::vector<uint8_t> encrypt_string(
            const std::string& plaintext,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& aad = {});

        /**
         * Decrypt to a string message
         */
        static std::string decrypt_string(
            const std::vector<uint8_t>& encrypted_data,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& aad = {});

        /**
         * Derive a room key from password and salt using HKDF
         * @param password User's password (or shared secret)
         * @param salt Random salt
         * @param info Context information
         * @return Derived 256-bit key
         */
        static std::vector<uint8_t> derive_key(
            const std::vector<uint8_t>& password,
            const std::vector<uint8_t>& salt,
            const std::string& info = "chat-room-key");

    private:
        class CipherContext
        {
        private:
            EVP_CIPHER_CTX* ctx_;

        public:
            CipherContext();
            ~CipherContext();

            // No copy
            CipherContext(const CipherContext&) = delete;
            CipherContext& operator=(const CipherContext&) = delete;

            EVP_CIPHER_CTX* get() { return ctx_; }
        };
    };

} // namespace chat::crypto