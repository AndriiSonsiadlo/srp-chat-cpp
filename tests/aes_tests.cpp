#include "chat/crypto/aes_engine.hpp"
#include "chat/auth/srp_utils.hpp"
#include <gtest/gtest.h>

namespace chat::crypto
{
    class AESEngineTest : public ::testing::Test
    {
    protected:
        std::vector<uint8_t> test_key;

        void SetUp() override
        {
            test_key = auth::SRPUtils::random_bytes(AESEngine::KEY_SIZE);
        }
    };

    TEST_F(AESEngineTest, EncryptDecryptBasic)
    {
        std::string plaintext = "Hello, World!";

        auto encrypted = AESEngine::encrypt_string(plaintext, test_key);
        EXPECT_GE(encrypted.size(), AESEngine::IV_SIZE + plaintext.size() + AESEngine::TAG_SIZE);

        auto decrypted = AESEngine::decrypt_string(encrypted, test_key);
        EXPECT_EQ(decrypted, plaintext);
    }

    TEST_F(AESEngineTest, EncryptDecryptEmpty)
    {
        std::string plaintext = "";

        auto encrypted = AESEngine::encrypt_string(plaintext, test_key);
        auto decrypted = AESEngine::decrypt_string(encrypted, test_key);

        EXPECT_EQ(decrypted, plaintext);
    }

    TEST_F(AESEngineTest, EncryptDecryptLongMessage)
    {
        std::string plaintext(10000, 'A');

        auto encrypted = AESEngine::encrypt_string(plaintext, test_key);
        auto decrypted = AESEngine::decrypt_string(encrypted, test_key);

        EXPECT_EQ(decrypted, plaintext);
    }

    TEST_F(AESEngineTest, EncryptDecryptSpecialCharacters)
    {
        std::string plaintext = "Special chars: \n\t\r !@#$%^&*(){}[]<>?/\\|";

        auto encrypted = AESEngine::encrypt_string(plaintext, test_key);
        auto decrypted = AESEngine::decrypt_string(encrypted, test_key);

        EXPECT_EQ(decrypted, plaintext);
    }

    TEST_F(AESEngineTest, EncryptDecryptUnicode)
    {
        std::string plaintext = "Unicode: こんにちは世界 🔒🔐";

        auto encrypted = AESEngine::encrypt_string(plaintext, test_key);
        auto decrypted = AESEngine::decrypt_string(encrypted, test_key);

        EXPECT_EQ(decrypted, plaintext);
    }

    TEST_F(AESEngineTest, DifferentKeysProduceDifferentCiphertext)
    {
        std::string plaintext = "Test message";

        auto key1 = auth::SRPUtils::random_bytes(AESEngine::KEY_SIZE);
        auto key2 = auth::SRPUtils::random_bytes(AESEngine::KEY_SIZE);

        auto encrypted1 = AESEngine::encrypt_string(plaintext, key1);
        auto encrypted2 = AESEngine::encrypt_string(plaintext, key2);

        EXPECT_NE(encrypted1, encrypted2);
    }

    TEST_F(AESEngineTest, SameMessageDifferentIVs)
    {
        std::string plaintext = "Test message";

        auto encrypted1 = AESEngine::encrypt_string(plaintext, test_key);
        auto encrypted2 = AESEngine::encrypt_string(plaintext, test_key);

        EXPECT_NE(encrypted1, encrypted2);

        auto decrypted1 = AESEngine::decrypt_string(encrypted1, test_key);
        auto decrypted2 = AESEngine::decrypt_string(encrypted2, test_key);

        EXPECT_EQ(decrypted1, plaintext);
        EXPECT_EQ(decrypted2, plaintext);
    }

    TEST_F(AESEngineTest, WrongKeyFailsDecryption)
    {
        std::string plaintext = "Secret message";

        auto encrypted = AESEngine::encrypt_string(plaintext, test_key);
        auto wrong_key = auth::SRPUtils::random_bytes(AESEngine::KEY_SIZE);

        EXPECT_THROW(
            AESEngine::decrypt_string(encrypted, wrong_key),
            std::runtime_error
        );
    }

    TEST_F(AESEngineTest, TamperedCiphertextFailsDecryption)
    {
        std::string plaintext = "Secret message";

        auto encrypted = AESEngine::encrypt_string(plaintext, test_key);
        if (encrypted.size() > AESEngine::IV_SIZE + AESEngine::TAG_SIZE) {
            encrypted[AESEngine::IV_SIZE + 5] ^= 0xFF;
        }

        EXPECT_THROW(
            AESEngine::decrypt_string(encrypted, test_key),
            std::runtime_error
        );
    }

    TEST_F(AESEngineTest, TamperedTagFailsDecryption)
    {
        std::string plaintext           = "Secret message";
        auto encrypted                  = AESEngine::encrypt_string(plaintext, test_key);
        encrypted[encrypted.size() - 1] ^= 0xFF;

        EXPECT_THROW(
            AESEngine::decrypt_string(encrypted, test_key),
            std::runtime_error
        );
    }

    TEST_F(AESEngineTest, InvalidKeySizeThrows)
    {
        std::string plaintext = "Test";
        std::vector<uint8_t> invalid_key(16); // 128 bits, not 256

        EXPECT_THROW(
            AESEngine::encrypt_string(plaintext, invalid_key),
            std::runtime_error
        );
    }

    TEST_F(AESEngineTest, TruncatedDataThrows)
    {
        std::string plaintext = "Test";
        auto encrypted        = AESEngine::encrypt_string(plaintext, test_key);
        encrypted.resize(AESEngine::IV_SIZE);

        EXPECT_THROW(
            AESEngine::decrypt_string(encrypted, test_key),
            std::runtime_error
        );
    }

    TEST_F(AESEngineTest, EncryptDecryptWithAAD)
    {
        std::string plaintext    = "Secret message";
        std::vector<uint8_t> aad = {1, 2, 3, 4, 5};

        auto encrypted = AESEngine::encrypt_string(plaintext, test_key, aad);
        auto decrypted = AESEngine::decrypt_string(encrypted, test_key, aad);

        EXPECT_EQ(decrypted, plaintext);
    }

    TEST_F(AESEngineTest, WrongAADFailsDecryption)
    {
        std::string plaintext     = "Secret message";
        std::vector<uint8_t> aad1 = {1, 2, 3, 4, 5};
        std::vector<uint8_t> aad2 = {1, 2, 3, 4, 6}; // Different

        auto encrypted = AESEngine::encrypt_string(plaintext, test_key, aad1);

        EXPECT_THROW(
            AESEngine::decrypt_string(encrypted, test_key, aad2),
            std::runtime_error
        );
    }

    TEST_F(AESEngineTest, KeyDerivationHKDF)
    {
        std::vector<uint8_t> password = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<uint8_t> salt     = auth::SRPUtils::random_bytes(16);
        std::string info              = "test-key-derivation";

        auto key = AESEngine::derive_key(password, salt, info);

        EXPECT_EQ(key.size(), AESEngine::KEY_SIZE);
    }

    TEST_F(AESEngineTest, KeyDerivationDeterministic)
    {
        std::vector<uint8_t> password = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<uint8_t> salt     = {9, 10, 11, 12, 13, 14, 15, 16};
        std::string info              = "test-key";

        auto key1 = AESEngine::derive_key(password, salt, info);
        auto key2 = AESEngine::derive_key(password, salt, info);

        EXPECT_EQ(key1, key2);
    }

    TEST_F(AESEngineTest, KeyDerivationDifferentInfo)
    {
        std::vector<uint8_t> password = {1, 2, 3, 4, 5, 6, 7, 8};
        std::vector<uint8_t> salt     = {9, 10, 11, 12, 13, 14, 15, 16};

        auto key1 = AESEngine::derive_key(password, salt, "info1");
        auto key2 = AESEngine::derive_key(password, salt, "info2");

        EXPECT_NE(key1, key2);
    }

    TEST_F(AESEngineTest, EncryptDecryptBinary)
    {
        std::vector<uint8_t> plaintext = {0x00, 0x01, 0xFF, 0x80, 0x7F};

        auto encrypted = AESEngine::encrypt(plaintext, test_key);
        auto decrypted = AESEngine::decrypt(encrypted, test_key);

        EXPECT_EQ(decrypted, plaintext);
    }

    TEST_F(AESEngineTest, RoundTripWithBase64)
    {
        std::string plaintext = "Test message for base64 encoding";

        auto encrypted = AESEngine::encrypt_string(plaintext, test_key);
        auto base64    = auth::SRPUtils::bytes_to_base64(encrypted);

        auto decoded   = auth::SRPUtils::base64_to_bytes(base64);
        auto decrypted = AESEngine::decrypt_string(decoded, test_key);

        EXPECT_EQ(decrypted, plaintext);
    }
} // namespace chat::crypto
