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

    TEST(AesTest, WrongKeyFailsToDecrypt)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x11);
        const std::vector<uint8_t> other(crypto::AESEngine::KEY_SIZE, 0x22);

        const auto sealed = crypto::AESEngine::encrypt_string("secret", key);
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(sealed, other), std::runtime_error);
    }

    TEST(AesTest, FlippedTagBitIsRejected)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x33);
        auto sealed = crypto::AESEngine::encrypt_string("secret", key);

        sealed.back() ^= 0x01; // last byte is inside the GCM tag
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(sealed, key), std::runtime_error);
    }

    TEST(AesTest, FlippedCiphertextBitIsRejected)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x44);
        auto sealed = crypto::AESEngine::encrypt_string("a much longer secret message", key);

        sealed[crypto::AESEngine::IV_SIZE + 2] ^= 0x01;
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(sealed, key), std::runtime_error);
    }

    TEST(AesTest, TruncatedPayloadIsRejected)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x55);
        auto sealed = crypto::AESEngine::encrypt_string("secret", key);

        sealed.resize(sealed.size() - 4);
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(sealed, key), std::runtime_error);

        const std::vector<uint8_t> far_too_short(4, 0x00);
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(far_too_short, key), std::runtime_error);
    }

    TEST(AesTest, RepeatedEncryptionUsesAFreshIv)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x66);

        const auto first  = crypto::AESEngine::encrypt_string("same text", key);
        const auto second = crypto::AESEngine::encrypt_string("same text", key);

        // GCM is catastrophically broken by IV reuse; identical plaintext must
        // still produce different bytes.
        EXPECT_NE(first, second);
        EXPECT_NE(std::vector<uint8_t>(first.begin(), first.begin() + crypto::AESEngine::IV_SIZE),
                  std::vector<uint8_t>(second.begin(), second.begin() + crypto::AESEngine::IV_SIZE));
    }

    TEST(AesTest, MismatchedAadIsRejected)
    {
        const std::vector<uint8_t> key(crypto::AESEngine::KEY_SIZE, 0x77);
        const std::vector<uint8_t> aad{'c', 't', 'x', '1'};
        const std::vector<uint8_t> other_aad{'c', 't', 'x', '2'};

        const auto sealed = crypto::AESEngine::encrypt_string("secret", key, aad);
        EXPECT_EQ(crypto::AESEngine::decrypt_string(sealed, key, aad), "secret");
        EXPECT_THROW((void)crypto::AESEngine::decrypt_string(sealed, key, other_aad), std::runtime_error);
    }

    TEST(AesTest, WrongKeySizeIsRejected)
    {
        const std::vector<uint8_t> short_key(16, 0x88);
        EXPECT_THROW((void)crypto::AESEngine::encrypt_string("secret", short_key), std::runtime_error);
    }

    TEST(AesTest, HkdfIsDeterministicAndSaltDependent)
    {
        const std::vector<uint8_t> ikm(32, 0x99);
        const std::vector<uint8_t> salt_a(16, 0x01);
        const std::vector<uint8_t> salt_b(16, 0x02);
        const std::string info = "srp-chat/aes-256-gcm/v1";

        const auto key_a1 = crypto::AESEngine::derive_key(ikm, salt_a, info);
        const auto key_a2 = crypto::AESEngine::derive_key(ikm, salt_a, info);
        const auto key_b  = crypto::AESEngine::derive_key(ikm, salt_b, info);

        EXPECT_EQ(key_a1.size(), crypto::AESEngine::KEY_SIZE);
        EXPECT_EQ(key_a1, key_a2);
        EXPECT_NE(key_a1, key_b);
        EXPECT_NE(key_a1, crypto::AESEngine::derive_key(ikm, salt_a, "different-info"));
    }
} // namespace chat::crypto
