#include "chat/auth/user_store.hpp"
#include "chat/auth/srp_utils.hpp"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

namespace chat::auth
{
    class UserStoreTest : public ::testing::Test
    {
    protected:
        std::filesystem::path path_;

        void SetUp() override
        {
            path_ = std::filesystem::temp_directory_path()
                  / ("user_store_test_" + SRPUtils::random_hex_id(8) + ".db");
        }

        void TearDown() override
        {
            std::error_code ec;
            std::filesystem::remove(path_, ec);
            std::filesystem::remove(path_.string() + ".tmp", ec);
        }

        static UserCredentials make_creds(const std::string& username)
        {
            return UserCredentials{
                .username = username,
                .salt = SRPUtils::random_bytes(SRP_SALT_SIZE),
                .verifier = SRPUtils::random_bytes(64)
            };
        }
    };

    TEST_F(UserStoreTest, RoundTripsThroughDisk)
    {
        const auto creds = make_creds("alice");
        {
            UserStore store(path_.string());
            EXPECT_TRUE(store.insert(creds));
            store.save();
        }

        UserStore reloaded(path_.string());
        reloaded.load();

        ASSERT_TRUE(reloaded.contains("alice"));
        const auto found = reloaded.find("alice");
        ASSERT_TRUE(found.has_value());
        EXPECT_EQ(found->salt, creds.salt);
        EXPECT_EQ(found->verifier, creds.verifier);
    }

    TEST_F(UserStoreTest, DuplicateInsertIsRefused)
    {
        UserStore store(path_.string());
        EXPECT_TRUE(store.insert(make_creds("bob")));
        EXPECT_FALSE(store.insert(make_creds("bob")));
        EXPECT_EQ(store.size(), 1u);
    }

    TEST_F(UserStoreTest, MalformedLinesAreSkipped)
    {
        {
            std::ofstream file(path_);
            file << "# SRP User Database\n";
            file << "this-line-has-no-colons\n";
            file << "onlyone:field\n";
            file << "\n";
            file << "carol:00112233:aabbcc\n";
        }

        UserStore store(path_.string());
        store.load();

        EXPECT_EQ(store.size(), 1u);
        EXPECT_TRUE(store.contains("carol"));
    }

    TEST_F(UserStoreTest, SaveLeavesNoTemporaryFileBehind)
    {
        UserStore store(path_.string());
        store.insert(make_creds("dave"));
        store.save();

        EXPECT_TRUE(std::filesystem::exists(path_));
        EXPECT_FALSE(std::filesystem::exists(path_.string() + ".tmp"));
    }

    TEST_F(UserStoreTest, RejectsUsernamesThatWouldCorruptTheFormat)
    {
        EXPECT_FALSE(UserStore::is_valid_username("has:colon"));
        EXPECT_FALSE(UserStore::is_valid_username("has\nnewline"));
        EXPECT_FALSE(UserStore::is_valid_username(""));
        EXPECT_FALSE(UserStore::is_valid_username(std::string(33, 'a')));
        EXPECT_FALSE(UserStore::is_valid_username("has space"));

        EXPECT_TRUE(UserStore::is_valid_username("alice"));
        EXPECT_TRUE(UserStore::is_valid_username("a_b-c9"));
        EXPECT_TRUE(UserStore::is_valid_username(std::string(32, 'a')));
    }

    TEST_F(UserStoreTest, InsertRejectsInvalidUsername)
    {
        UserStore store(path_.string());
        auto creds = make_creds("bad:name");
        EXPECT_FALSE(store.insert(creds));
        EXPECT_EQ(store.size(), 0u);
    }

    TEST_F(UserStoreTest, EmptyPathMeansInMemoryOnly)
    {
        UserStore store;
        EXPECT_TRUE(store.insert(make_creds("erin")));
        EXPECT_NO_THROW(store.save());
        EXPECT_NO_THROW(store.load());
        EXPECT_TRUE(store.contains("erin")); // load() must not wipe an in-memory store
    }
} // namespace chat::auth
