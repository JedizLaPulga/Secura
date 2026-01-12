// ============================================================================
// Secura - KeyManager Unit Tests
// ============================================================================

#include <gtest/gtest.h>
#include "secura/key_manager.hpp"

namespace secura::tests {

// ============================================================================
// Key Generation Tests
// ============================================================================

TEST(KeyManagerTest, GenerateKey_ReturnsCorrectSize) {
    auto result = KeyManager::generate_key();
    
    ASSERT_TRUE(result.has_value()) << "Key generation should succeed";
    EXPECT_EQ(result->size(), constants::AES_KEY_SIZE) << "Key should be 32 bytes";
}

TEST(KeyManagerTest, GenerateKey_IsRandom) {
    // Generate two keys and ensure they're different
    auto key1 = KeyManager::generate_key();
    auto key2 = KeyManager::generate_key();
    
    ASSERT_TRUE(key1.has_value());
    ASSERT_TRUE(key2.has_value());
    
    // Keys should be different (probability of collision is 2^-256)
    EXPECT_NE(key1->span().data(), key2->span().data());
    
    // Compare actual bytes
    bool are_equal = std::equal(
        key1->span().begin(), key1->span().end(),
        key2->span().begin(), key2->span().end()
    );
    EXPECT_FALSE(are_equal) << "Two random keys should not be equal";
}

TEST(KeyManagerTest, GenerateNonce_ReturnsCorrectSize) {
    auto result = KeyManager::generate_nonce();
    
    ASSERT_TRUE(result.has_value()) << "Nonce generation should succeed";
    EXPECT_EQ(result->size(), constants::AES_GCM_NONCE_SIZE) << "Nonce should be 12 bytes";
}

TEST(KeyManagerTest, GenerateSalt_ReturnsCorrectSize) {
    auto result = KeyManager::generate_salt();
    
    ASSERT_TRUE(result.has_value()) << "Salt generation should succeed";
    EXPECT_EQ(result->size(), constants::PBKDF2_SALT_SIZE) << "Salt should be 16 bytes";
}

TEST(KeyManagerTest, GenerateRandomBytes_ReturnsCorrectSize) {
    constexpr std::size_t test_size = 64;
    auto result = KeyManager::generate_random_bytes(test_size);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), test_size);
}

TEST(KeyManagerTest, GenerateRandomBytes_ZeroLengthReturnsError) {
    auto result = KeyManager::generate_random_bytes(0);
    
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ErrorCode::InvalidArgument);
}

// ============================================================================
// Password Derivation Tests
// ============================================================================

TEST(KeyManagerTest, DeriveKeyFromPassword_ReturnsCorrectSize) {
    const std::string password = "MySecurePassword123!";
    auto salt_result = KeyManager::generate_salt();
    ASSERT_TRUE(salt_result.has_value());
    
    auto key_result = KeyManager::derive_key_from_password(password, *salt_result, 1000);
    
    ASSERT_TRUE(key_result.has_value()) << "Key derivation should succeed";
    EXPECT_EQ(key_result->size(), constants::AES_KEY_SIZE) << "Derived key should be 32 bytes";
}

TEST(KeyManagerTest, DeriveKeyFromPassword_SameInputsSameOutput) {
    const std::string password = "MySecurePassword123!";
    ByteBuffer salt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    auto key1 = KeyManager::derive_key_from_password(password, salt, 1000);
    auto key2 = KeyManager::derive_key_from_password(password, salt, 1000);
    
    ASSERT_TRUE(key1.has_value());
    ASSERT_TRUE(key2.has_value());
    
    // Same password + salt should produce same key (deterministic)
    bool are_equal = std::equal(
        key1->span().begin(), key1->span().end(),
        key2->span().begin(), key2->span().end()
    );
    EXPECT_TRUE(are_equal) << "Same password and salt should produce same key";
}

TEST(KeyManagerTest, DeriveKeyFromPassword_DifferentSaltsDifferentKeys) {
    const std::string password = "MySecurePassword123!";
    
    auto salt1 = KeyManager::generate_salt();
    auto salt2 = KeyManager::generate_salt();
    ASSERT_TRUE(salt1.has_value());
    ASSERT_TRUE(salt2.has_value());
    
    auto key1 = KeyManager::derive_key_from_password(password, *salt1, 1000);
    auto key2 = KeyManager::derive_key_from_password(password, *salt2, 1000);
    
    ASSERT_TRUE(key1.has_value());
    ASSERT_TRUE(key2.has_value());
    
    // Different salts should produce different keys
    bool are_equal = std::equal(
        key1->span().begin(), key1->span().end(),
        key2->span().begin(), key2->span().end()
    );
    EXPECT_FALSE(are_equal) << "Different salts should produce different keys";
}

TEST(KeyManagerTest, DeriveKeyFromPassword_ShortPasswordReturnsError) {
    const std::string short_password = "short";  // Less than 8 characters
    ByteBuffer salt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    auto result = KeyManager::derive_key_from_password(short_password, salt);
    
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ErrorCode::PasswordTooShort);
}

TEST(KeyManagerTest, DeriveKeyFromPassword_InvalidSaltSizeReturnsError) {
    const std::string password = "MySecurePassword123!";
    ByteBuffer short_salt = {1, 2, 3, 4, 5};  // Less than 16 bytes
    
    auto result = KeyManager::derive_key_from_password(password, short_salt);
    
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ErrorCode::InvalidSaltSize);
}

// ============================================================================
// Validation Tests
// ============================================================================

TEST(KeyManagerTest, ValidatePassword_ValidPassword) {
    auto result = KeyManager::validate_password("ValidPassword123!");
    EXPECT_TRUE(result.has_value());
}

TEST(KeyManagerTest, ValidatePassword_TooShort) {
    auto result = KeyManager::validate_password("short");
    
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ErrorCode::PasswordTooShort);
}

TEST(KeyManagerTest, ValidatePassword_ExactlyMinLength) {
    auto result = KeyManager::validate_password("12345678");  // Exactly 8 chars
    EXPECT_TRUE(result.has_value());
}

TEST(KeyManagerTest, IsValidKeySize) {
    ByteBuffer valid_key(constants::AES_KEY_SIZE);
    ByteBuffer invalid_key(16);  // Wrong size
    
    EXPECT_TRUE(KeyManager::is_valid_key_size(valid_key));
    EXPECT_FALSE(KeyManager::is_valid_key_size(invalid_key));
}

TEST(KeyManagerTest, IsValidNonceSize) {
    ByteBuffer valid_nonce(constants::AES_GCM_NONCE_SIZE);
    ByteBuffer invalid_nonce(8);
    
    EXPECT_TRUE(KeyManager::is_valid_nonce_size(valid_nonce));
    EXPECT_FALSE(KeyManager::is_valid_nonce_size(invalid_nonce));
}

TEST(KeyManagerTest, IsValidSaltSize) {
    ByteBuffer valid_salt(constants::PBKDF2_SALT_SIZE);
    ByteBuffer invalid_salt(8);
    
    EXPECT_TRUE(KeyManager::is_valid_salt_size(valid_salt));
    EXPECT_FALSE(KeyManager::is_valid_salt_size(invalid_salt));
}

} // namespace secura::tests
