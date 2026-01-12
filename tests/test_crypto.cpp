// ============================================================================
// Secura - Encryptor and Decryptor Integration Tests
// ============================================================================
// These tests verify the full encryption/decryption cycle works correctly.
// ============================================================================

#include <gtest/gtest.h>
#include "secura/encryptor.hpp"
#include "secura/decryptor.hpp"
#include "secura/key_manager.hpp"

#include <filesystem>
#include <fstream>

namespace secura::tests {

// ============================================================================
// Text Encryption/Decryption Tests
// ============================================================================

TEST(CryptoIntegrationTest, EncryptDecryptText_RoundTrip) {
    // Generate a key
    auto key_result = KeyManager::generate_key();
    ASSERT_TRUE(key_result.has_value());
    
    // Original message
    const std::string original = "Hello, Secura! This is a secret message.";
    
    // Encrypt
    auto encrypted_result = Encryptor::encrypt_text(original, key_result->span());
    ASSERT_TRUE(encrypted_result.has_value()) << "Encryption should succeed";
    
    // Ciphertext should be larger than plaintext (nonce + tag overhead)
    EXPECT_GT(encrypted_result->size(), original.size());
    
    // Decrypt
    auto decrypted_result = Decryptor::decrypt_text(*encrypted_result, key_result->span());
    ASSERT_TRUE(decrypted_result.has_value()) << "Decryption should succeed";
    
    // Verify the round-trip
    EXPECT_EQ(*decrypted_result, original) << "Decrypted text should match original";
}

TEST(CryptoIntegrationTest, EncryptDecryptText_WithPassword) {
    const std::string password = "MySecurePassword123!";
    const std::string original = "Secret data encrypted with password";
    
    // Encrypt with password
    auto encrypted = Encryptor::encrypt_text_with_password(original, password);
    ASSERT_TRUE(encrypted.has_value());
    
    // Decrypt with password
    auto decrypted = Decryptor::decrypt_text_with_password(*encrypted, password);
    ASSERT_TRUE(decrypted.has_value());
    
    EXPECT_EQ(*decrypted, original);
}

TEST(CryptoIntegrationTest, DecryptWithWrongKey_FailsAuthentication) {
    // Generate two different keys
    auto key1 = KeyManager::generate_key();
    auto key2 = KeyManager::generate_key();
    ASSERT_TRUE(key1.has_value());
    ASSERT_TRUE(key2.has_value());
    
    const std::string original = "Secret message";
    
    // Encrypt with key1
    auto encrypted = Encryptor::encrypt_text(original, key1->span());
    ASSERT_TRUE(encrypted.has_value());
    
    // Try to decrypt with key2 (wrong key)
    auto decrypted = Decryptor::decrypt_text(*encrypted, key2->span());
    
    // Should fail with AuthenticationFailed
    ASSERT_FALSE(decrypted.has_value());
    EXPECT_EQ(decrypted.error(), ErrorCode::AuthenticationFailed);
}

TEST(CryptoIntegrationTest, DecryptWithWrongPassword_FailsAuthentication) {
    const std::string original = "Secret message";
    
    // Encrypt with one password
    auto encrypted = Encryptor::encrypt_text_with_password(original, "CorrectPassword123");
    ASSERT_TRUE(encrypted.has_value());
    
    // Try to decrypt with wrong password
    auto decrypted = Decryptor::decrypt_text_with_password(*encrypted, "WrongPassword456!");
    
    ASSERT_FALSE(decrypted.has_value());
    EXPECT_EQ(decrypted.error(), ErrorCode::AuthenticationFailed);
}

TEST(CryptoIntegrationTest, TamperedCiphertext_FailsAuthentication) {
    auto key = KeyManager::generate_key();
    ASSERT_TRUE(key.has_value());
    
    const std::string original = "Important data that must not be tampered";
    
    // Encrypt
    auto encrypted = Encryptor::encrypt_text(original, key->span());
    ASSERT_TRUE(encrypted.has_value());
    
    // Tamper with the ciphertext (modify a byte in the middle)
    ByteBuffer tampered = *encrypted;
    if (tampered.size() > 20) {
        tampered[20] ^= 0xFF;  // Flip all bits in one byte
    }
    
    // Try to decrypt tampered data
    auto decrypted = Decryptor::decrypt_text(tampered, key->span());
    
    // Should fail authentication
    ASSERT_FALSE(decrypted.has_value());
    EXPECT_EQ(decrypted.error(), ErrorCode::AuthenticationFailed);
}

// ============================================================================
// Binary Data Tests
// ============================================================================

TEST(CryptoIntegrationTest, EncryptDecryptBinary_RoundTrip) {
    auto key = KeyManager::generate_key();
    ASSERT_TRUE(key.has_value());
    
    // Create some binary data (including null bytes)
    ByteBuffer original = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00, 0x80, 0x7F};
    
    // Encrypt
    auto encrypted = Encryptor::encrypt(original, key->span());
    ASSERT_TRUE(encrypted.has_value());
    
    // Decrypt
    auto decrypted = Decryptor::decrypt(*encrypted, key->span());
    ASSERT_TRUE(decrypted.has_value());
    
    // Verify
    EXPECT_EQ(*decrypted, original);
}

TEST(CryptoIntegrationTest, EncryptEmptyData_ReturnsError) {
    auto key = KeyManager::generate_key();
    ASSERT_TRUE(key.has_value());
    
    ByteBuffer empty;
    
    auto result = Encryptor::encrypt(empty, key->span());
    
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ErrorCode::InvalidPlaintext);
}

TEST(CryptoIntegrationTest, DecryptInvalidCiphertext_ReturnsError) {
    auto key = KeyManager::generate_key();
    ASSERT_TRUE(key.has_value());
    
    // Ciphertext too short (less than nonce + tag)
    ByteBuffer too_short = {1, 2, 3, 4, 5};
    
    auto result = Decryptor::decrypt(too_short, key->span());
    
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ErrorCode::InvalidCiphertext);
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST(CryptoIntegrationTest, EncryptDecrypt_LargeData) {
    auto key = KeyManager::generate_key();
    ASSERT_TRUE(key.has_value());
    
    // Create 1MB of random-ish data
    ByteBuffer large_data(1024 * 1024);
    for (std::size_t i = 0; i < large_data.size(); ++i) {
        large_data[i] = static_cast<Byte>(i & 0xFF);
    }
    
    // Encrypt
    auto encrypted = Encryptor::encrypt(large_data, key->span());
    ASSERT_TRUE(encrypted.has_value());
    
    // Decrypt
    auto decrypted = Decryptor::decrypt(*encrypted, key->span());
    ASSERT_TRUE(decrypted.has_value());
    
    // Verify
    EXPECT_EQ(*decrypted, large_data);
}

TEST(CryptoIntegrationTest, EncryptDecrypt_UnicodeText) {
    auto key = KeyManager::generate_key();
    ASSERT_TRUE(key.has_value());
    
    // Unicode text with various scripts
    const std::string original = u8"Hello 世界 🔐 Привет مرحبا";
    
    auto encrypted = Encryptor::encrypt_text(original, key->span());
    ASSERT_TRUE(encrypted.has_value());
    
    auto decrypted = Decryptor::decrypt_text(*encrypted, key->span());
    ASSERT_TRUE(decrypted.has_value());
    
    EXPECT_EQ(*decrypted, original);
}

TEST(CryptoIntegrationTest, InvalidKeySize_ReturnsError) {
    ByteBuffer invalid_key(16);  // Wrong size (should be 32)
    const std::string data = "test";
    
    auto result = Encryptor::encrypt_text(data, invalid_key);
    
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ErrorCode::InvalidKeySize);
}

// ============================================================================
// File I/O Tests (using temp files)
// ============================================================================

class FileEncryptionTest : public ::testing::Test {
protected:
    std::filesystem::path temp_dir;
    std::filesystem::path input_file;
    std::filesystem::path encrypted_file;
    std::filesystem::path decrypted_file;
    
    void SetUp() override {
        temp_dir = std::filesystem::temp_directory_path() / "secura_test";
        std::filesystem::create_directories(temp_dir);
        
        input_file = temp_dir / "input.txt";
        encrypted_file = temp_dir / "encrypted.bin";
        decrypted_file = temp_dir / "decrypted.txt";
    }
    
    void TearDown() override {
        std::filesystem::remove_all(temp_dir);
    }
    
    void write_file(const std::filesystem::path& path, const std::string& content) {
        std::ofstream file(path, std::ios::binary);
        file.write(content.data(), static_cast<std::streamsize>(content.size()));
    }
    
    std::string read_file(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        return content;
    }
};

TEST_F(FileEncryptionTest, EncryptDecryptFile_RoundTrip) {
    // Create input file
    const std::string original = "This is a test file content for encryption.";
    write_file(input_file, original);
    
    // Generate key
    auto key = KeyManager::generate_key();
    ASSERT_TRUE(key.has_value());
    
    // Encrypt file
    auto encrypt_result = Encryptor::encrypt_file(input_file, encrypted_file, key->span());
    ASSERT_TRUE(encrypt_result.has_value()) << "File encryption should succeed";
    
    // Decrypt file
    auto decrypt_result = Decryptor::decrypt_file(encrypted_file, decrypted_file, key->span());
    ASSERT_TRUE(decrypt_result.has_value()) << "File decryption should succeed";
    
    // Verify content
    std::string decrypted_content = read_file(decrypted_file);
    EXPECT_EQ(decrypted_content, original);
}

TEST_F(FileEncryptionTest, EncryptDecryptFile_WithPassword) {
    const std::string original = "Password-protected file content";
    write_file(input_file, original);
    
    const std::string password = "FilePassword123!";
    
    // Encrypt
    auto encrypt_result = Encryptor::encrypt_file_with_password(
        input_file, encrypted_file, password);
    ASSERT_TRUE(encrypt_result.has_value());
    
    // Decrypt
    auto decrypt_result = Decryptor::decrypt_file_with_password(
        encrypted_file, decrypted_file, password);
    ASSERT_TRUE(decrypt_result.has_value());
    
    // Verify
    EXPECT_EQ(read_file(decrypted_file), original);
}

TEST_F(FileEncryptionTest, EncryptNonexistentFile_ReturnsError) {
    auto key = KeyManager::generate_key();
    ASSERT_TRUE(key.has_value());
    
    std::filesystem::path nonexistent = temp_dir / "does_not_exist.txt";
    
    auto result = Encryptor::encrypt_file(nonexistent, encrypted_file, key->span());
    
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ErrorCode::FileNotFound);
}

} // namespace secura::tests
