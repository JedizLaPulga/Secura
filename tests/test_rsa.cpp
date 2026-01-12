// ============================================================================
// Secura - RSA Unit Tests
// ============================================================================

#include <gtest/gtest.h>
#include "secura/rsa_key_pair.hpp"
#include "secura/rsa_encryptor.hpp"
#include "secura/rsa_decryptor.hpp"

#include <filesystem>
#include <fstream>

namespace secura::tests {

// ============================================================================
// Key Generation Tests
// ============================================================================

TEST(RsaKeyPairTest, Generate2048_Succeeds) {
    auto result = RsaKeyPair::generate(RsaKeySize::Bits2048);
    
    ASSERT_TRUE(result.has_value()) << "RSA-2048 key generation should succeed";
    EXPECT_TRUE(result->is_valid());
    EXPECT_TRUE(result->has_public_key());
    EXPECT_TRUE(result->has_private_key());
    EXPECT_EQ(result->key_size_bits(), 2048);
}

TEST(RsaKeyPairTest, Generate4096_Succeeds) {
    auto result = RsaKeyPair::generate(RsaKeySize::Bits4096);
    
    ASSERT_TRUE(result.has_value()) << "RSA-4096 key generation should succeed";
    EXPECT_TRUE(result->is_valid());
    EXPECT_EQ(result->key_size_bits(), 4096);
}

TEST(RsaKeyPairTest, MaxEncryptSize_2048) {
    auto result = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(result.has_value());
    
    // RSA-2048 with OAEP-SHA256: 256 - 66 = 190 bytes max
    EXPECT_EQ(result->max_encrypt_size(), 190);
}

TEST(RsaKeyPairTest, MaxEncryptSize_4096) {
    auto result = RsaKeyPair::generate(RsaKeySize::Bits4096);
    ASSERT_TRUE(result.has_value());
    
    // RSA-4096 with OAEP-SHA256: 512 - 66 = 446 bytes max
    EXPECT_EQ(result->max_encrypt_size(), 446);
}

// ============================================================================
// PEM Export/Import Tests
// ============================================================================

TEST(RsaKeyPairTest, ExportImportPublicKey_RoundTrip) {
    auto original = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(original.has_value());
    
    // Export public key
    auto pem_result = original->export_public_key_pem();
    ASSERT_TRUE(pem_result.has_value());
    EXPECT_TRUE(pem_result->find("-----BEGIN PUBLIC KEY-----") != std::string::npos);
    
    // Import public key
    auto imported = RsaKeyPair::import_public_key_pem(*pem_result);
    ASSERT_TRUE(imported.has_value());
    
    EXPECT_TRUE(imported->has_public_key());
    EXPECT_FALSE(imported->has_private_key());  // Public key only!
    EXPECT_EQ(imported->key_size_bits(), 2048);
}

TEST(RsaKeyPairTest, ExportImportPrivateKey_RoundTrip) {
    auto original = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(original.has_value());
    
    // Export private key
    auto pem_result = original->export_private_key_pem();
    ASSERT_TRUE(pem_result.has_value());
    EXPECT_TRUE(pem_result->find("-----BEGIN PRIVATE KEY-----") != std::string::npos);
    
    // Import private key
    auto imported = RsaKeyPair::import_private_key_pem(*pem_result);
    ASSERT_TRUE(imported.has_value());
    
    EXPECT_TRUE(imported->has_public_key());
    EXPECT_TRUE(imported->has_private_key());
}

TEST(RsaKeyPairTest, ExportImportEncryptedPrivateKey_RoundTrip) {
    auto original = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(original.has_value());
    
    const std::string password = "TestPassword123!";
    
    // Export encrypted private key
    auto pem_result = original->export_private_key_pem_encrypted(password);
    ASSERT_TRUE(pem_result.has_value());
    EXPECT_TRUE(pem_result->find("-----BEGIN ENCRYPTED PRIVATE KEY-----") != std::string::npos);
    
    // Import with correct password
    auto imported = RsaKeyPair::import_private_key_pem_encrypted(*pem_result, password);
    ASSERT_TRUE(imported.has_value());
    EXPECT_TRUE(imported->has_private_key());
}

TEST(RsaKeyPairTest, ImportEncryptedPrivateKey_WrongPassword) {
    auto original = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(original.has_value());
    
    auto pem_result = original->export_private_key_pem_encrypted("CorrectPassword");
    ASSERT_TRUE(pem_result.has_value());
    
    // Try to import with wrong password
    auto imported = RsaKeyPair::import_private_key_pem_encrypted(*pem_result, "WrongPassword");
    ASSERT_FALSE(imported.has_value());
    EXPECT_EQ(imported.error(), ErrorCode::AuthenticationFailed);
}

// ============================================================================
// Direct RSA Encryption Tests
// ============================================================================

TEST(RsaEncryptorTest, EncryptDecrypt_SmallData) {
    auto keypair = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(keypair.has_value());
    
    // Small data that fits in RSA
    ByteBuffer plaintext = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    // Encrypt with public key
    auto encrypted = RsaEncryptor::encrypt(plaintext, *keypair);
    ASSERT_TRUE(encrypted.has_value());
    EXPECT_EQ(encrypted->size(), 256);  // RSA-2048 output is always 256 bytes
    
    // Decrypt with private key
    auto decrypted = RsaDecryptor::decrypt(*encrypted, *keypair);
    ASSERT_TRUE(decrypted.has_value());
    
    EXPECT_EQ(*decrypted, plaintext);
}

TEST(RsaEncryptorTest, EncryptDecrypt_MaxSize) {
    auto keypair = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(keypair.has_value());
    
    // Create data at max size (190 bytes for RSA-2048 with OAEP-SHA256)
    ByteBuffer plaintext(keypair->max_encrypt_size());
    for (std::size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<Byte>(i & 0xFF);
    }
    
    auto encrypted = RsaEncryptor::encrypt(plaintext, *keypair);
    ASSERT_TRUE(encrypted.has_value());
    
    auto decrypted = RsaDecryptor::decrypt(*encrypted, *keypair);
    ASSERT_TRUE(decrypted.has_value());
    
    EXPECT_EQ(*decrypted, plaintext);
}

TEST(RsaEncryptorTest, Encrypt_DataTooLarge_Fails) {
    auto keypair = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(keypair.has_value());
    
    // Data larger than max size
    ByteBuffer too_large(keypair->max_encrypt_size() + 1);
    
    auto result = RsaEncryptor::encrypt(too_large, *keypair);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ErrorCode::InvalidPlaintext);
}

TEST(RsaDecryptorTest, Decrypt_WrongKey_Fails) {
    auto keypair1 = RsaKeyPair::generate(RsaKeySize::Bits2048);
    auto keypair2 = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(keypair1.has_value());
    ASSERT_TRUE(keypair2.has_value());
    
    ByteBuffer plaintext = {1, 2, 3, 4, 5};
    
    // Encrypt with keypair1's public key
    auto encrypted = RsaEncryptor::encrypt(plaintext, *keypair1);
    ASSERT_TRUE(encrypted.has_value());
    
    // Try to decrypt with keypair2's private key
    auto decrypted = RsaDecryptor::decrypt(*encrypted, *keypair2);
    ASSERT_FALSE(decrypted.has_value());
    EXPECT_EQ(decrypted.error(), ErrorCode::DecryptionFailed);
}

TEST(RsaDecryptorTest, Decrypt_PublicKeyOnly_Fails) {
    auto keypair = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(keypair.has_value());
    
    // Export and import only the public key
    auto public_pem = keypair->export_public_key_pem();
    ASSERT_TRUE(public_pem.has_value());
    
    auto public_only = RsaKeyPair::import_public_key_pem(*public_pem);
    ASSERT_TRUE(public_only.has_value());
    
    ByteBuffer plaintext = {1, 2, 3, 4, 5};
    auto encrypted = RsaEncryptor::encrypt(plaintext, *keypair);
    ASSERT_TRUE(encrypted.has_value());
    
    // Try to decrypt with public key only
    auto decrypted = RsaDecryptor::decrypt(*encrypted, *public_only);
    ASSERT_FALSE(decrypted.has_value());
    EXPECT_EQ(decrypted.error(), ErrorCode::InvalidArgument);
}

// ============================================================================
// Hybrid Encryption Tests
// ============================================================================

TEST(RsaHybridTest, HybridEncryptDecrypt_SmallData) {
    auto keypair = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(keypair.has_value());
    
    const std::string original = "Hello, RSA Hybrid Encryption!";
    
    // Encrypt with hybrid (RSA + AES)
    auto encrypted = RsaEncryptor::hybrid_encrypt_text(original, *keypair);
    ASSERT_TRUE(encrypted.has_value());
    
    // Decrypt
    auto decrypted = RsaDecryptor::hybrid_decrypt_text(*encrypted, *keypair);
    ASSERT_TRUE(decrypted.has_value());
    
    EXPECT_EQ(*decrypted, original);
}

TEST(RsaHybridTest, HybridEncryptDecrypt_LargeData) {
    auto keypair = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(keypair.has_value());
    
    // Create 1MB of data (way larger than RSA can handle directly)
    ByteBuffer large_data(1024 * 1024);
    for (std::size_t i = 0; i < large_data.size(); ++i) {
        large_data[i] = static_cast<Byte>(i & 0xFF);
    }
    
    // Encrypt with hybrid
    auto encrypted = RsaEncryptor::hybrid_encrypt(large_data, *keypair);
    ASSERT_TRUE(encrypted.has_value());
    
    // Decrypt
    auto decrypted = RsaDecryptor::hybrid_decrypt(*encrypted, *keypair);
    ASSERT_TRUE(decrypted.has_value());
    
    EXPECT_EQ(*decrypted, large_data);
}

TEST(RsaHybridTest, SerializeDeserialize_RoundTrip) {
    auto keypair = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(keypair.has_value());
    
    const std::string original = "Message to serialize";
    
    // Encrypt
    auto encrypted = RsaEncryptor::hybrid_encrypt_text(original, *keypair);
    ASSERT_TRUE(encrypted.has_value());
    
    // Serialize
    ByteBuffer serialized = RsaEncryptor::serialize_hybrid_data(*encrypted);
    
    // Deserialize
    auto deserialized = RsaEncryptor::deserialize_hybrid_data(serialized);
    ASSERT_TRUE(deserialized.has_value());
    
    // Decrypt from deserialized
    auto decrypted = RsaDecryptor::hybrid_decrypt_text(*deserialized, *keypair);
    ASSERT_TRUE(decrypted.has_value());
    
    EXPECT_EQ(*decrypted, original);
}

TEST(RsaHybridTest, DecryptSerialized_Convenience) {
    auto keypair = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(keypair.has_value());
    
    const std::string original = "Convenience method test";
    
    // Encrypt and serialize
    auto encrypted = RsaEncryptor::hybrid_encrypt_text(original, *keypair);
    ASSERT_TRUE(encrypted.has_value());
    ByteBuffer serialized = RsaEncryptor::serialize_hybrid_data(*encrypted);
    
    // Decrypt directly from serialized data
    auto decrypted = RsaDecryptor::hybrid_decrypt_text_serialized(serialized, *keypair);
    ASSERT_TRUE(decrypted.has_value());
    
    EXPECT_EQ(*decrypted, original);
}

TEST(RsaHybridTest, DecryptWithWrongKey_Fails) {
    auto keypair1 = RsaKeyPair::generate(RsaKeySize::Bits2048);
    auto keypair2 = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(keypair1.has_value());
    ASSERT_TRUE(keypair2.has_value());
    
    const std::string original = "Secret message";
    
    // Encrypt with keypair1
    auto encrypted = RsaEncryptor::hybrid_encrypt_text(original, *keypair1);
    ASSERT_TRUE(encrypted.has_value());
    
    // Try to decrypt with keypair2
    auto decrypted = RsaDecryptor::hybrid_decrypt_text(*encrypted, *keypair2);
    ASSERT_FALSE(decrypted.has_value());
}

// ============================================================================
// File I/O Tests
// ============================================================================

class RsaFileTest : public ::testing::Test {
protected:
    std::filesystem::path temp_dir;
    std::filesystem::path public_key_file;
    std::filesystem::path private_key_file;
    std::filesystem::path encrypted_private_key_file;
    
    void SetUp() override {
        temp_dir = std::filesystem::temp_directory_path() / "secura_rsa_test";
        std::filesystem::create_directories(temp_dir);
        
        public_key_file = temp_dir / "public.pem";
        private_key_file = temp_dir / "private.pem";
        encrypted_private_key_file = temp_dir / "private_encrypted.pem";
    }
    
    void TearDown() override {
        std::filesystem::remove_all(temp_dir);
    }
};

TEST_F(RsaFileTest, SaveLoadPublicKey) {
    auto original = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(original.has_value());
    
    // Save public key
    auto save_result = original->save_public_key(public_key_file);
    ASSERT_TRUE(save_result.has_value());
    
    // Load public key
    auto loaded = RsaKeyPair::load_public_key(public_key_file);
    ASSERT_TRUE(loaded.has_value());
    
    EXPECT_TRUE(loaded->has_public_key());
    EXPECT_FALSE(loaded->has_private_key());
}

TEST_F(RsaFileTest, SaveLoadPrivateKey) {
    auto original = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(original.has_value());
    
    // Save private key
    auto save_result = original->save_private_key(private_key_file);
    ASSERT_TRUE(save_result.has_value());
    
    // Load private key
    auto loaded = RsaKeyPair::load_private_key(private_key_file);
    ASSERT_TRUE(loaded.has_value());
    
    EXPECT_TRUE(loaded->has_private_key());
}

TEST_F(RsaFileTest, SaveLoadEncryptedPrivateKey) {
    auto original = RsaKeyPair::generate(RsaKeySize::Bits2048);
    ASSERT_TRUE(original.has_value());
    
    const std::string password = "FilePassword123!";
    
    // Save encrypted private key
    auto save_result = original->save_private_key_encrypted(encrypted_private_key_file, password);
    ASSERT_TRUE(save_result.has_value());
    
    // Load encrypted private key
    auto loaded = RsaKeyPair::load_private_key_encrypted(encrypted_private_key_file, password);
    ASSERT_TRUE(loaded.has_value());
    
    EXPECT_TRUE(loaded->has_private_key());
}

TEST_F(RsaFileTest, LoadNonexistentFile_Fails) {
    auto result = RsaKeyPair::load_public_key(temp_dir / "nonexistent.pem");
    
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ErrorCode::FileNotFound);
}

} // namespace secura::tests
