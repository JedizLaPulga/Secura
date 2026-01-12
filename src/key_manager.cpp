// ============================================================================
// Secura - Key Manager Implementation
// ============================================================================

#include "secura/key_manager.hpp"

// OpenSSL headers
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace secura {

// ============================================================================
// Random Generation
// ============================================================================

Result<SecureBuffer> KeyManager::generate_key() {
    SecureBuffer key(constants::AES_KEY_SIZE);
    
    // RAND_bytes returns 1 on success, 0 or -1 on failure
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        return std::unexpected(ErrorCode::KeyGenerationFailed);
    }
    
    return key;
}

Result<ByteBuffer> KeyManager::generate_nonce() {
    ByteBuffer nonce(constants::AES_GCM_NONCE_SIZE);
    
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        return std::unexpected(ErrorCode::KeyGenerationFailed);
    }
    
    return nonce;
}

Result<ByteBuffer> KeyManager::generate_salt() {
    ByteBuffer salt(constants::PBKDF2_SALT_SIZE);
    
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        return std::unexpected(ErrorCode::KeyGenerationFailed);
    }
    
    return salt;
}

Result<ByteBuffer> KeyManager::generate_random_bytes(std::size_t length) {
    if (length == 0) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    ByteBuffer bytes(length);
    
    if (RAND_bytes(bytes.data(), static_cast<int>(length)) != 1) {
        return std::unexpected(ErrorCode::KeyGenerationFailed);
    }
    
    return bytes;
}

// ============================================================================
// Password-Based Key Derivation
// ============================================================================

Result<SecureBuffer> KeyManager::derive_key_from_password(
    std::string_view password,
    ByteSpan salt,
    int iterations
) {
    // Validate password
    if (auto result = validate_password(password); !result) {
        return std::unexpected(result.error());
    }
    
    // Validate salt
    if (!is_valid_salt_size(salt)) {
        return std::unexpected(ErrorCode::InvalidSaltSize);
    }
    
    // Validate iterations
    if (iterations < 1) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    SecureBuffer derived_key(constants::AES_KEY_SIZE);
    
    // PKCS5_PBKDF2_HMAC performs PBKDF2 with HMAC-SHA256
    // Parameters:
    // - password: the password bytes
    // - password length
    // - salt: random salt
    // - salt length  
    // - iterations: number of rounds
    // - digest: hash function (SHA-256)
    // - output length: 32 bytes for AES-256
    // - output buffer
    int result = PKCS5_PBKDF2_HMAC(
        password.data(),
        static_cast<int>(password.size()),
        salt.data(),
        static_cast<int>(salt.size()),
        iterations,
        EVP_sha256(),
        static_cast<int>(constants::AES_KEY_SIZE),
        derived_key.data()
    );
    
    if (result != 1) {
        return std::unexpected(ErrorCode::KeyDerivationFailed);
    }
    
    return derived_key;
}

// ============================================================================
// Validation
// ============================================================================

VoidResult KeyManager::validate_password(std::string_view password) {
    if (password.size() < constants::MIN_PASSWORD_LENGTH) {
        return std::unexpected(ErrorCode::PasswordTooShort);
    }
    
    if (password.size() > constants::MAX_PASSWORD_LENGTH) {
        return std::unexpected(ErrorCode::PasswordTooLong);
    }
    
    return {};  // Success (empty expected<void> means success)
}

bool KeyManager::is_valid_key_size(ByteSpan key) noexcept {
    return key.size() == constants::AES_KEY_SIZE;
}

bool KeyManager::is_valid_nonce_size(ByteSpan nonce) noexcept {
    return nonce.size() == constants::AES_GCM_NONCE_SIZE;
}

bool KeyManager::is_valid_salt_size(ByteSpan salt) noexcept {
    return salt.size() == constants::PBKDF2_SALT_SIZE;
}

} // namespace secura
