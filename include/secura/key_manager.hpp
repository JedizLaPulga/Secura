// ============================================================================
// Secura - Key Manager
// ============================================================================
// The KeyManager handles all cryptographic key operations:
// - Generating random keys for AES-256
// - Deriving keys from passwords using PBKDF2-HMAC-SHA256
// - Generating secure random nonces/IVs
// - Generating random salts for password derivation
//
// All keys are stored in SecureBuffer to ensure they're zeroed on destruction.
// ============================================================================

#ifndef SECURA_KEY_MANAGER_HPP
#define SECURA_KEY_MANAGER_HPP

#include "types.hpp"
#include <string_view>

namespace secura {

/// Manages cryptographic key generation and derivation
class KeyManager {
public:
    KeyManager() = default;
    ~KeyManager() = default;

    // Non-copyable, non-movable (stateless, so no need)
    KeyManager(const KeyManager&) = delete;
    KeyManager& operator=(const KeyManager&) = delete;
    KeyManager(KeyManager&&) = delete;
    KeyManager& operator=(KeyManager&&) = delete;

    // ========================================================================
    // Random Generation
    // ========================================================================

    /// Generate a cryptographically secure random AES-256 key
    /// @return A 32-byte (256-bit) random key in a SecureBuffer, or an error
    [[nodiscard]] static Result<SecureBuffer> generate_key();

    /// Generate a cryptographically secure random nonce for AES-GCM
    /// @return A 12-byte (96-bit) random nonce, or an error
    [[nodiscard]] static Result<ByteBuffer> generate_nonce();

    /// Generate a cryptographically secure random salt for PBKDF2
    /// @return A 16-byte (128-bit) random salt, or an error
    [[nodiscard]] static Result<ByteBuffer> generate_salt();

    /// Generate random bytes of specified length
    /// @param length Number of random bytes to generate
    /// @return Random bytes, or an error
    [[nodiscard]] static Result<ByteBuffer> generate_random_bytes(std::size_t length);

    // ========================================================================
    // Password-Based Key Derivation
    // ========================================================================

    /// Derive an AES-256 key from a password using PBKDF2-HMAC-SHA256
    /// @param password The user's password (UTF-8 encoded)
    /// @param salt Random salt (should be stored alongside ciphertext)
    /// @param iterations Number of PBKDF2 iterations (default: 600,000)
    /// @return A 32-byte derived key in a SecureBuffer, or an error
    [[nodiscard]] static Result<SecureBuffer> derive_key_from_password(
        std::string_view password,
        ByteSpan salt,
        int iterations = constants::PBKDF2_ITERATIONS
    );

    // ========================================================================
    // Validation
    // ========================================================================

    /// Validate that a password meets security requirements
    /// @param password The password to validate
    /// @return Success or an error explaining what's wrong
    [[nodiscard]] static VoidResult validate_password(std::string_view password);

    /// Validate that a key is the correct size for AES-256
    /// @param key The key to validate
    /// @return true if valid, false otherwise
    [[nodiscard]] static bool is_valid_key_size(ByteSpan key) noexcept;

    /// Validate that a nonce is the correct size for AES-GCM
    /// @param nonce The nonce to validate
    /// @return true if valid, false otherwise
    [[nodiscard]] static bool is_valid_nonce_size(ByteSpan nonce) noexcept;

    /// Validate that a salt is the correct size for PBKDF2
    /// @param salt The salt to validate
    /// @return true if valid, false otherwise
    [[nodiscard]] static bool is_valid_salt_size(ByteSpan salt) noexcept;
};

} // namespace secura

#endif // SECURA_KEY_MANAGER_HPP
