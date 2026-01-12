// ============================================================================
// Secura - Decryptor
// ============================================================================
// The Decryptor class provides AES-256-GCM decryption for:
// - Text strings (UTF-8)
// - Binary data (arbitrary bytes)
// - Files
//
// AES-GCM decryption also VERIFIES the authentication tag, which means:
// - If the data was modified → AuthenticationFailed error
// - If the key is wrong → AuthenticationFailed error
// - If the nonce was changed → AuthenticationFailed error
//
// Expected input format: [nonce (12 bytes)] + [ciphertext] + [auth tag (16 bytes)]
// For password-based: [salt (16 bytes)] + [nonce (12 bytes)] + [ciphertext] + [tag (16 bytes)]
// ============================================================================

#ifndef SECURA_DECRYPTOR_HPP
#define SECURA_DECRYPTOR_HPP

#include "types.hpp"
#include <filesystem>
#include <string>
#include <string_view>

namespace secura {

/// Provides AES-256-GCM decryption for text, binary data, and files
class Decryptor {
public:
    Decryptor() = default;
    ~Decryptor() = default;

    // Non-copyable, non-movable
    Decryptor(const Decryptor&) = delete;
    Decryptor& operator=(const Decryptor&) = delete;
    Decryptor(Decryptor&&) = delete;
    Decryptor& operator=(Decryptor&&) = delete;

    // ========================================================================
    // Text Decryption
    // ========================================================================

    /// Decrypt ciphertext back to a text string
    /// @param ciphertext The encrypted data (format: [nonce][ciphertext][tag])
    /// @param key The 32-byte AES-256 key
    /// @return The original text, or an error (especially AuthenticationFailed!)
    [[nodiscard]] static Result<std::string> decrypt_text(
        ByteSpan ciphertext,
        ByteSpan key
    );

    /// Decrypt ciphertext using a password
    /// @param ciphertext The encrypted data (format: [salt][nonce][ciphertext][tag])
    /// @param password The password used during encryption
    /// @return The original text, or an error
    [[nodiscard]] static Result<std::string> decrypt_text_with_password(
        ByteSpan ciphertext,
        std::string_view password
    );

    // ========================================================================
    // Binary Data Decryption
    // ========================================================================

    /// Decrypt ciphertext back to binary data
    /// @param ciphertext The encrypted data (format: [nonce][ciphertext][tag])
    /// @param key The 32-byte AES-256 key
    /// @return The original data, or an error
    [[nodiscard]] static Result<ByteBuffer> decrypt(
        ByteSpan ciphertext,
        ByteSpan key
    );

    /// Decrypt ciphertext using a password
    /// @param ciphertext The encrypted data (format: [salt][nonce][ciphertext][tag])
    /// @param password The password used during encryption
    /// @return The original data, or an error
    [[nodiscard]] static Result<ByteBuffer> decrypt_with_password(
        ByteSpan ciphertext,
        std::string_view password
    );

    // ========================================================================
    // File Decryption
    // ========================================================================

    /// Decrypt a file and write the plaintext to another file
    /// @param input_path Path to the encrypted file
    /// @param output_path Path to write the decrypted file
    /// @param key The 32-byte AES-256 key
    /// @return Success or an error
    [[nodiscard]] static VoidResult decrypt_file(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path,
        ByteSpan key
    );

    /// Decrypt a file using a password
    /// @param input_path Path to the encrypted file
    /// @param output_path Path to write the decrypted file
    /// @param password The password used during encryption
    /// @return Success or an error
    [[nodiscard]] static VoidResult decrypt_file_with_password(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path,
        std::string_view password
    );

private:
    /// Internal decryption implementation
    [[nodiscard]] static Result<ByteBuffer> decrypt_impl(
        ByteSpan ciphertext,  // Just the encrypted data (no nonce/tag)
        ByteSpan key,
        ByteSpan nonce,
        ByteSpan tag
    );
};

} // namespace secura

#endif // SECURA_DECRYPTOR_HPP
