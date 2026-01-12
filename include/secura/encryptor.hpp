// ============================================================================
// Secura - Encryptor
// ============================================================================
// The Encryptor class provides AES-256-GCM encryption for:
// - Text strings (UTF-8)
// - Binary data (arbitrary bytes)
// - Files (with size limits for safety)
//
// AES-256-GCM provides:
// - Confidentiality: Data is unreadable without the key
// - Integrity: Any tampering is detected via the authentication tag
// - Authenticity: You can verify the data came from someone with the key
//
// Output format: [nonce (12 bytes)] + [ciphertext] + [auth tag (16 bytes)]
// ============================================================================

#ifndef SECURA_ENCRYPTOR_HPP
#define SECURA_ENCRYPTOR_HPP

#include "types.hpp"
#include <filesystem>
#include <string>
#include <string_view>

namespace secura {

/// Provides AES-256-GCM encryption for text, binary data, and files
class Encryptor {
public:
    Encryptor() = default;
    ~Encryptor() = default;

    // Non-copyable, non-movable
    Encryptor(const Encryptor&) = delete;
    Encryptor& operator=(const Encryptor&) = delete;
    Encryptor(Encryptor&&) = delete;
    Encryptor& operator=(Encryptor&&) = delete;

    // ========================================================================
    // Text Encryption
    // ========================================================================

    /// Encrypt a text string using AES-256-GCM
    /// @param plaintext The text to encrypt (UTF-8)
    /// @param key The 32-byte AES-256 key
    /// @return Ciphertext in format: [nonce][ciphertext][tag], or an error
    [[nodiscard]] static Result<ByteBuffer> encrypt_text(
        std::string_view plaintext,
        ByteSpan key
    );

    /// Encrypt a text string using a password (derives key internally)
    /// @param plaintext The text to encrypt (UTF-8)
    /// @param password The password to derive the key from
    /// @return Ciphertext in format: [salt][nonce][ciphertext][tag], or an error
    [[nodiscard]] static Result<ByteBuffer> encrypt_text_with_password(
        std::string_view plaintext,
        std::string_view password
    );

    // ========================================================================
    // Binary Data Encryption
    // ========================================================================

    /// Encrypt arbitrary binary data using AES-256-GCM
    /// @param plaintext The data to encrypt
    /// @param key The 32-byte AES-256 key
    /// @return Ciphertext in format: [nonce][ciphertext][tag], or an error
    [[nodiscard]] static Result<ByteBuffer> encrypt(
        ByteSpan plaintext,
        ByteSpan key
    );

    /// Encrypt binary data using a password (derives key internally)
    /// @param plaintext The data to encrypt
    /// @param password The password to derive the key from
    /// @return Ciphertext in format: [salt][nonce][ciphertext][tag], or an error
    [[nodiscard]] static Result<ByteBuffer> encrypt_with_password(
        ByteSpan plaintext,
        std::string_view password
    );

    // ========================================================================
    // File Encryption
    // ========================================================================

    /// Encrypt a file and write the ciphertext to another file
    /// @param input_path Path to the file to encrypt
    /// @param output_path Path to write the encrypted file
    /// @param key The 32-byte AES-256 key
    /// @return Success or an error
    [[nodiscard]] static VoidResult encrypt_file(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path,
        ByteSpan key
    );

    /// Encrypt a file using a password
    /// @param input_path Path to the file to encrypt
    /// @param output_path Path to write the encrypted file
    /// @param password The password to derive the key from
    /// @return Success or an error
    [[nodiscard]] static VoidResult encrypt_file_with_password(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path,
        std::string_view password
    );

private:
    /// Internal encryption implementation
    [[nodiscard]] static Result<ByteBuffer> encrypt_impl(
        ByteSpan plaintext,
        ByteSpan key,
        ByteSpan nonce
    );
};

} // namespace secura

#endif // SECURA_ENCRYPTOR_HPP
