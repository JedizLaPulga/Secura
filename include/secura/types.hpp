// ============================================================================
// Secura - Common Types and Error Handling
// ============================================================================
// This header defines the foundational types used throughout Secura:
// - Error codes and result types using C++23 std::expected
// - Secure byte containers
// - Type aliases for clarity
// ============================================================================

#ifndef SECURA_TYPES_HPP
#define SECURA_TYPES_HPP

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace secura {

// ============================================================================
// Byte Types
// ============================================================================

/// A single byte (unsigned 8-bit integer)
using Byte = std::uint8_t;

/// A dynamically-sized container for bytes (used for keys, ciphertext, etc.)
using ByteBuffer = std::vector<Byte>;

/// A read-only view into a byte sequence (non-owning, efficient)
using ByteSpan = std::span<const Byte>;

/// A mutable view into a byte sequence
using MutableByteSpan = std::span<Byte>;

// ============================================================================
// Error Codes
// ============================================================================

/// All possible error conditions in Secura
enum class ErrorCode {
    // Success (not typically used with std::expected, but useful for logging)
    Success = 0,

    // Key Management Errors (100-199)
    KeyGenerationFailed = 100,
    KeyDerivationFailed = 101,
    InvalidKeySize = 102,
    InvalidSaltSize = 103,
    PasswordTooShort = 104,
    PasswordTooLong = 105,

    // Encryption Errors (200-299)
    EncryptionFailed = 200,
    InvalidPlaintext = 201,
    CipherInitFailed = 202,
    CipherUpdateFailed = 203,
    CipherFinalizeFailed = 204,

    // Decryption Errors (300-399)
    DecryptionFailed = 300,
    InvalidCiphertext = 301,
    AuthenticationFailed = 302,  // CRITICAL: Tampered data detected!
    InvalidNonce = 303,
    InvalidTag = 304,

    // File I/O Errors (400-499)
    FileNotFound = 400,
    FileReadError = 401,
    FileWriteError = 402,
    FileTooLarge = 403,
    InvalidFilePath = 404,

    // General Errors (500-599)
    InvalidArgument = 500,
    OutOfMemory = 501,
    NotImplemented = 502,
    InternalError = 503,
};

/// Convert an error code to a human-readable string
[[nodiscard]] constexpr std::string_view error_to_string(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::Success: return "Success";
        
        // Key Management
        case ErrorCode::KeyGenerationFailed: return "Key generation failed";
        case ErrorCode::KeyDerivationFailed: return "Key derivation failed";
        case ErrorCode::InvalidKeySize: return "Invalid key size";
        case ErrorCode::InvalidSaltSize: return "Invalid salt size";
        case ErrorCode::PasswordTooShort: return "Password too short (minimum 8 characters)";
        case ErrorCode::PasswordTooLong: return "Password too long (maximum 128 characters)";

        // Encryption
        case ErrorCode::EncryptionFailed: return "Encryption failed";
        case ErrorCode::InvalidPlaintext: return "Invalid plaintext";
        case ErrorCode::CipherInitFailed: return "Cipher initialization failed";
        case ErrorCode::CipherUpdateFailed: return "Cipher update failed";
        case ErrorCode::CipherFinalizeFailed: return "Cipher finalization failed";

        // Decryption
        case ErrorCode::DecryptionFailed: return "Decryption failed";
        case ErrorCode::InvalidCiphertext: return "Invalid ciphertext";
        case ErrorCode::AuthenticationFailed: return "Authentication failed - data may be tampered!";
        case ErrorCode::InvalidNonce: return "Invalid nonce/IV";
        case ErrorCode::InvalidTag: return "Invalid authentication tag";

        // File I/O
        case ErrorCode::FileNotFound: return "File not found";
        case ErrorCode::FileReadError: return "File read error";
        case ErrorCode::FileWriteError: return "File write error";
        case ErrorCode::FileTooLarge: return "File too large";
        case ErrorCode::InvalidFilePath: return "Invalid file path";

        // General
        case ErrorCode::InvalidArgument: return "Invalid argument";
        case ErrorCode::OutOfMemory: return "Out of memory";
        case ErrorCode::NotImplemented: return "Not implemented";
        case ErrorCode::InternalError: return "Internal error";

        default: return "Unknown error";
    }
}

// ============================================================================
// Result Type (using C++23 std::expected)
// ============================================================================

/// A result type that either contains a value T or an ErrorCode
/// Usage: Result<ByteBuffer> encrypt(...) { ... }
///        if (auto result = encrypt(data); result) { use(*result); }
///        else { handle_error(result.error()); }
template <typename T>
using Result = std::expected<T, ErrorCode>;

/// A result type for operations that don't return a value
using VoidResult = std::expected<void, ErrorCode>;

// ============================================================================
// Crypto Constants
// ============================================================================

namespace constants {

/// AES-256 key size in bytes (256 bits)
inline constexpr std::size_t AES_KEY_SIZE = 32;

/// AES-GCM nonce/IV size in bytes (96 bits, recommended by NIST)
inline constexpr std::size_t AES_GCM_NONCE_SIZE = 12;

/// AES-GCM authentication tag size in bytes (128 bits)
inline constexpr std::size_t AES_GCM_TAG_SIZE = 16;

/// Salt size for PBKDF2 key derivation (128 bits)
inline constexpr std::size_t PBKDF2_SALT_SIZE = 16;

/// Number of PBKDF2 iterations (higher = slower but more secure)
/// OWASP recommends 600,000+ for PBKDF2-HMAC-SHA256 (2023)
inline constexpr int PBKDF2_ITERATIONS = 600'000;

/// Minimum password length
inline constexpr std::size_t MIN_PASSWORD_LENGTH = 8;

/// Maximum password length
inline constexpr std::size_t MAX_PASSWORD_LENGTH = 128;

/// Maximum file size for in-memory encryption (100 MB)
inline constexpr std::size_t MAX_FILE_SIZE = 100 * 1024 * 1024;

} // namespace constants

// ============================================================================
// Secure Memory Utilities
// ============================================================================

/// Securely zero out memory (prevents compiler optimization from removing it)
/// Uses C++23's std::memset_explicit if available, otherwise volatile hack
inline void secure_zero(MutableByteSpan buffer) noexcept {
#if __cpp_lib_memset_explicit >= 202207L
    std::memset_explicit(buffer.data(), 0, buffer.size());
#else
    // Volatile pointer prevents compiler from optimizing away the memset
    volatile Byte* ptr = buffer.data();
    for (std::size_t i = 0; i < buffer.size(); ++i) {
        ptr[i] = 0;
    }
#endif
}

/// RAII wrapper for secure memory that zeros itself on destruction
class SecureBuffer {
public:
    SecureBuffer() = default;
    
    explicit SecureBuffer(std::size_t size) : data_(size) {}
    
    explicit SecureBuffer(ByteSpan data) : data_(data.begin(), data.end()) {}
    
    // Move operations
    SecureBuffer(SecureBuffer&& other) noexcept : data_(std::move(other.data_)) {}
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            clear();
            data_ = std::move(other.data_);
        }
        return *this;
    }
    
    // No copying (security: avoid accidental key duplication)
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    ~SecureBuffer() { clear(); }
    
    /// Securely clear the buffer
    void clear() noexcept {
        if (!data_.empty()) {
            secure_zero(data_);
            data_.clear();
        }
    }
    
    /// Resize the buffer
    void resize(std::size_t new_size) { data_.resize(new_size); }
    
    /// Access the underlying data
    [[nodiscard]] Byte* data() noexcept { return data_.data(); }
    [[nodiscard]] const Byte* data() const noexcept { return data_.data(); }
    
    /// Get the size
    [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
    
    /// Check if empty
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
    
    /// Get a span view
    [[nodiscard]] ByteSpan span() const noexcept { return ByteSpan{data_}; }
    [[nodiscard]] MutableByteSpan mutable_span() noexcept { return MutableByteSpan{data_}; }
    
    /// Convert to ByteBuffer (creates a copy - use sparingly for security)
    [[nodiscard]] ByteBuffer to_buffer() const { return data_; }

private:
    ByteBuffer data_;
};

} // namespace secura

#endif // SECURA_TYPES_HPP
