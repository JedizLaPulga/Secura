// ============================================================================
// Secura - RSA Encryptor
// ============================================================================
// RSA encryption using OAEP padding with SHA-256.
//
// IMPORTANT: RSA can only encrypt small amounts of data!
// - RSA-2048: Max ~190 bytes
// - RSA-4096: Max ~446 bytes
//
// For larger data, use HYBRID ENCRYPTION:
// 1. Generate a random AES key
// 2. Encrypt your data with AES (using Encryptor)
// 3. Encrypt the AES key with RSA (using RsaEncryptor)
// 4. Send both the RSA-encrypted key and AES-encrypted data
//
// This class provides both direct RSA encryption and hybrid encryption.
// ============================================================================

#ifndef SECURA_RSA_ENCRYPTOR_HPP
#define SECURA_RSA_ENCRYPTOR_HPP

#include "types.hpp"
#include "rsa_key_pair.hpp"
#include <string>
#include <string_view>

namespace secura {

/// Container for hybrid-encrypted data
struct HybridEncryptedData {
    ByteBuffer encrypted_key;   // AES key encrypted with RSA
    ByteBuffer encrypted_data;  // Data encrypted with AES-GCM
};

/// Provides RSA encryption functionality
class RsaEncryptor {
public:
    RsaEncryptor() = default;
    ~RsaEncryptor() = default;

    // Non-copyable, non-movable
    RsaEncryptor(const RsaEncryptor&) = delete;
    RsaEncryptor& operator=(const RsaEncryptor&) = delete;
    RsaEncryptor(RsaEncryptor&&) = delete;
    RsaEncryptor& operator=(RsaEncryptor&&) = delete;

    // ========================================================================
    // Direct RSA Encryption (for small data only!)
    // ========================================================================

    /// Encrypt data directly with RSA (OAEP-SHA256 padding)
    /// @param plaintext The data to encrypt (must be <= max_encrypt_size)
    /// @param public_key The recipient's public key
    /// @return Encrypted data, or an error
    /// @note Use hybrid_encrypt for larger data!
    [[nodiscard]] static Result<ByteBuffer> encrypt(
        ByteSpan plaintext,
        const RsaKeyPair& public_key
    );

    // ========================================================================
    // Hybrid Encryption (RSA + AES, for any size data)
    // ========================================================================

    /// Encrypt data using hybrid encryption (RSA + AES-256-GCM)
    /// This is the recommended method for encrypting data of any size.
    /// @param plaintext The data to encrypt
    /// @param public_key The recipient's public key
    /// @return Encrypted key + encrypted data, or an error
    [[nodiscard]] static Result<HybridEncryptedData> hybrid_encrypt(
        ByteSpan plaintext,
        const RsaKeyPair& public_key
    );

    /// Encrypt text using hybrid encryption
    /// @param plaintext The text to encrypt
    /// @param public_key The recipient's public key
    [[nodiscard]] static Result<HybridEncryptedData> hybrid_encrypt_text(
        std::string_view plaintext,
        const RsaKeyPair& public_key
    );

    // ========================================================================
    // Serialization (for transmitting hybrid encrypted data)
    // ========================================================================

    /// Serialize hybrid encrypted data to a single buffer
    /// Format: [key_length (4 bytes)] + [encrypted_key] + [encrypted_data]
    [[nodiscard]] static ByteBuffer serialize_hybrid_data(
        const HybridEncryptedData& data
    );

    /// Deserialize hybrid encrypted data from a buffer
    [[nodiscard]] static Result<HybridEncryptedData> deserialize_hybrid_data(
        ByteSpan serialized
    );
};

} // namespace secura

#endif // SECURA_RSA_ENCRYPTOR_HPP
