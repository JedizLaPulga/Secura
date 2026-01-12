// ============================================================================
// Secura - RSA Decryptor
// ============================================================================
// RSA decryption using OAEP padding with SHA-256.
// Requires the PRIVATE key to decrypt data encrypted with the public key.
// ============================================================================

#ifndef SECURA_RSA_DECRYPTOR_HPP
#define SECURA_RSA_DECRYPTOR_HPP

#include "types.hpp"
#include "rsa_key_pair.hpp"
#include "rsa_encryptor.hpp"  // For HybridEncryptedData
#include <string>

namespace secura {

/// Provides RSA decryption functionality
class RsaDecryptor {
public:
    RsaDecryptor() = default;
    ~RsaDecryptor() = default;

    // Non-copyable, non-movable
    RsaDecryptor(const RsaDecryptor&) = delete;
    RsaDecryptor& operator=(const RsaDecryptor&) = delete;
    RsaDecryptor(RsaDecryptor&&) = delete;
    RsaDecryptor& operator=(RsaDecryptor&&) = delete;

    // ========================================================================
    // Direct RSA Decryption
    // ========================================================================

    /// Decrypt RSA-encrypted data (OAEP-SHA256 padding)
    /// @param ciphertext The encrypted data
    /// @param private_key The private key (must have private key!)
    /// @return Decrypted data, or an error
    [[nodiscard]] static Result<ByteBuffer> decrypt(
        ByteSpan ciphertext,
        const RsaKeyPair& private_key
    );

    // ========================================================================
    // Hybrid Decryption (RSA + AES)
    // ========================================================================

    /// Decrypt hybrid-encrypted data (RSA + AES-256-GCM)
    /// @param encrypted The hybrid encrypted data
    /// @param private_key The private key
    /// @return Decrypted data, or an error
    [[nodiscard]] static Result<ByteBuffer> hybrid_decrypt(
        const HybridEncryptedData& encrypted,
        const RsaKeyPair& private_key
    );

    /// Decrypt hybrid-encrypted data from a serialized buffer
    /// @param serialized The serialized hybrid data
    /// @param private_key The private key
    [[nodiscard]] static Result<ByteBuffer> hybrid_decrypt_serialized(
        ByteSpan serialized,
        const RsaKeyPair& private_key
    );

    /// Decrypt hybrid-encrypted text
    /// @param encrypted The hybrid encrypted data
    /// @param private_key The private key
    /// @return Decrypted text, or an error
    [[nodiscard]] static Result<std::string> hybrid_decrypt_text(
        const HybridEncryptedData& encrypted,
        const RsaKeyPair& private_key
    );

    /// Decrypt hybrid-encrypted text from a serialized buffer
    [[nodiscard]] static Result<std::string> hybrid_decrypt_text_serialized(
        ByteSpan serialized,
        const RsaKeyPair& private_key
    );
};

} // namespace secura

#endif // SECURA_RSA_DECRYPTOR_HPP
