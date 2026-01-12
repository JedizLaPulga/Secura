// ============================================================================
// Secura - RSA Key Pair
// ============================================================================
// RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm.
// It uses two keys:
// - Public Key: Share freely. Used to ENCRYPT messages for you.
// - Private Key: Keep SECRET. Used to DECRYPT messages sent to you.
//
// Common use cases:
// 1. Key Exchange: Encrypt an AES key with someone's public RSA key
// 2. Digital Signatures: Sign data with private key, verify with public key
// 3. NOT for bulk data (slow, size-limited) - use hybrid encryption instead
//
// This implementation supports RSA-2048 and RSA-4096.
// ============================================================================

#ifndef SECURA_RSA_KEY_PAIR_HPP
#define SECURA_RSA_KEY_PAIR_HPP

#include "types.hpp"
#include <filesystem>
#include <string>
#include <string_view>

namespace secura {

/// RSA key sizes supported by Secura
enum class RsaKeySize {
    Bits2048 = 2048,  // Good for most use cases (faster)
    Bits4096 = 4096   // Higher security (slower)
};

/// Holds an RSA key pair (public + private keys)
/// Keys are stored in PEM format for interoperability
class RsaKeyPair {
public:
    /// Create an empty (invalid) key pair
    RsaKeyPair() = default;
    
    /// Destructor securely clears the private key
    ~RsaKeyPair();
    
    // Move operations
    RsaKeyPair(RsaKeyPair&& other) noexcept;
    RsaKeyPair& operator=(RsaKeyPair&& other) noexcept;
    
    // No copying (security: avoid duplicating private keys)
    RsaKeyPair(const RsaKeyPair&) = delete;
    RsaKeyPair& operator=(const RsaKeyPair&) = delete;

    // ========================================================================
    // Key Generation
    // ========================================================================

    /// Generate a new RSA key pair
    /// @param key_size The RSA key size (2048 or 4096 bits)
    /// @return A new key pair, or an error
    [[nodiscard]] static Result<RsaKeyPair> generate(
        RsaKeySize key_size = RsaKeySize::Bits2048
    );

    // ========================================================================
    // Key Import/Export (PEM Format)
    // ========================================================================

    /// Export the public key in PEM format
    /// This is safe to share with anyone who wants to send you encrypted data
    [[nodiscard]] Result<std::string> export_public_key_pem() const;

    /// Export the private key in PEM format
    /// WARNING: Keep this secret! Anyone with this can decrypt your data
    [[nodiscard]] Result<std::string> export_private_key_pem() const;

    /// Export the private key in encrypted PEM format (password-protected)
    /// @param password Password to encrypt the private key
    [[nodiscard]] Result<std::string> export_private_key_pem_encrypted(
        std::string_view password
    ) const;

    /// Import a public key from PEM format
    /// @param pem The PEM-encoded public key
    [[nodiscard]] static Result<RsaKeyPair> import_public_key_pem(
        std::string_view pem
    );

    /// Import a private key from PEM format
    /// @param pem The PEM-encoded private key
    [[nodiscard]] static Result<RsaKeyPair> import_private_key_pem(
        std::string_view pem
    );

    /// Import an encrypted private key from PEM format
    /// @param pem The encrypted PEM-encoded private key
    /// @param password Password to decrypt the private key
    [[nodiscard]] static Result<RsaKeyPair> import_private_key_pem_encrypted(
        std::string_view pem,
        std::string_view password
    );

    // ========================================================================
    // File Operations
    // ========================================================================

    /// Save the public key to a file
    [[nodiscard]] VoidResult save_public_key(const std::filesystem::path& path) const;

    /// Save the private key to a file (unencrypted - be careful!)
    [[nodiscard]] VoidResult save_private_key(const std::filesystem::path& path) const;

    /// Save the private key to a file (encrypted with password)
    [[nodiscard]] VoidResult save_private_key_encrypted(
        const std::filesystem::path& path,
        std::string_view password
    ) const;

    /// Load a public key from a file
    [[nodiscard]] static Result<RsaKeyPair> load_public_key(
        const std::filesystem::path& path
    );

    /// Load a private key from a file
    [[nodiscard]] static Result<RsaKeyPair> load_private_key(
        const std::filesystem::path& path
    );

    /// Load an encrypted private key from a file
    [[nodiscard]] static Result<RsaKeyPair> load_private_key_encrypted(
        const std::filesystem::path& path,
        std::string_view password
    );

    // ========================================================================
    // Key Information
    // ========================================================================

    /// Check if this key pair is valid (has been generated or imported)
    [[nodiscard]] bool is_valid() const noexcept;

    /// Check if this key pair has a public key
    [[nodiscard]] bool has_public_key() const noexcept;

    /// Check if this key pair has a private key
    [[nodiscard]] bool has_private_key() const noexcept;

    /// Get the key size in bits
    [[nodiscard]] std::size_t key_size_bits() const noexcept;

    /// Get the maximum data size that can be encrypted with this key
    /// (For OAEP with SHA-256, this is key_size/8 - 66 bytes)
    [[nodiscard]] std::size_t max_encrypt_size() const noexcept;

    // Internal: Get the OpenSSL EVP_PKEY handle (for Encryptor/Decryptor use)
    [[nodiscard]] void* get_evp_pkey() const noexcept { return evp_pkey_; }

private:
    explicit RsaKeyPair(void* evp_pkey);
    
    void* evp_pkey_ = nullptr;  // OpenSSL EVP_PKEY*
};

} // namespace secura

#endif // SECURA_RSA_KEY_PAIR_HPP
