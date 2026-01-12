// ============================================================================
// Secura - RSA Encryptor Implementation
// ============================================================================

#include "secura/rsa_encryptor.hpp"
#include "secura/encryptor.hpp"
#include "secura/key_manager.hpp"

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <memory>
#include <cstring>

namespace secura {

// ============================================================================
// RAII Helper
// ============================================================================

namespace {

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ctx) const { if (ctx) EVP_PKEY_CTX_free(ctx); }
};
using UniqueEvpPkeyCtx = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

} // anonymous namespace

// ============================================================================
// Direct RSA Encryption
// ============================================================================

Result<ByteBuffer> RsaEncryptor::encrypt(ByteSpan plaintext, const RsaKeyPair& public_key) {
    if (!public_key.has_public_key()) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    if (plaintext.empty()) {
        return std::unexpected(ErrorCode::InvalidPlaintext);
    }
    
    if (plaintext.size() > public_key.max_encrypt_size()) {
        return std::unexpected(ErrorCode::InvalidPlaintext);  // Data too large for RSA
    }
    
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(public_key.get_evp_pkey());
    
    // Create encryption context
    UniqueEvpPkeyCtx ctx(EVP_PKEY_CTX_new(pkey, nullptr));
    if (!ctx) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Initialize encryption
    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Set OAEP padding with SHA-256 (secure, modern padding)
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Determine output size
    std::size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, 
                         plaintext.data(), plaintext.size()) <= 0) {
        return std::unexpected(ErrorCode::EncryptionFailed);
    }
    
    // Allocate output buffer
    ByteBuffer ciphertext(outlen);
    
    // Perform encryption
    if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &outlen,
                         plaintext.data(), plaintext.size()) <= 0) {
        return std::unexpected(ErrorCode::EncryptionFailed);
    }
    
    ciphertext.resize(outlen);
    return ciphertext;
}

// ============================================================================
// Hybrid Encryption (RSA + AES)
// ============================================================================

Result<HybridEncryptedData> RsaEncryptor::hybrid_encrypt(
    ByteSpan plaintext,
    const RsaKeyPair& public_key
) {
    if (!public_key.has_public_key()) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    if (plaintext.empty()) {
        return std::unexpected(ErrorCode::InvalidPlaintext);
    }
    
    // Step 1: Generate a random AES-256 key
    auto aes_key_result = KeyManager::generate_key();
    if (!aes_key_result) {
        return std::unexpected(aes_key_result.error());
    }
    
    // Step 2: Encrypt the data with AES-256-GCM
    auto aes_encrypted_result = Encryptor::encrypt(plaintext, aes_key_result->span());
    if (!aes_encrypted_result) {
        return std::unexpected(aes_encrypted_result.error());
    }
    
    // Step 3: Encrypt the AES key with RSA
    auto rsa_encrypted_key = encrypt(aes_key_result->span(), public_key);
    if (!rsa_encrypted_key) {
        return std::unexpected(rsa_encrypted_key.error());
    }
    
    // Step 4: Return both encrypted key and encrypted data
    HybridEncryptedData result;
    result.encrypted_key = std::move(*rsa_encrypted_key);
    result.encrypted_data = std::move(*aes_encrypted_result);
    
    return result;
}

Result<HybridEncryptedData> RsaEncryptor::hybrid_encrypt_text(
    std::string_view plaintext,
    const RsaKeyPair& public_key
) {
    ByteSpan data{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    return hybrid_encrypt(data, public_key);
}

// ============================================================================
// Serialization
// ============================================================================

ByteBuffer RsaEncryptor::serialize_hybrid_data(const HybridEncryptedData& data) {
    // Format: [key_length (4 bytes, big-endian)] + [encrypted_key] + [encrypted_data]
    ByteBuffer serialized;
    serialized.reserve(4 + data.encrypted_key.size() + data.encrypted_data.size());
    
    // Write key length as 4-byte big-endian
    uint32_t key_len = static_cast<uint32_t>(data.encrypted_key.size());
    serialized.push_back(static_cast<Byte>((key_len >> 24) & 0xFF));
    serialized.push_back(static_cast<Byte>((key_len >> 16) & 0xFF));
    serialized.push_back(static_cast<Byte>((key_len >> 8) & 0xFF));
    serialized.push_back(static_cast<Byte>(key_len & 0xFF));
    
    // Write encrypted key
    serialized.insert(serialized.end(), data.encrypted_key.begin(), data.encrypted_key.end());
    
    // Write encrypted data
    serialized.insert(serialized.end(), data.encrypted_data.begin(), data.encrypted_data.end());
    
    return serialized;
}

Result<HybridEncryptedData> RsaEncryptor::deserialize_hybrid_data(ByteSpan serialized) {
    if (serialized.size() < 4) {
        return std::unexpected(ErrorCode::InvalidCiphertext);
    }
    
    // Read key length (4 bytes, big-endian)
    uint32_t key_len = (static_cast<uint32_t>(serialized[0]) << 24) |
                       (static_cast<uint32_t>(serialized[1]) << 16) |
                       (static_cast<uint32_t>(serialized[2]) << 8) |
                       static_cast<uint32_t>(serialized[3]);
    
    if (serialized.size() < 4 + key_len) {
        return std::unexpected(ErrorCode::InvalidCiphertext);
    }
    
    HybridEncryptedData result;
    
    // Extract encrypted key
    auto key_start = serialized.data() + 4;
    result.encrypted_key.assign(key_start, key_start + key_len);
    
    // Extract encrypted data
    auto data_start = key_start + key_len;
    auto data_len = serialized.size() - 4 - key_len;
    result.encrypted_data.assign(data_start, data_start + data_len);
    
    return result;
}

} // namespace secura
