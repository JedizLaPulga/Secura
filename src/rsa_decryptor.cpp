// ============================================================================
// Secura - RSA Decryptor Implementation
// ============================================================================

#include "secura/rsa_decryptor.hpp"
#include "secura/rsa_encryptor.hpp"
#include "secura/decryptor.hpp"

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <memory>

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
// Direct RSA Decryption
// ============================================================================

Result<ByteBuffer> RsaDecryptor::decrypt(ByteSpan ciphertext, const RsaKeyPair& private_key) {
    if (!private_key.has_private_key()) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    if (ciphertext.empty()) {
        return std::unexpected(ErrorCode::InvalidCiphertext);
    }
    
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(private_key.get_evp_pkey());
    
    // Create decryption context
    UniqueEvpPkeyCtx ctx(EVP_PKEY_CTX_new(pkey, nullptr));
    if (!ctx) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Initialize decryption
    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Set OAEP padding with SHA-256 (must match encryption settings)
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
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen,
                         ciphertext.data(), ciphertext.size()) <= 0) {
        return std::unexpected(ErrorCode::DecryptionFailed);
    }
    
    // Allocate output buffer
    ByteBuffer plaintext(outlen);
    
    // Perform decryption
    int result = EVP_PKEY_decrypt(ctx.get(), plaintext.data(), &outlen,
                                   ciphertext.data(), ciphertext.size());
    
    if (result <= 0) {
        // Decryption failed - could be wrong key or corrupted data
        return std::unexpected(ErrorCode::DecryptionFailed);
    }
    
    plaintext.resize(outlen);
    return plaintext;
}

// ============================================================================
// Hybrid Decryption (RSA + AES)
// ============================================================================

Result<ByteBuffer> RsaDecryptor::hybrid_decrypt(
    const HybridEncryptedData& encrypted,
    const RsaKeyPair& private_key
) {
    if (!private_key.has_private_key()) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    // Step 1: Decrypt the AES key using RSA
    auto aes_key_result = decrypt(encrypted.encrypted_key, private_key);
    if (!aes_key_result) {
        return std::unexpected(aes_key_result.error());
    }
    
    // Verify the decrypted key is the right size for AES-256
    if (aes_key_result->size() != constants::AES_KEY_SIZE) {
        return std::unexpected(ErrorCode::InvalidKeySize);
    }
    
    // Step 2: Decrypt the data using AES-256-GCM
    auto data_result = Decryptor::decrypt(encrypted.encrypted_data, *aes_key_result);
    if (!data_result) {
        return std::unexpected(data_result.error());
    }
    
    return data_result;
}

Result<ByteBuffer> RsaDecryptor::hybrid_decrypt_serialized(
    ByteSpan serialized,
    const RsaKeyPair& private_key
) {
    // Deserialize the hybrid data
    auto data_result = RsaEncryptor::deserialize_hybrid_data(serialized);
    if (!data_result) {
        return std::unexpected(data_result.error());
    }
    
    return hybrid_decrypt(*data_result, private_key);
}

Result<std::string> RsaDecryptor::hybrid_decrypt_text(
    const HybridEncryptedData& encrypted,
    const RsaKeyPair& private_key
) {
    auto result = hybrid_decrypt(encrypted, private_key);
    if (!result) {
        return std::unexpected(result.error());
    }
    
    return std::string(reinterpret_cast<const char*>(result->data()), result->size());
}

Result<std::string> RsaDecryptor::hybrid_decrypt_text_serialized(
    ByteSpan serialized,
    const RsaKeyPair& private_key
) {
    auto result = hybrid_decrypt_serialized(serialized, private_key);
    if (!result) {
        return std::unexpected(result.error());
    }
    
    return std::string(reinterpret_cast<const char*>(result->data()), result->size());
}

} // namespace secura
