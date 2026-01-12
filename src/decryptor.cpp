// ============================================================================
// Secura - Decryptor Implementation
// ============================================================================

#include "secura/decryptor.hpp"
#include "secura/key_manager.hpp"

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/err.h>

// Standard library
#include <fstream>

namespace secura {

// ============================================================================
// Internal Implementation
// ============================================================================

Result<ByteBuffer> Decryptor::decrypt_impl(
    ByteSpan ciphertext,
    ByteSpan key,
    ByteSpan nonce,
    ByteSpan tag
) {
    // Create cipher context with RAII cleanup
    struct ContextDeleter {
        void operator()(EVP_CIPHER_CTX* ctx) const {
            if (ctx) EVP_CIPHER_CTX_free(ctx);
        }
    };
    std::unique_ptr<EVP_CIPHER_CTX, ContextDeleter> ctx(EVP_CIPHER_CTX_new());
    
    if (!ctx) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Initialize decryption with AES-256-GCM
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Set the nonce/IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 
                            static_cast<int>(constants::AES_GCM_NONCE_SIZE), nullptr) != 1) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Set the key and nonce
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Allocate output buffer (same size as ciphertext for GCM)
    ByteBuffer plaintext(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;
    
    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                          ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        return std::unexpected(ErrorCode::DecryptionFailed);
    }
    plaintext_len = len;
    
    // Set the expected authentication tag
    // This MUST be done before calling EVP_DecryptFinal_ex
    // Note: We need to cast away const because OpenSSL's API is poorly designed
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(constants::AES_GCM_TAG_SIZE),
                            const_cast<Byte*>(tag.data())) != 1) {
        return std::unexpected(ErrorCode::InvalidTag);
    }
    
    // Finalize decryption and VERIFY the authentication tag
    // EVP_DecryptFinal_ex returns 0 if the tag doesn't match!
    // This is the critical security check - if it fails, the data was TAMPERED!
    int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len);
    
    if (ret <= 0) {
        // SECURITY CRITICAL: Tag verification failed!
        // This means either:
        // 1. The data was modified after encryption
        // 2. The wrong key was used
        // 3. The nonce was corrupted
        // DO NOT return the partially decrypted data!
        return std::unexpected(ErrorCode::AuthenticationFailed);
    }
    
    plaintext_len += len;
    plaintext.resize(static_cast<std::size_t>(plaintext_len));
    
    return plaintext;
}

// ============================================================================
// Text Decryption
// ============================================================================

Result<std::string> Decryptor::decrypt_text(ByteSpan ciphertext, ByteSpan key) {
    auto result = decrypt(ciphertext, key);
    if (!result) {
        return std::unexpected(result.error());
    }
    
    // Convert bytes to string
    return std::string(reinterpret_cast<const char*>(result->data()), result->size());
}

Result<std::string> Decryptor::decrypt_text_with_password(
    ByteSpan ciphertext,
    std::string_view password
) {
    auto result = decrypt_with_password(ciphertext, password);
    if (!result) {
        return std::unexpected(result.error());
    }
    
    return std::string(reinterpret_cast<const char*>(result->data()), result->size());
}

// ============================================================================
// Binary Data Decryption
// ============================================================================

Result<ByteBuffer> Decryptor::decrypt(ByteSpan ciphertext, ByteSpan key) {
    // Minimum size: nonce + tag (no actual ciphertext for empty plaintext)
    constexpr std::size_t MIN_SIZE = constants::AES_GCM_NONCE_SIZE + constants::AES_GCM_TAG_SIZE;
    
    if (ciphertext.size() < MIN_SIZE) {
        return std::unexpected(ErrorCode::InvalidCiphertext);
    }
    
    if (!KeyManager::is_valid_key_size(key)) {
        return std::unexpected(ErrorCode::InvalidKeySize);
    }
    
    // Extract components from ciphertext:
    // [nonce (12 bytes)] + [encrypted data] + [tag (16 bytes)]
    
    // Extract nonce (first 12 bytes)
    ByteSpan nonce = ciphertext.subspan(0, constants::AES_GCM_NONCE_SIZE);
    
    // Extract tag (last 16 bytes)
    ByteSpan tag = ciphertext.subspan(ciphertext.size() - constants::AES_GCM_TAG_SIZE);
    
    // Extract encrypted data (everything between nonce and tag)
    std::size_t encrypted_size = ciphertext.size() - constants::AES_GCM_NONCE_SIZE - constants::AES_GCM_TAG_SIZE;
    ByteSpan encrypted_data = ciphertext.subspan(constants::AES_GCM_NONCE_SIZE, encrypted_size);
    
    // Decrypt
    return decrypt_impl(encrypted_data, key, nonce, tag);
}

Result<ByteBuffer> Decryptor::decrypt_with_password(ByteSpan ciphertext, std::string_view password) {
    // Minimum size: salt + nonce + tag
    constexpr std::size_t MIN_SIZE = constants::PBKDF2_SALT_SIZE + 
                                     constants::AES_GCM_NONCE_SIZE + 
                                     constants::AES_GCM_TAG_SIZE;
    
    if (ciphertext.size() < MIN_SIZE) {
        return std::unexpected(ErrorCode::InvalidCiphertext);
    }
    
    // Extract salt (first 16 bytes)
    ByteSpan salt = ciphertext.subspan(0, constants::PBKDF2_SALT_SIZE);
    
    // The rest is the encrypted data (nonce + ciphertext + tag)
    ByteSpan encrypted_portion = ciphertext.subspan(constants::PBKDF2_SALT_SIZE);
    
    // Derive the key from password
    auto key_result = KeyManager::derive_key_from_password(password, salt);
    if (!key_result) {
        return std::unexpected(key_result.error());
    }
    
    // Decrypt with the derived key
    return decrypt(encrypted_portion, key_result->span());
}

// ============================================================================
// File Decryption
// ============================================================================

VoidResult Decryptor::decrypt_file(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    ByteSpan key
) {
    // Check if input file exists
    if (!std::filesystem::exists(input_path)) {
        return std::unexpected(ErrorCode::FileNotFound);
    }
    
    // Check file size
    auto file_size = std::filesystem::file_size(input_path);
    if (file_size > constants::MAX_FILE_SIZE) {
        return std::unexpected(ErrorCode::FileTooLarge);
    }
    
    // Minimum size check
    constexpr std::size_t MIN_SIZE = constants::AES_GCM_NONCE_SIZE + constants::AES_GCM_TAG_SIZE;
    if (file_size < MIN_SIZE) {
        return std::unexpected(ErrorCode::InvalidCiphertext);
    }
    
    // Read the encrypted file
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    
    ByteBuffer ciphertext(file_size);
    input_file.read(reinterpret_cast<char*>(ciphertext.data()), 
                    static_cast<std::streamsize>(file_size));
    
    if (!input_file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    input_file.close();
    
    // Decrypt
    auto decrypted_result = decrypt(ciphertext, key);
    if (!decrypted_result) {
        return std::unexpected(decrypted_result.error());
    }
    
    // Write to output file
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    output_file.write(reinterpret_cast<const char*>(decrypted_result->data()),
                      static_cast<std::streamsize>(decrypted_result->size()));
    
    if (!output_file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    return {};  // Success
}

VoidResult Decryptor::decrypt_file_with_password(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path,
    std::string_view password
) {
    // Check if input file exists
    if (!std::filesystem::exists(input_path)) {
        return std::unexpected(ErrorCode::FileNotFound);
    }
    
    // Check file size
    auto file_size = std::filesystem::file_size(input_path);
    if (file_size > constants::MAX_FILE_SIZE) {
        return std::unexpected(ErrorCode::FileTooLarge);
    }
    
    // Minimum size check (salt + nonce + tag)
    constexpr std::size_t MIN_SIZE = constants::PBKDF2_SALT_SIZE + 
                                     constants::AES_GCM_NONCE_SIZE + 
                                     constants::AES_GCM_TAG_SIZE;
    if (file_size < MIN_SIZE) {
        return std::unexpected(ErrorCode::InvalidCiphertext);
    }
    
    // Read the encrypted file
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    
    ByteBuffer ciphertext(file_size);
    input_file.read(reinterpret_cast<char*>(ciphertext.data()), 
                    static_cast<std::streamsize>(file_size));
    
    if (!input_file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    input_file.close();
    
    // Decrypt with password
    auto decrypted_result = decrypt_with_password(ciphertext, password);
    if (!decrypted_result) {
        return std::unexpected(decrypted_result.error());
    }
    
    // Write to output file
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    output_file.write(reinterpret_cast<const char*>(decrypted_result->data()),
                      static_cast<std::streamsize>(decrypted_result->size()));
    
    if (!output_file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    return {};  // Success
}

} // namespace secura
