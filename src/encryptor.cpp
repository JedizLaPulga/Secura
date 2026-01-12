// ============================================================================
// Secura - Encryptor Implementation
// ============================================================================

#include "secura/encryptor.hpp"
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

Result<ByteBuffer> Encryptor::encrypt_impl(
    ByteSpan plaintext,
    ByteSpan key,
    ByteSpan nonce
) {
    // Create cipher context with RAII cleanup
    // EVP_CIPHER_CTX_new allocates a cipher context
    // EVP_CIPHER_CTX_free deallocates it
    struct ContextDeleter {
        void operator()(EVP_CIPHER_CTX* ctx) const {
            if (ctx) EVP_CIPHER_CTX_free(ctx);
        }
    };
    std::unique_ptr<EVP_CIPHER_CTX, ContextDeleter> ctx(EVP_CIPHER_CTX_new());
    
    if (!ctx) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Initialize encryption with AES-256-GCM
    // EVP_aes_256_gcm() returns the AES-256-GCM cipher algorithm
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Set the nonce/IV length (must be done before setting key/IV)
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 
                            static_cast<int>(constants::AES_GCM_NONCE_SIZE), nullptr) != 1) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Set the key and nonce
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        return std::unexpected(ErrorCode::CipherInitFailed);
    }
    
    // Allocate output buffer
    // Ciphertext is same size as plaintext for GCM mode
    ByteBuffer ciphertext(plaintext.size());
    int len = 0;
    int ciphertext_len = 0;
    
    // Encrypt the plaintext
    // EVP_EncryptUpdate can be called multiple times for streaming
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, 
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        return std::unexpected(ErrorCode::CipherUpdateFailed);
    }
    ciphertext_len = len;
    
    // Finalize encryption
    // For GCM, this doesn't add more ciphertext but generates the auth tag
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
        return std::unexpected(ErrorCode::CipherFinalizeFailed);
    }
    ciphertext_len += len;
    
    // Resize to actual size (should be same as plaintext for GCM)
    ciphertext.resize(static_cast<std::size_t>(ciphertext_len));
    
    // Get the authentication tag
    ByteBuffer tag(constants::AES_GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 
                            static_cast<int>(constants::AES_GCM_TAG_SIZE), tag.data()) != 1) {
        return std::unexpected(ErrorCode::CipherFinalizeFailed);
    }
    
    // Append tag to ciphertext
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    
    return ciphertext;
}

// ============================================================================
// Text Encryption
// ============================================================================

Result<ByteBuffer> Encryptor::encrypt_text(std::string_view plaintext, ByteSpan key) {
    // Convert string to bytes
    ByteSpan data{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    return encrypt(data, key);
}

Result<ByteBuffer> Encryptor::encrypt_text_with_password(
    std::string_view plaintext,
    std::string_view password
) {
    ByteSpan data{reinterpret_cast<const Byte*>(plaintext.data()), plaintext.size()};
    return encrypt_with_password(data, password);
}

// ============================================================================
// Binary Data Encryption
// ============================================================================

Result<ByteBuffer> Encryptor::encrypt(ByteSpan plaintext, ByteSpan key) {
    // Validate inputs
    if (plaintext.empty()) {
        return std::unexpected(ErrorCode::InvalidPlaintext);
    }
    
    if (!KeyManager::is_valid_key_size(key)) {
        return std::unexpected(ErrorCode::InvalidKeySize);
    }
    
    // Generate a random nonce
    auto nonce_result = KeyManager::generate_nonce();
    if (!nonce_result) {
        return std::unexpected(nonce_result.error());
    }
    const ByteBuffer& nonce = *nonce_result;
    
    // Encrypt the data
    auto ciphertext_result = encrypt_impl(plaintext, key, nonce);
    if (!ciphertext_result) {
        return std::unexpected(ciphertext_result.error());
    }
    
    // Build output: [nonce] + [ciphertext + tag]
    ByteBuffer output;
    output.reserve(nonce.size() + ciphertext_result->size());
    output.insert(output.end(), nonce.begin(), nonce.end());
    output.insert(output.end(), ciphertext_result->begin(), ciphertext_result->end());
    
    return output;
}

Result<ByteBuffer> Encryptor::encrypt_with_password(ByteSpan plaintext, std::string_view password) {
    // Validate plaintext
    if (plaintext.empty()) {
        return std::unexpected(ErrorCode::InvalidPlaintext);
    }
    
    // Generate a random salt
    auto salt_result = KeyManager::generate_salt();
    if (!salt_result) {
        return std::unexpected(salt_result.error());
    }
    const ByteBuffer& salt = *salt_result;
    
    // Derive key from password
    auto key_result = KeyManager::derive_key_from_password(password, salt);
    if (!key_result) {
        return std::unexpected(key_result.error());
    }
    
    // Encrypt with the derived key
    auto encrypted_result = encrypt(plaintext, key_result->span());
    if (!encrypted_result) {
        return std::unexpected(encrypted_result.error());
    }
    
    // Build output: [salt] + [nonce + ciphertext + tag]
    ByteBuffer output;
    output.reserve(salt.size() + encrypted_result->size());
    output.insert(output.end(), salt.begin(), salt.end());
    output.insert(output.end(), encrypted_result->begin(), encrypted_result->end());
    
    return output;
}

// ============================================================================
// File Encryption
// ============================================================================

VoidResult Encryptor::encrypt_file(
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
    
    // Read the entire file into memory
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    
    ByteBuffer plaintext(file_size);
    input_file.read(reinterpret_cast<char*>(plaintext.data()), 
                    static_cast<std::streamsize>(file_size));
    
    if (!input_file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    input_file.close();
    
    // Encrypt the data
    auto encrypted_result = encrypt(plaintext, key);
    if (!encrypted_result) {
        return std::unexpected(encrypted_result.error());
    }
    
    // Write to output file
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    output_file.write(reinterpret_cast<const char*>(encrypted_result->data()),
                      static_cast<std::streamsize>(encrypted_result->size()));
    
    if (!output_file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    return {};  // Success
}

VoidResult Encryptor::encrypt_file_with_password(
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
    
    // Read the entire file into memory
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    
    ByteBuffer plaintext(file_size);
    input_file.read(reinterpret_cast<char*>(plaintext.data()), 
                    static_cast<std::streamsize>(file_size));
    
    if (!input_file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    input_file.close();
    
    // Encrypt with password
    auto encrypted_result = encrypt_with_password(plaintext, password);
    if (!encrypted_result) {
        return std::unexpected(encrypted_result.error());
    }
    
    // Write to output file
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    output_file.write(reinterpret_cast<const char*>(encrypted_result->data()),
                      static_cast<std::streamsize>(encrypted_result->size()));
    
    if (!output_file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    return {};  // Success
}

} // namespace secura
