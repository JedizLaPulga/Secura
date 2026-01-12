// ============================================================================
// Secura - RSA Key Pair Implementation
// ============================================================================

#include "secura/rsa_key_pair.hpp"

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// Standard library
#include <fstream>
#include <memory>

namespace secura {

// ============================================================================
// RAII Helpers
// ============================================================================

namespace {

// Custom deleter for BIO
struct BioDeleter {
    void operator()(BIO* bio) const { if (bio) BIO_free(bio); }
};
using UniqueBio = std::unique_ptr<BIO, BioDeleter>;

// Custom deleter for EVP_PKEY
struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const { if (key) EVP_PKEY_free(key); }
};
using UniqueEvpPkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

// Custom deleter for EVP_PKEY_CTX
struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ctx) const { if (ctx) EVP_PKEY_CTX_free(ctx); }
};
using UniqueEvpPkeyCtx = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

} // anonymous namespace

// ============================================================================
// Constructor / Destructor
// ============================================================================

RsaKeyPair::RsaKeyPair(void* evp_pkey) : evp_pkey_(evp_pkey) {}

RsaKeyPair::~RsaKeyPair() {
    if (evp_pkey_) {
        EVP_PKEY_free(static_cast<EVP_PKEY*>(evp_pkey_));
        evp_pkey_ = nullptr;
    }
}

RsaKeyPair::RsaKeyPair(RsaKeyPair&& other) noexcept 
    : evp_pkey_(other.evp_pkey_) {
    other.evp_pkey_ = nullptr;
}

RsaKeyPair& RsaKeyPair::operator=(RsaKeyPair&& other) noexcept {
    if (this != &other) {
        if (evp_pkey_) {
            EVP_PKEY_free(static_cast<EVP_PKEY*>(evp_pkey_));
        }
        evp_pkey_ = other.evp_pkey_;
        other.evp_pkey_ = nullptr;
    }
    return *this;
}

// ============================================================================
// Key Generation
// ============================================================================

Result<RsaKeyPair> RsaKeyPair::generate(RsaKeySize key_size) {
    // Create a context for key generation
    UniqueEvpPkeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx) {
        return std::unexpected(ErrorCode::KeyGenerationFailed);
    }
    
    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        return std::unexpected(ErrorCode::KeyGenerationFailed);
    }
    
    // Set the key size
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), static_cast<int>(key_size)) <= 0) {
        return std::unexpected(ErrorCode::KeyGenerationFailed);
    }
    
    // Generate the key pair
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
        return std::unexpected(ErrorCode::KeyGenerationFailed);
    }
    
    return RsaKeyPair(pkey);
}

// ============================================================================
// PEM Export
// ============================================================================

Result<std::string> RsaKeyPair::export_public_key_pem() const {
    if (!has_public_key()) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    UniqueBio bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        return std::unexpected(ErrorCode::InternalError);
    }
    
    if (PEM_write_bio_PUBKEY(bio.get(), static_cast<EVP_PKEY*>(evp_pkey_)) != 1) {
        return std::unexpected(ErrorCode::InternalError);
    }
    
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    
    return std::string(data, static_cast<std::size_t>(len));
}

Result<std::string> RsaKeyPair::export_private_key_pem() const {
    if (!has_private_key()) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    UniqueBio bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        return std::unexpected(ErrorCode::InternalError);
    }
    
    // Write private key WITHOUT encryption (pass null for cipher and password)
    if (PEM_write_bio_PrivateKey(bio.get(), static_cast<EVP_PKEY*>(evp_pkey_), 
                                  nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        return std::unexpected(ErrorCode::InternalError);
    }
    
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    
    return std::string(data, static_cast<std::size_t>(len));
}

Result<std::string> RsaKeyPair::export_private_key_pem_encrypted(
    std::string_view password
) const {
    if (!has_private_key()) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    if (password.empty()) {
        return std::unexpected(ErrorCode::PasswordTooShort);
    }
    
    UniqueBio bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        return std::unexpected(ErrorCode::InternalError);
    }
    
    // Write private key WITH AES-256-CBC encryption
    if (PEM_write_bio_PrivateKey(bio.get(), static_cast<EVP_PKEY*>(evp_pkey_),
                                  EVP_aes_256_cbc(),
                                  reinterpret_cast<const unsigned char*>(password.data()),
                                  static_cast<int>(password.size()),
                                  nullptr, nullptr) != 1) {
        return std::unexpected(ErrorCode::InternalError);
    }
    
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    
    return std::string(data, static_cast<std::size_t>(len));
}

// ============================================================================
// PEM Import
// ============================================================================

Result<RsaKeyPair> RsaKeyPair::import_public_key_pem(std::string_view pem) {
    UniqueBio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) {
        return std::unexpected(ErrorCode::InternalError);
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!pkey) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    // Verify it's an RSA key
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    return RsaKeyPair(pkey);
}

Result<RsaKeyPair> RsaKeyPair::import_private_key_pem(std::string_view pem) {
    UniqueBio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) {
        return std::unexpected(ErrorCode::InternalError);
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!pkey) {
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    return RsaKeyPair(pkey);
}

Result<RsaKeyPair> RsaKeyPair::import_private_key_pem_encrypted(
    std::string_view pem,
    std::string_view password
) {
    UniqueBio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) {
        return std::unexpected(ErrorCode::InternalError);
    }
    
    // Cast password to non-const for OpenSSL (it won't modify it)
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(
        bio.get(), nullptr, nullptr, 
        const_cast<char*>(password.data())
    );
    
    if (!pkey) {
        return std::unexpected(ErrorCode::AuthenticationFailed);  // Wrong password
    }
    
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        return std::unexpected(ErrorCode::InvalidArgument);
    }
    
    return RsaKeyPair(pkey);
}

// ============================================================================
// File Operations
// ============================================================================

VoidResult RsaKeyPair::save_public_key(const std::filesystem::path& path) const {
    auto pem_result = export_public_key_pem();
    if (!pem_result) {
        return std::unexpected(pem_result.error());
    }
    
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    file.write(pem_result->data(), static_cast<std::streamsize>(pem_result->size()));
    if (!file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    return {};
}

VoidResult RsaKeyPair::save_private_key(const std::filesystem::path& path) const {
    auto pem_result = export_private_key_pem();
    if (!pem_result) {
        return std::unexpected(pem_result.error());
    }
    
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    file.write(pem_result->data(), static_cast<std::streamsize>(pem_result->size()));
    if (!file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    return {};
}

VoidResult RsaKeyPair::save_private_key_encrypted(
    const std::filesystem::path& path,
    std::string_view password
) const {
    auto pem_result = export_private_key_pem_encrypted(password);
    if (!pem_result) {
        return std::unexpected(pem_result.error());
    }
    
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    file.write(pem_result->data(), static_cast<std::streamsize>(pem_result->size()));
    if (!file) {
        return std::unexpected(ErrorCode::FileWriteError);
    }
    
    return {};
}

Result<RsaKeyPair> RsaKeyPair::load_public_key(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return std::unexpected(ErrorCode::FileNotFound);
    }
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    
    std::string pem((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    
    return import_public_key_pem(pem);
}

Result<RsaKeyPair> RsaKeyPair::load_private_key(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return std::unexpected(ErrorCode::FileNotFound);
    }
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    
    std::string pem((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    
    return import_private_key_pem(pem);
}

Result<RsaKeyPair> RsaKeyPair::load_private_key_encrypted(
    const std::filesystem::path& path,
    std::string_view password
) {
    if (!std::filesystem::exists(path)) {
        return std::unexpected(ErrorCode::FileNotFound);
    }
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::unexpected(ErrorCode::FileReadError);
    }
    
    std::string pem((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    
    return import_private_key_pem_encrypted(pem, password);
}

// ============================================================================
// Key Information
// ============================================================================

bool RsaKeyPair::is_valid() const noexcept {
    return evp_pkey_ != nullptr;
}

bool RsaKeyPair::has_public_key() const noexcept {
    return evp_pkey_ != nullptr;
}

bool RsaKeyPair::has_private_key() const noexcept {
    if (!evp_pkey_) return false;
    
    // Check if we can get the private key components
    // A public-only key will not have the private exponent
    BIGNUM* d = nullptr;
    EVP_PKEY_get_bn_param(static_cast<EVP_PKEY*>(evp_pkey_), "d", &d);
    bool has_private = (d != nullptr);
    if (d) BN_free(d);
    
    return has_private;
}

std::size_t RsaKeyPair::key_size_bits() const noexcept {
    if (!evp_pkey_) return 0;
    return static_cast<std::size_t>(EVP_PKEY_get_bits(static_cast<EVP_PKEY*>(evp_pkey_)));
}

std::size_t RsaKeyPair::max_encrypt_size() const noexcept {
    // For OAEP with SHA-256:
    // max_size = key_size_bytes - 2 * hash_size - 2
    // hash_size for SHA-256 = 32 bytes
    // So: max_size = key_size_bytes - 66
    std::size_t key_bytes = key_size_bits() / 8;
    if (key_bytes <= 66) return 0;
    return key_bytes - 66;
}

} // namespace secura
